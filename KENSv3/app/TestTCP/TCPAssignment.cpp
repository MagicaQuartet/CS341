/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <utility>
#include "TCPAssignment.hpp"

#define PACKETSIZE 54
#define WINDOWSIZE 1024

namespace E
{

enum {ST_CLOSED, ST_LISTEN, ST_SYN_SENT, ST_SYN_RCVD, ST_ESTABLISHED};

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

/* helper functions */

uint16_t makeChecksum(uint8_t *TCPHeader, uint8_t *src_ip, uint8_t *dest_ip) {
	uint32_t sum = 0;

	for (int i = 0; i < 10; i++) {
		sum = sum + (TCPHeader[2*i] << 8) + TCPHeader[2*i+1];
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
	}
	
	for (int i = 0; i < 2; i++) {
		sum = sum + (src_ip[2*i] << 8) + src_ip[2*i+1];
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
	}
	
	for (int i = 0; i < 2; i++) {
		sum = sum + (dest_ip[2*i] << 8) + dest_ip[2*i+1];
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
	}

	sum += 20;	// header size
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	sum += 6;		// protocol
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);		

	return (uint16_t)~sum;
}

/* SOCKET */

int TCPAssignment::syscall_socket(int pid) {
	int fd;
	struct socket_info* sock;

	fd = this->createFileDescriptor(pid);
	sock = (struct socket_info*)calloc(sizeof(struct socket_info), 1);

	sock->fd = fd;
	sock->pid = pid;
	sock->listenUUID = 0;

	sock->bind = false;
	sock->state = ST_CLOSED;

	sock->seqnum = 0;
	sock->backlog = 0;

	sock->src_ip = 0;
	sock->src_port = 0;
	sock->dest_ip = 0;
	sock->dest_port = 0;

	this->socket_list.push_back(sock);

	return fd;
}

/* CLOSE */

void TCPAssignment::syscall_close(int pid, int fd) {
	this->removeFileDescriptor(pid, fd);
	bool erased = false;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			free(*it);
			this->socket_list.erase(it);
			erased = true;
			break;
		}
	}

	if (!erased) {
		for (std::list<struct socket_info*>::iterator it=this->connect_socket_list.begin(); it!=this->connect_socket_list.end(); ++it) {
			if ((*it)->fd == fd && (*it)->pid == pid) {
				free(*it);
				this->connect_socket_list.erase(it);
				break;
			}
		}
	}
}

/* CONNECT */

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t len) {
	struct sockaddr_in* ptr;
	struct socket_info* sock;
	Host *host;
	Packet *packet;
	uint8_t TCPHeader[20], src_ip[4], dest_ip[4];
	
	ptr = (struct sockaddr_in*)addr;
	host = this->getHost();	
	sock = NULL;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}

	if (sock == NULL || sock->bind)
		this->returnSystemCall(syscallUUID, -1);
	else {
		if (!sock->bind) {
			*(uint32_t*)dest_ip = ptr->sin_addr.s_addr;
			sock->state = ST_SYN_SENT;
			host->getIPAddr(src_ip, host->getRoutingTable(dest_ip));
			sock->src_ip = *(uint32_t*)src_ip;
			sock->src_port = htons(65535);
		}
		sock->dest_ip = ptr->sin_addr.s_addr;
		sock->dest_port = ptr->sin_port;
		
		packet = this->allocatePacket(PACKETSIZE);
		memset(TCPHeader, 0, 20);
		*(uint32_t*)src_ip = sock->src_ip;
		*(uint32_t*)dest_ip = sock->dest_ip;
		*(uint16_t*)TCPHeader = sock->src_port;
		*(uint16_t*)(TCPHeader+2) = sock->dest_port;
		*(uint32_t*)(TCPHeader+4) = htonl(sock->seqnum);
		sock->seqnum += 1;
		*(TCPHeader+12) = 0x50;
		*(TCPHeader+13) = 0x02;
		*(uint16_t*)(TCPHeader+14) = htons(WINDOWSIZE);
		packet->writeData(14+12, src_ip, 4);
		packet->writeData(14+16, dest_ip, 4);
	
		*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, src_ip, dest_ip));
		packet->writeData(14+20, TCPHeader, 20);

//		for (int i = 0; i < 20; i++) {
//			printf("%x\t", TCPHeader[i]);
//			if (i % 4 == 3)
//				printf("\n");
//		}

		this->block_connect.push_back(std::make_pair(sock, syscallUUID));
		fflush(stdout);
		this->sendPacket("IPv4", packet);
		//this->freePacket(packet);
	}
}

/* LISTEN */

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog) {
	struct socket_info* sock;
	int ret;

	sock = NULL;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}

	if (sock == NULL)
		ret = -1;
	else {
		sock->state = ST_LISTEN;
		sock->listenUUID = syscallUUID;
		sock->backlog = backlog;
		this->connection_SYN[syscallUUID] = std::list<struct connection_info*>();
		this->connection_ACK[syscallUUID] = std::list<struct connection_info*>();
		ret = 0;
	}

	return ret;
}

/* ACCEPT */
void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *lenptr) {
	struct socket_info* sock, *new_socket;
	struct sockaddr_in* ptr;

	ptr = (struct sockaddr_in *)addr;
	sock = NULL;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}
	if (sock == NULL || sock->state != ST_LISTEN)
		this->returnSystemCall(syscallUUID, -1);
	else {
		fd = this->createFileDescriptor(pid);
		new_socket = (struct socket_info*)calloc(sizeof(socket_info), 1);
		new_socket->fd = fd;
		new_socket->pid = pid;
		new_socket->listenUUID = 0;

		new_socket->state = ST_SYN_RCVD;
		new_socket->bind = false;

		new_socket->seqnum = 0;
		new_socket->backlog = 0;
		new_socket->src_ip = sock->src_ip;
		new_socket->src_port = sock->src_port;
		new_socket->dest_ip = 0;
		new_socket->dest_port = 0;
		this->connect_socket_list.push_back(new_socket);

		if (this->connection_ACK[sock->fd].empty()) {
			printf("										>>> ACCEPT: no ACKed connection, BLOCKED\n");
			this->block_accept.push_back(std::make_pair(sock, std::make_pair(syscallUUID, new_socket)));
			this->block_accept_addr.push_back(std::make_pair(syscallUUID, ptr));
		}
		else {
			printf("										>>> ACCEPT: ACKed connection found, CONNECTION COMPLETE\n");
			new_socket->bind = true;
			new_socket->state = ST_ESTABLISHED;
			new_socket->dest_ip = this->connection_ACK[sock->fd].front()->client_ip;
			new_socket->dest_port = this->connection_ACK[sock->fd].front()->client_port;
			ptr->sin_family = AF_INET;
			ptr->sin_addr.s_addr = new_socket->dest_ip;
			ptr->sin_port = new_socket->dest_port;

			//free(this->connection_ACK[sock->fd].front());
			this->connection_ACK[sock->fd].pop_front();
			this->returnSystemCall(syscallUUID, new_socket->fd);
		}
	}
}

/* BIND */

int TCPAssignment::syscall_bind(int pid, int fd, struct sockaddr *addr, socklen_t len) {
	struct socket_info *sock;
	struct sockaddr_in *ptr;
	int ret;

	ptr = (struct sockaddr_in *)addr;
	sock = NULL;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}
		
	if (sock == NULL) {
			printf("								>>> error: no socket\n");
		ret = -1;
	}
	else {
		if (sock->bind) {
				printf("									>>> error: double binding\n");
			ret = -1;
		}
		else {
			ret = 0;
			for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
				if ((ptr->sin_addr.s_addr == 0 || (*it)->src_ip == 0 || ptr->sin_addr.s_addr == (*it)->src_ip) && ptr->sin_port == (*it)->src_port) {
					printf("											>>> error: bind rule violation\n");
					ret = -1;
					break;
				}
			}
		}
	}

	if (!ret) {
		sock->bind = true;
		sock->src_ip = ptr->sin_addr.s_addr;
		sock->src_port = ptr->sin_port;
	}

	return ret;
}

/* GETSOCKNAME */

int TCPAssignment::syscall_getsockname(int pid, int fd, struct sockaddr *addr, socklen_t *lenptr) {
	struct socket_info *sock;
	struct sockaddr_in *ptr;
	int ret;

	ptr = (struct sockaddr_in *)addr;
	sock = NULL;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}
	if (sock == NULL) {
		for (std::list<struct socket_info*>::iterator it=this->connect_socket_list.begin(); it!=this->connect_socket_list.end(); ++it) {
			if ((*it)->fd == fd && (*it)->pid == pid) {
				sock = *it;
				break;
			}
		}
	}

	if (sock == NULL)
		ret = -1;
	else {
		ptr->sin_family = AF_INET;
		ptr->sin_addr.s_addr = sock->src_ip;
		ptr->sin_port = sock->src_port;
		ret = 0;
	}

	return ret;
}

/* GETPEERNAME */
int TCPAssignment::syscall_getpeername(int pid, int fd, struct sockaddr *addr, socklen_t *lenptr) {
	struct socket_info* sock;
	struct sockaddr_in *ptr;

	sock = NULL;
	ptr = (struct sockaddr_in *)addr;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}

	if (sock == NULL || sock->state != ST_ESTABLISHED) {
		printf("												>>> GETPEERNAME: no such socket\n");
		return -1;
	}
	else {
		ptr->sin_family = AF_INET;
		ptr->sin_addr.s_addr = sock->dest_ip;
		ptr->sin_port = sock->dest_port;

		return 0;
	}
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int ret;

	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		this->returnSystemCall(syscallUUID, this->syscall_socket(pid));
		break;
	case CLOSE:
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		this->syscall_close(pid, param.param1_int);
		this->returnSystemCall(syscallUUID, 0);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		this->syscall_connect(syscallUUID, pid, param.param1_int, (struct sockaddr*)param.param2_ptr, param.param3_int);			
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		ret = this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		this->returnSystemCall(syscallUUID, ret);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		this->syscall_accept(syscallUUID, pid, param.param1_int, (struct sockaddr*)param.param2_ptr, (socklen_t *)param.param3_ptr);
		break;
	case BIND:
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		ret = this->syscall_bind(pid, param.param1_int, (struct sockaddr *)param.param2_ptr, param.param3_int);
		this->returnSystemCall(syscallUUID, ret);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		ret = this->syscall_getsockname(pid, param.param1_int, (struct sockaddr *)param.param2_ptr, (socklen_t *)param.param3_ptr);
		this->returnSystemCall(syscallUUID, ret);
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		ret = this->syscall_getpeername(pid, param.param1_int, (struct sockaddr *)param.param2_ptr, (socklen_t *)param.param3_ptr);
		this->returnSystemCall(syscallUUID, ret);
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint8_t src_ip[4], dest_ip[4], src_port[2], dest_port[2], bits, syn = 0x02, ack = 0x10, TCPHeader[20];
	uint32_t seqnum, acknum;
	Packet *new_packet;
	struct socket_info* sock;

	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	packet->readData(14+20+0, src_port, 2);
	packet->readData(14+20+2, dest_port, 2);
	packet->readData(14+20+4, (uint8_t*)&acknum, 4);
	packet->readData(14+20+13, &bits, 1);
//	packet->readData(14+20, TCPHeader, 20);

/*
	if ((bits & syn) && (bits & ack)) {
		for (int i = 0; i < 20; i++) {
			printf("%x\t", TCPHeader[i]);
				if (i % 4 == 3)
					printf("\n");
		}
		for (int i = 0; i < 4; i++) {
			printf("%x\t", src_ip[i]);
				if (i % 4 == 3)
					printf("\n");
		}
		for (int i = 0; i < 20; i++) {
			printf("%x\t", TCPHeader[i]);
				if (i % 4 == 3)
					printf("\n");
		}
	}
*/

	if (!(bits & ack)) {
		// SYN
		
		new_packet = this->clonePacket(packet);
		bits = syn | ack;
		
		sock = NULL;

		for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
			if (((*it)->src_ip == 0 || (*it)->src_ip == *(uint32_t*)dest_ip) && (*it)->src_port == *(uint16_t*)dest_port) {
				sock = *it;
				break;
			}
		}

		if (sock != NULL) {
			if (sock->state == ST_LISTEN) {
				struct connection_info* conninfo;
				conninfo = (struct connection_info*)calloc(sizeof(struct connection_info*), 1);
	
				conninfo->client_ip = *(uint32_t*)src_ip;
				conninfo->client_port = *(uint16_t*)src_port;
				conninfo->server_ip = *(uint32_t*)dest_ip;
				conninfo->server_port = *(uint16_t*)dest_port;

				if (this->connection_SYN[sock->listenUUID].size() < sock->backlog) {
					this->connection_SYN[sock->listenUUID].push_back(conninfo);
				}

				seqnum = htonl(sock->seqnum);
				sock->seqnum += 1;
				acknum = htonl(ntohl(acknum)+1);

				new_packet->writeData(14+12, dest_ip, 4);
				new_packet->writeData(14+16, src_ip, 4);
				new_packet->writeData(14+20+0, dest_port, 2);
				new_packet->writeData(14+20+2, src_port, 2);
				new_packet->writeData(14+20+4, (uint8_t*)&seqnum, 4);
				new_packet->writeData(14+20+8, (uint8_t*)&acknum, 4);
				new_packet->writeData(14+20+13, &bits, 1);
		
				new_packet->readData(14+20, TCPHeader, 20);
				*(uint16_t*)(TCPHeader+16) = 0;
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, dest_ip, src_ip));

				new_packet->writeData(14+20, TCPHeader, 20);
				this->sendPacket("IPv4", new_packet);
			}
			else {
				printf("																>>>>> maybe simultaneous?\n");
			}
		}	
		//this->freePacket(new_packet)
	}
	else {
		if (bits & syn) {
			// SYNACK
			UUID uuid = 0;
			new_packet = this->clonePacket(packet);
			bits = ack;

			sock = NULL;

			for (std::list<std::pair<struct socket_info*, UUID>>::iterator it=this->block_connect.begin(); it!=this->block_connect.end(); ++it) {
				if (((*it).first->src_ip == 0 || (*it).first->src_ip == *(uint32_t*)dest_ip) && (*it).first->src_port == *(uint16_t*)dest_port) {
					sock = (*it).first;
					uuid = (*it).second;
					block_connect.erase(it);
					break;
				}
			}

			if (sock != NULL) {
				sock->state = ST_ESTABLISHED;
				seqnum = htonl(sock->seqnum);
				acknum = htonl(ntohl(acknum)+1);
				sock->seqnum += 1;

				new_packet->writeData(14+12, dest_ip, 4);
				new_packet->writeData(14+16, src_ip, 4);
				new_packet->writeData(14+20+0, dest_port, 2);
				new_packet->writeData(14+20+2, src_port, 2);
				new_packet->writeData(14+20+4, (uint8_t*)&seqnum, 4);
				new_packet->writeData(14+20+8, (uint8_t*)&acknum, 4);
				new_packet->writeData(14+20+13, &bits, 1);

				new_packet->readData(14+20, TCPHeader, 20);
				*(uint16_t*)(TCPHeader+16) = 0;
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, dest_ip, src_ip));

				new_packet->writeData(14+20, TCPHeader, 20);
	
				this->sendPacket("IPv4", new_packet);
				this->returnSystemCall(uuid, 0);
			}
			//this->freePacket(new_packet);
		}
		else {
			// ACK
			UUID uuid = 0;
			struct socket_info* new_socket = NULL;
			struct socket_info* listen_socket = NULL;
			struct connection_info* conninfo = NULL;
			sock = NULL;

			for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
				if (((*it)->src_ip == 0 || (*it)->src_ip == *(uint32_t*)dest_ip) && (*it)->src_port == *(uint16_t*)dest_port && (*it)->state == ST_LISTEN) {
					listen_socket = *it;
					break;
				}
			}
			
			if (listen_socket != NULL) {
				for (std::list<struct connection_info*>::iterator it=this->connection_SYN[listen_socket->listenUUID].begin(); it!=this->connection_SYN[listen_socket->listenUUID].end(); ++it) {
					if ((*it)->client_port == *(uint16_t*)src_port && (*(uint32_t*)src_ip == 0 || (*it)->client_ip == *(uint32_t*)src_ip)) {
						conninfo = *it;
						this->connection_SYN[listen_socket->listenUUID].erase(it);
						break;
					}
				}
				
				if (conninfo != NULL) {
					for (std::list<std::pair<struct socket_info*, std::pair<UUID, struct socket_info*>>>::iterator it=this->block_accept.begin(); it!=this->block_accept.end(); ++it) {
						if (((*it).first->src_ip == 0 || (*it).first->src_ip == *(uint32_t*)dest_ip) && (*it).first->src_port == *(uint16_t*)dest_port) {
							sock = (*it).first;
							uuid = (*it).second.first;
							new_socket = (*it).second.second;
							this->block_accept.erase(it);
							break;
						}
					}
		
					if (sock != NULL) {
						// blocked accept exists (backlog check in connection_SYN needed?)
						new_socket->dest_ip = *(uint32_t*)src_ip;
						new_socket->dest_port = *(uint16_t*)src_port;
		
						for (std::list<std::pair<UUID, struct sockaddr_in*>>::iterator it=block_accept_addr.begin(); it!=block_accept_addr.end(); ++it) {
							if((*it).first == uuid) {
								(*it).second->sin_family = AF_INET;
								(*it).second->sin_addr.s_addr = new_socket->dest_ip;
								(*it).second->sin_port = new_socket->dest_port;
								break;
							}
						}
		
						this->returnSystemCall(uuid, new_socket->fd);
					}
					else {
						// no blocked accept
						this->connection_ACK[listen_socket->listenUUID].push_back(conninfo);	
					}
				}
			}
		}
	}
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
