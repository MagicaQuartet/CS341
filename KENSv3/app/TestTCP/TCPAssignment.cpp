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

#define MSS				 	512
#define BUFFERSIZE 	51200
#define WINDOWSIZE 	51200
#define TIMEAFTER 	100000000

#define FIN 0x01
#define SYN 0x02
#define ACK 0x10

namespace E
{

enum {ST_CLOSED, ST_LISTEN, ST_SYN_SENT, ST_SYN_RCVD, ST_ESTABLISHED,
			ST_CLOSE_WAIT, ST_LAST_ACK,
			ST_FIN_WAIT_1, ST_FIN_WAIT_2, ST_CLOSING, ST_TIME_WAIT};

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

// make a checksum with given TCP header, data, source ip and destination ip
uint16_t makeChecksum(uint8_t *TCPHeader, uint8_t* buf, int bufsize, uint8_t *src_ip, uint8_t *dest_ip) {
	uint32_t sum = 0;

	for (int i = 0; i < 10; i++) {
		sum = sum + (TCPHeader[2*i] << 8) + TCPHeader[2*i+1];
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
	}

	if (buf != NULL) {
		int cnt = bufsize%2 ? (bufsize+1)/2 : bufsize/2;
		for (int i = 0; i < cnt; i++) {
			sum = sum + (buf[2*i] << 8) + buf[2*i+1];
			while (sum >> 16)
				sum = (sum >> 16) + (sum & 0xffff);
		}
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

	sum += 20 + bufsize;	// header+data size
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	sum += 6;		// protocol
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	return (uint16_t)~sum;
}

// check packet corruption by checksum
uint16_t checkChecksum(uint8_t *TCPHeader, uint8_t* buf, int bufsize, uint8_t *src_ip, uint8_t *dest_ip) {
	uint32_t sum = 0;

	for (int i = 0; i < 10; i++) {
		sum = sum + (TCPHeader[2*i] << 8) + TCPHeader[2*i+1];
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
	}

	if (buf != NULL && bufsize > 0) {
		int cnt = bufsize%2 ? (bufsize+1)/2 : bufsize/2;
		for (int i = 0; i < cnt; i++) {
			sum = sum + (buf[2*i] << 8) + buf[2*i+1];
			while (sum >> 16)
				sum = (sum >> 16) + (sum & 0xffff);
		}
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

	sum += 20 + bufsize;	// header+data size
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	sum += 6;		// protocol
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	return (uint16_t)sum + 1;
}

// find the next sequence number of the packet that should arrives next
int nextAcknum (struct socket_info* socket) {
	int acknum = 1;
	bool start = false;

	for (std::list<struct history_info*>::iterator it=socket->read_history.begin(); it!=socket->read_history.end(); ++it) {
		if (!start) {
			start = true;
			acknum = (*it)->seqnum;
			acknum += (*it)->size;
		}
		else if (acknum == (*it)->seqnum)
			acknum += (*it)->size;
		else
			break;
	}
	
	return acknum;
}

/* SOCKET */

int TCPAssignment::syscall_socket(int pid) {
	int fd;
	struct socket_info* sock;

	fd = this->createFileDescriptor(pid);
	sock = new socket_info;

	sock->fd = fd;
	sock->pid = pid;
	sock->listenUUID = 0;
	sock->parent = sock;

	sock->bind = false;
	sock->state = ST_CLOSED;

	sock->backlog = 0;
	sock->last_acknum = 0;
	sock->last_acknum_cnt = 0;

	sock->src_ip = 0;
	sock->src_port = 0;
	sock->dest_ip = 0;
	sock->dest_port = 0;

	this->socket_list.push_back(sock);

	sock->write_buf_size = 0;
	sock->write_blocked = NULL;
	
	sock->read_buf_size = 0;
	sock->read_blocked = NULL;

	sock->handshake_timer = NULL;
	sock->FIN_packet = NULL;

	sock->slow_start = 1;
	sock->cwnd = MSS;
	sock->acked_bytes = 0;
	sock->ssthresh = BUFFERSIZE;

	return fd;
}

/* CLOSE */

void TCPAssignment::syscall_close(int pid, int fd) {
	this->removeFileDescriptor(pid, fd);
	std::list <struct socket_info*>::iterator normal_it, connect_it;
	struct socket_info* normal_socket, *connect_socket, *closed_socket, *sock;
	
	normal_socket = NULL;
	connect_socket = NULL;
	closed_socket = NULL;

	for (normal_it=this->socket_list.begin(); normal_it!=this->socket_list.end(); ++normal_it) {
		if ((*normal_it)->fd == fd && (*normal_it)->pid == pid) {
			normal_socket = *normal_it;
			break;
		}
	}

	for (connect_it=this->connect_socket_list.begin(); connect_it!=this->connect_socket_list.end(); ++connect_it) {
		if ((*connect_it)->fd == fd && (*connect_it)->pid == pid) {
			connect_socket = *connect_it;
			break;
		}
	}
	
	for (std::list<struct socket_info*>::iterator it=this->closed_socket_list.begin(); it!=this->closed_socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			closed_socket = *it;
			break;
		}
	}
	
	if (closed_socket == NULL) {
		// close() can be called under ESTABLISHED or CLOSE_WAIT state
		if ((connect_socket != NULL && (connect_socket->state == ST_ESTABLISHED || connect_socket->state == ST_CLOSE_WAIT)) || (normal_socket != NULL && (normal_socket->state == ST_ESTABLISHED || normal_socket->state == ST_CLOSE_WAIT))) {
			if (connect_socket != NULL) {
				this->closed_socket_list.push_back(connect_socket);
				sock = connect_socket;
			}
			else {
				this->closed_socket_list.push_back(normal_socket);
				sock = normal_socket;
			}
	
			Packet *packet;
			uint8_t TCPHeader[20], src_ip[4], dest_ip[4];

			if (sock->state == ST_CLOSE_WAIT || sock->state == ST_ESTABLISHED) {
				if (sock->state == ST_CLOSE_WAIT)
					sock->state = ST_LAST_ACK;	

				packet = this->allocatePacket(54);

				memset(TCPHeader, 0, 20);
				*(uint32_t*)src_ip = sock->src_ip;
				*(uint32_t*)dest_ip = sock->dest_ip;
				*(uint16_t*)TCPHeader = sock->src_port;																																		// source port
				*(uint16_t*)(TCPHeader+2) = sock->dest_port;																															// destination port
				*(uint32_t*)(TCPHeader+4) = htonl(sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)]);	// sequence number
				*(uint32_t*)(TCPHeader+8) = htonl(sock->parent->acknum[std::make_pair(sock->dest_ip, sock->dest_port)]);
				*(TCPHeader+12) = 0x50;																																										// header size in 4bytes
				*(TCPHeader+13) = FIN;																																										// flag (FIN)
				*(uint16_t*)(TCPHeader+14) = htons(WINDOWSIZE);																														// window size
				packet->writeData(14+12, src_ip, 4);
				packet->writeData(14+16, dest_ip, 4);
			
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, src_ip, dest_ip));
				packet->writeData(14+20, TCPHeader, 20);
				
				// if data transfer is not accomplished yet, postpone connection teardown
				if (sock->write_history.empty() || (!sock->read_history.empty() && nextAcknum(sock) > (*sock->read_history.rbegin())->seqnum)) {
					this->sendPacket("IPv4", packet);
					if (sock->state == ST_ESTABLISHED)
						sock->state = ST_FIN_WAIT_1;	
				}
				else {
					sock->FIN_packet = packet;
				}
				sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)] += 1;
			}
		}
		else {
			if (normal_socket != NULL) {
				this->closed_socket_list.push_back(normal_socket);
			}
		}
	}
}

/* READ */

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, int size) {
	struct socket_info *sock = NULL;
	
	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {										// search a socket to read
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
	
	if (sock != NULL && sock->state == ST_ESTABLISHED) {
		int total_read_bytes = 0;																												// total_read_bytes: the amount of data already read
		int remainder = size;																														// remainder: the amount of remaining data to read

		while (remainder > 0) {
			if (!sock->read_buf.empty() && nextAcknum(sock) >= sock->read_buf.front()->seqnum) {						// case 1: buffer has data and data in read_buf is in right order
				struct buf_elem* elem = sock->read_buf.front();
				int read_bytes = remainder > elem->size ? elem->size : remainder;

				memcpy(buf+total_read_bytes, elem->data, read_bytes);
				sock->read_buf_size -= read_bytes;
				total_read_bytes += read_bytes;

				remainder -= read_bytes;

				if (read_bytes < elem->size) {
					memcpy(elem->data, elem->data + read_bytes, elem->size-read_bytes);
					elem->size -= read_bytes;
					break;
				}
				else {
					sock->read_buf.pop_front();
					free(elem->data);
					delete elem;
				}	
			}
			else																																					// case 2: no more data in the buffer or data in read_buf is not in right order
				break;
		}

		if (total_read_bytes > 0) {																											// case 1: the socket read data
			this->returnSystemCall(syscallUUID, total_read_bytes);
			
			if (!sock->read_history.empty() && (*sock->read_history.rbegin())->seqnum < nextAcknum(sock) && sock->FIN_packet != NULL) {
						this->sendPacket("IPv4", sock->FIN_packet);
						if (sock->state == ST_ESTABLISHED)
							sock->state = ST_FIN_WAIT_1;
						sock->FIN_packet = NULL;
					}												// ... return
		}
		else {																																					// case 2: no data read yet
			struct buf_elem* elem = new buf_elem;																					// ... block
			elem->syscallUUID = syscallUUID;
			elem->size = size;
			elem->data = (char *)buf;
			sock->read_blocked = elem;
		}
	}
	else
		this->returnSystemCall(syscallUUID, -1);
}

/* WRITE */

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void *buf, int size) {
	struct socket_info* sock = NULL;

	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {										// search a socket to write
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

	if (sock != NULL && sock->state == ST_ESTABLISHED) {
		int written_bytes = 0;																						// written_bytes: the amount of data already written
		
		while (written_bytes < size) {
			int writable = sock->cwnd - sock->write_buf_size;
			struct buf_elem* elem = new buf_elem;
			elem->syscallUUID = syscallUUID;

			if (writable > 0) {																							// case 1: buffer is not full
				int write_bytes = writable >= size ? size : writable;
				write_bytes = 512 > write_bytes ? write_bytes : 512;

				Packet *packet;
				uint8_t TCPHeader[20], src_ip[4], dest_ip[4], length[2];
				struct timer_info *timer = new timer_info;
				struct packet_info *pinfo = new packet_info;
		
				elem->seqnum = sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)];
				elem->size = write_bytes;
				elem->data = (char *)calloc(sizeof(char), write_bytes+1);
				memcpy(elem->data, buf+written_bytes, write_bytes);

				packet = this->allocatePacket(54+write_bytes);
				memset(TCPHeader, 0, 20);
				*(uint16_t*)length = htons(write_bytes+40);
				*(uint32_t*)src_ip = sock->src_ip;																																				// set packet length according to data segment
				*(uint32_t*)dest_ip = sock->dest_ip;
				*(uint16_t*)TCPHeader = sock->src_port;																																		// source port
				*(uint16_t*)(TCPHeader+2) = sock->dest_port;																															// destination port
				*(uint32_t*)(TCPHeader+4) = htonl(sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)]);	// sequence number
				*(uint32_t*)(TCPHeader+8) = htonl(sock->parent->acknum[std::make_pair(sock->dest_ip, sock->dest_port)]);
				*(TCPHeader+12) = 0x50;																																										// header size in 4bytes
				*(TCPHeader+13) = ACK;
				*(uint16_t*)(TCPHeader+14) = htons(WINDOWSIZE);																														// window size
				packet->writeData(14+2, length, 2);
				packet->writeData(14+12, src_ip, 4);
				packet->writeData(14+16, dest_ip, 4);
	
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, (uint8_t*)elem->data, write_bytes, src_ip, dest_ip));
				packet->writeData(14+20, TCPHeader, 20);
				packet->writeData(14+20+20, elem->data, write_bytes);																											// add data segment

				pinfo->seqnum = sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)];
				pinfo->size = write_bytes;
				
				timer->timerUUID = this->addTimer(timer, TIMEAFTER);
				timer->socket = sock;
				timer->packet = this->clonePacket(packet);
				pinfo->timer = timer;
				
				this->sendPacket("IPv4", packet);
				sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)] += write_bytes;
				sock->write_buf.push_back(elem);
				sock->write_buf_size += write_bytes;
				sock->write_history.push_back(pinfo);
				
				written_bytes += write_bytes;
			}
			else {																												// case 2: buffer is full
				elem->size = size - written_bytes;													// ... block
				elem->data = (char *)calloc(sizeof(char), elem->size);
				memcpy(elem->data, buf+written_bytes, elem->size);
				sock->write_blocked = elem;

				break;
			}
		}
		if (written_bytes > 0)
			this->returnSystemCall(syscallUUID, written_bytes);
	}
	else
		this->returnSystemCall(syscallUUID, -1);
}

/* CONNECT */

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t len) {
	struct sockaddr_in* ptr;
	struct socket_info* sock;
	struct timer_info* timer;
	Host *host;
	Packet *packet;
	uint8_t TCPHeader[20], src_ip[4], dest_ip[4];
	
	ptr = (struct sockaddr_in*)addr;
	host = this->getHost();	
	sock = NULL;

	// search socket_list
	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}

	// if there is no such socket or it is not for CONNECT, error
	if (sock == NULL || sock->state == ST_LISTEN || sock->state == ST_SYN_SENT)
		this->returnSystemCall(syscallUUID, -1);
	else {
		// implicit binding
		if (!sock->bind) {
			*(uint32_t*)dest_ip = ptr->sin_addr.s_addr;
			host->getIPAddr(src_ip, host->getRoutingTable(dest_ip));
			sock->src_ip = *(uint32_t*)src_ip;
			sock->src_port = htons(65535);
		}
		sock->dest_ip = ptr->sin_addr.s_addr;
		sock->dest_port = ptr->sin_port;
		sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)] = 0;
		sock->parent->acknum[std::make_pair(sock->dest_ip, sock->dest_port)] = 0;
		
		// create SYN packet
		packet = this->allocatePacket(54);
		timer = new timer_info;

		memset(TCPHeader, 0, 20);
		*(uint32_t*)src_ip = sock->src_ip;
		*(uint32_t*)dest_ip = sock->dest_ip;
		*(uint16_t*)TCPHeader = sock->src_port;					// source port
		*(uint16_t*)(TCPHeader+2) = sock->dest_port;		// destination port
		*(uint32_t*)(TCPHeader+4) = htonl(sock->parent->seqnum[std::make_pair(sock->dest_ip, sock->dest_port)]);	// sequence number
		*(uint32_t*)(TCPHeader+8) = htonl(sock->parent->acknum[std::make_pair(sock->dest_ip, sock->dest_port)]);
		*(TCPHeader+12) = 0x50;													// header size in 4bytes
		*(TCPHeader+13) = SYN;													// flag (SYN)
		*(uint16_t*)(TCPHeader+14) = htons(WINDOWSIZE);	// window size
		packet->writeData(14+12, src_ip, 4);
		packet->writeData(14+16, dest_ip, 4);
	
		*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, src_ip, dest_ip));
		
		packet->writeData(14+20, TCPHeader, 20);

		timer->timerUUID = this->addTimer(timer, TIMEAFTER);
		timer->socket = sock;
		timer->packet = this->clonePacket(packet);
		sock->handshake_timer = timer;

		this->block_connect.push_back(std::make_pair(sock, syscallUUID));		
		this->sendPacket("IPv4", packet);
		sock->state = ST_SYN_SENT;
	}
}

/* LISTEN */

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog) {
	struct socket_info* sock;
	int ret;

	sock = NULL;

	// search socket_list
	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}

	// if there is no such socket, error
	if (sock == NULL)
		ret = -1;
	else {
		sock->state = ST_LISTEN;
		sock->listenUUID = syscallUUID;
		sock->backlog = backlog;
		this->connection_SYN[syscallUUID] = std::list<struct connection_info*>();	// SYN request queue for this socket
		this->connection_ACK[syscallUUID] = std::list<struct connection_info*>();	// ACK request queue for this socket
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

	// search socket_list
	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}

	// if there is no such socket or its state is not LISTENing, error
	if (sock == NULL || sock->state != ST_LISTEN)
		this->returnSystemCall(syscallUUID, -1);
	else {
		// create new socket to establish new connection
		fd = this->createFileDescriptor(pid);
		new_socket = new socket_info;
		new_socket->fd = fd;
		new_socket->pid = pid;
		new_socket->listenUUID = 0;
		new_socket->parent = sock;

		new_socket->state = ST_SYN_RCVD;
		new_socket->bind = false;

		new_socket->backlog = 0;
		new_socket->last_acknum = 0;
		new_socket->last_acknum_cnt = 0;

		new_socket->src_ip = sock->src_ip;
		new_socket->src_port = sock->src_port;
		new_socket->dest_ip = 0;
		new_socket->dest_port = 0;

		new_socket->write_buf_size = 0;
		new_socket->write_blocked = NULL;

		new_socket->read_buf_size = 0;
		new_socket->read_blocked = NULL;

		new_socket->handshake_timer = NULL;
		new_socket->FIN_packet = NULL;
		
		new_socket->slow_start = 1;
		new_socket->cwnd = MSS;
		new_socket->acked_bytes = 0;
		new_socket->ssthresh = BUFFERSIZE;

		this->connect_socket_list.push_back(new_socket);

		// if there is no ACK requests in queue, block
		if (this->connection_ACK[sock->listenUUID].empty()) {
			this->block_accept.push_back(std::make_pair(sock, std::make_pair(syscallUUID, new_socket)));
			this->block_accept_addr.push_back(std::make_pair(syscallUUID, ptr));
		}
		else {	// otherwise, get a ACK request and fill new_socket and addr. no block.
			new_socket->state = ST_ESTABLISHED;
			new_socket->dest_ip = this->connection_ACK[sock->listenUUID].front()->client_ip;
			new_socket->dest_port = this->connection_ACK[sock->listenUUID].front()->client_port;
			new_socket->src_ip = this->connection_ACK[sock->listenUUID].front()->server_ip;
			new_socket->src_port = this->connection_ACK[sock->listenUUID].front()->server_port;
			ptr->sin_family = AF_INET;
			ptr->sin_addr.s_addr = new_socket->dest_ip;
			ptr->sin_port = new_socket->dest_port;

			this->connection_ACK[sock->listenUUID].pop_front();
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

	// search socket_list
	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}
		
	// if there is no such socket, error
	if (sock == NULL) {
		ret = -1;
	}
	else {
		// if it is already bound, error
		if (sock->bind) {
			ret = -1;
		}
		else {
			ret = 0;
			// if this syscall violates bind rule, error
			for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
				if ((ptr->sin_addr.s_addr == 0 || (*it)->src_ip == 0 || ptr->sin_addr.s_addr == (*it)->src_ip) && ptr->sin_port == (*it)->src_port) {
					ret = -1;
					break;
				}
			}
		}
	}

	// valid socket
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

	// search socket_list
	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}
	// if there is no such socket, search connect_socket_list
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

	// search socket_list
	for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
		if ((*it)->fd == fd && (*it)->pid == pid) {
			sock = *it;
			break;
		}
	}

	// if there is no such socket, search connect_socket_list
	if (sock == NULL) {
		for (std::list<struct socket_info*>::iterator it=this->connect_socket_list.begin(); it!=this->connect_socket_list.end(); ++it) {
			if ((*it)->fd == fd && (*it)->pid == pid) {
				sock = *it;
				break;
			}
		}
	}

	if (sock == NULL || sock->state != ST_ESTABLISHED) {
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
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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
	uint8_t length[2], src_ip[4], dest_ip[4], src_port[2], dest_port[2], TCPHeader[20], data[512];
	uint8_t bits;
	int seqnum, acknum, new_seqnum, new_acknum;
	Packet *new_packet;
	struct socket_info* sock;

	memset(data, 0, 512);
	packet->readData(14+2, length, 2);								// packet length
	packet->readData(14+12, src_ip, 4);								// source ip
	packet->readData(14+16, dest_ip, 4);							// destination ip
	packet->readData(14+20+0, src_port, 2);						// source port
	packet->readData(14+20+2, dest_port, 2);					// destination port
	packet->readData(14+20+4, (uint8_t*)&seqnum, 4);	// sequence number
	packet->readData(14+20+8, (uint8_t*)&acknum, 4);	// acknowledge number
	packet->readData(14+20+13, &bits, 1);							// flag

	packet->readData(14+20, TCPHeader, 20);														// TCP header
	packet->readData(14+20+20, data, ntohs(*(uint16_t*)length)-40);		// data

	if (checkChecksum(TCPHeader, data, ntohs(*(uint16_t*)length)-40, src_ip, dest_ip) != 0)		// if the packet is corrupted, ignore it
		return;

	if (bits & SYN && ~bits & ACK && ~bits & FIN) {
		// SYN
		
		new_packet = this->clonePacket(packet);
		bits = SYN | ACK;
		
		sock = NULL;

		// search socket_list
		for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
			if (((*it)->src_ip == 0 || (*it)->src_ip == *(uint32_t*)dest_ip) && (*it)->src_port == *(uint16_t*)dest_port) {
				sock = *it;
				break;
			}
		}

		if (sock != NULL) {
			struct timer_info* timer;
			struct connection_info* conninfo;

			if (sock->state == ST_LISTEN) {
				if (this->connection_SYN[sock->listenUUID].size() < sock->backlog) {
					struct socket_info *connect_socket = NULL;
					struct connection_info* acked_conninfo = NULL;

					// check if there is an established connection between src and dest
					for (std::list<struct socket_info*>::iterator it=this->connect_socket_list.begin(); it!=this->connect_socket_list.end(); ++it) {
						if ((*it)->state == ST_ESTABLISHED && (*it)->dest_ip == *(uint32_t*)src_ip && (*it)->dest_port == *(uint16_t*)src_port) {
							connect_socket = *it;
							break;
						}
					}

					// check if there is an ACK request between src and dest
					for (std::list<struct connection_info*>::iterator it=this->connection_ACK[sock->listenUUID].begin(); it!=this->connection_ACK[sock->listenUUID].end(); ++it) {
						if ((*it)->client_ip == *(uint32_t*)src_ip && (*it)->client_port == *(uint16_t*)src_port) {
							acked_conninfo = *it;
							break;
						}
					}

					if (connect_socket == NULL && acked_conninfo == NULL) {
						// new connection_info that represents this SYN request
						conninfo = new connection_info;
	
						conninfo->client_ip = *(uint32_t*)src_ip;
						conninfo->client_port = *(uint16_t*)src_port;
						conninfo->server_ip = *(uint32_t*)dest_ip;
						conninfo->server_port = *(uint16_t*)dest_port;
					
						this->connection_SYN[sock->listenUUID].push_back(conninfo);

						timer = new timer_info;

						// send SYNACK packet to client
						sock->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = 0;							// initialize sequence number for new connection
						new_seqnum = htonl(sock->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);

						sock->parent->acknum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = (int)ntohl(seqnum)+1;
						new_acknum = htonl((int)ntohl(seqnum)+1);

						new_packet->writeData(14+12, dest_ip, 4);
						new_packet->writeData(14+16, src_ip, 4);
						new_packet->writeData(14+20+0, dest_port, 2);
						new_packet->writeData(14+20+2, src_port, 2);
						new_packet->writeData(14+20+4, (uint8_t*)&new_seqnum, 4);
						new_packet->writeData(14+20+8, (uint8_t*)&new_acknum, 4);
						new_packet->writeData(14+20+13, &bits, 1);
			
						new_packet->readData(14+20, TCPHeader, 20);
						*(uint16_t*)(TCPHeader+16) = 0;
						*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, dest_ip, src_ip));
	
						new_packet->writeData(14+20, TCPHeader, 20);

						timer->timerUUID = this->addTimer(timer, TIMEAFTER);
						timer->socket = sock;
						timer->packet = this->clonePacket(new_packet);
						sock->handshake_timer = timer;

						this->sendPacket("IPv4", new_packet);
					}
				}
			}
			else if (sock->state == ST_SYN_SENT) {	// simultaneous open
				if (sock->handshake_timer != NULL) {
					this->cancelTimer(sock->handshake_timer->timerUUID);
					sock->handshake_timer = NULL;
				}

				conninfo = new connection_info;

				conninfo->client_ip = *(uint32_t*)src_ip;
				conninfo->client_port = *(uint16_t*)src_port;
				conninfo->server_ip = *(uint32_t*)dest_ip;
				conninfo->server_port = *(uint16_t*)dest_port;

				timer = new timer_info;
				
				// send SYNACK packet to client
				sock->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = 0;								// initialize sequence number for new connection
				new_seqnum = htonl(sock->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);
				sock->parent->acknum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = (int)ntohl(seqnum)+1;
				new_acknum = htonl((int)ntohl(seqnum)+1);

				new_packet->writeData(14+12, dest_ip, 4);
				new_packet->writeData(14+16, src_ip, 4);
				new_packet->writeData(14+20+0, dest_port, 2);
				new_packet->writeData(14+20+2, src_port, 2);
				new_packet->writeData(14+20+4, (uint8_t*)&new_seqnum, 4);
				new_packet->writeData(14+20+8, (uint8_t*)&new_acknum, 4);
				new_packet->writeData(14+20+13, &bits, 1);
			
				new_packet->readData(14+20, TCPHeader, 20);
				*(uint16_t*)(TCPHeader+16) = 0;
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, dest_ip, src_ip));
	
				new_packet->writeData(14+20, TCPHeader, 20);
				
				timer->timerUUID = this->addTimer(timer, TIMEAFTER);
				timer->socket = sock;
				timer->packet = this->clonePacket(new_packet);
				sock->handshake_timer = timer;

				this->sendPacket("IPv4", new_packet);
				sock->state = ST_SYN_RCVD;
			}
		}
	}
	else if (bits & SYN && bits & ACK && ~bits & FIN) {
		// SYNACK
		UUID uuid = 0;
		new_packet = this->clonePacket(packet);
		bits = ACK;

		sock = NULL;

		// search for blocked CONNECT of receiving socket
		for (std::list<std::pair<struct socket_info*, UUID>>::iterator it=this->block_connect.begin(); it!=this->block_connect.end(); ++it) {
			if (((*it).first->src_ip == 0 || (*it).first->src_ip == *(uint32_t*)dest_ip) && (*it).first->src_port == *(uint16_t*)dest_port) {
				sock = (*it).first;
				uuid = (*it).second;
				block_connect.erase(it);
				break;
			}
		}	

		if (sock != NULL) {									// the first SYNACK
			sock->state = ST_ESTABLISHED;
			if (sock->handshake_timer != NULL) {
				this->cancelTimer(sock->handshake_timer->timerUUID);
				sock->handshake_timer = NULL;
			}

			// send ACK packet
			sock->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] += 1;
			new_seqnum = htonl(sock->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);
			sock->parent->acknum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = (int)ntohl(seqnum)+1;
			new_acknum = htonl((int)ntohl(seqnum)+1);
			
			new_packet->writeData(14+12, dest_ip, 4);
			new_packet->writeData(14+16, src_ip, 4);
			new_packet->writeData(14+20+0, dest_port, 2);
			new_packet->writeData(14+20+2, src_port, 2);
			new_packet->writeData(14+20+4, (uint8_t*)&new_seqnum, 4);
			new_packet->writeData(14+20+8, (uint8_t*)&new_acknum, 4);
			new_packet->writeData(14+20+13, &bits, 1);

			new_packet->readData(14+20, TCPHeader, 20);
			*(uint16_t*)(TCPHeader+16) = 0;
			*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, dest_ip, src_ip));

			new_packet->writeData(14+20, TCPHeader, 20);
			
			this->sendPacket("IPv4", new_packet);
			this->returnSystemCall(uuid, 0);
		}
		else {															// retransmitted SYNACK
			for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
				if (((*it)->src_ip == 0 || (*it)->src_ip == *(uint32_t*)dest_ip) && (*it)->src_port == *(uint16_t*)dest_port) {
					sock = *it;
					break;
				}
			}

			if (sock != NULL) {
				if (sock->handshake_timer != NULL) {
					this->cancelTimer(sock->handshake_timer->timerUUID);
					sock->handshake_timer = NULL;
				}

				// send ACK packet
				new_seqnum = htonl(sock->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);
				new_acknum = htonl(sock->parent->acknum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);
			
				new_packet->writeData(14+12, dest_ip, 4);
				new_packet->writeData(14+16, src_ip, 4);
				new_packet->writeData(14+20+0, dest_port, 2);
				new_packet->writeData(14+20+2, src_port, 2);
				new_packet->writeData(14+20+4, (uint8_t*)&new_seqnum, 4);
				new_packet->writeData(14+20+8, (uint8_t*)&new_acknum, 4);
				new_packet->writeData(14+20+13, &bits, 1);

				new_packet->readData(14+20, TCPHeader, 20);
				*(uint16_t*)(TCPHeader+16) = 0;
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, dest_ip, src_ip));

				new_packet->writeData(14+20, TCPHeader, 20);
			
				this->sendPacket("IPv4", new_packet);
			}
		}
	}
	else if (~bits & SYN && bits & ACK && ~bits & FIN){
		// ACK
		UUID uuid = 0;
		struct socket_info* new_socket = NULL;
		struct socket_info* normal_socket = NULL;
		struct socket_info* connect_socket = NULL;
		struct connection_info* conninfo = NULL;
		sock = NULL;

		for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
			if (((*it)->src_ip == 0 || (*it)->src_ip == *(uint32_t*)dest_ip) && (*it)->src_port == *(uint16_t*)dest_port) {
				normal_socket = *it;
				break;
			}
		}
		
		for (std::list<struct socket_info*>::iterator it=this->connect_socket_list.begin(); it!=this->connect_socket_list.end(); ++it) {
			if ((*it)->parent->fd == normal_socket->fd && (*it)->dest_ip == *(uint32_t*)src_ip && (*it)->dest_port == *(uint16_t*)src_port) {
				connect_socket = *it;
				break;
			}
		}
			
		if (normal_socket->state == ST_LISTEN && connect_socket != NULL) {			// established connection exists
			
			if (connect_socket->state == ST_ESTABLISHED) {												// data transmission step
				if (ntohs(*(uint16_t*)length) == 40) {															// ACK - response of data transfer
					if (connect_socket->write_history.empty())
						return;
					std::list<struct buf_elem*>::iterator it;

					if (connect_socket->last_acknum != (int)ntohl(acknum)) {					// check duplicate
						connect_socket->last_acknum = (int)ntohl(acknum);
						connect_socket->last_acknum_cnt = 1;
					}
					else
						connect_socket->last_acknum_cnt++;

					if (connect_socket->last_acknum_cnt < 3) {												// no fast retransmit
						for (it=connect_socket->write_buf.begin(); it!=connect_socket->write_buf.end(); ++it) {			// remove data that the peer received from buffer
							if ((*it)->seqnum + (*it)->size <= (int)ntohl(acknum)) {																		// ... and adjust current data size in buffer
								connect_socket->write_buf_size -= (*it)->size;
								connect_socket->acked_bytes += (*it)->size;
							}
							else
								break;
						}

						if (connect_socket->acked_bytes >= connect_socket->cwnd) {
							connect_socket->acked_bytes = 0;
							if (connect_socket->slow_start) {
								connect_socket->cwnd *= 2;
								if (connect_socket->cwnd > connect_socket->ssthresh)
									connect_socket->slow_start = 0;
							}
							else {
								connect_socket->cwnd += MSS;
							}
						}

						connect_socket->write_buf.erase(connect_socket->write_buf.begin(), it);

						while (!connect_socket->write_history.empty()) {																						// remove information of ACKed packet
							struct packet_info* pinfo = connect_socket->write_history.front();
							if (pinfo->seqnum < (int)ntohl(acknum)) {
								this->cancelTimer(pinfo->timer->timerUUID);
								connect_socket->write_history.pop_front();
							}
							else
								break;
						}

						if (connect_socket->write_blocked != NULL) {																								// case: blocked write exists
							int written_bytes = 0;

							while (written_bytes < connect_socket->write_blocked->size) {
								struct buf_elem* elem = new buf_elem;
								struct timer_info* timer = new timer_info;
								struct packet_info* pinfo = new packet_info;
								int writable = connect_socket->cwnd - connect_socket->write_buf_size;
								int write_bytes = writable >= connect_socket->write_blocked->size ? connect_socket->write_blocked->size : writable;

								if (writable <= 0)
									break;

								elem->seqnum = connect_socket->parent->seqnum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)];
								elem->size = write_bytes;
								elem->data = (char *)calloc(sizeof(char), write_bytes+1);
								memcpy(elem->data, connect_socket->write_blocked->data, write_bytes);

								new_packet = this->allocatePacket(54+write_bytes);
								memset(TCPHeader, 0, 20);
								*(uint32_t*)src_ip = connect_socket->src_ip;
								*(uint32_t*)dest_ip = connect_socket->dest_ip;
								*(uint32_t*)length = htons(write_bytes);
								*(uint16_t*)TCPHeader = connect_socket->src_port;					// source port
								*(uint16_t*)(TCPHeader+2) = connect_socket->dest_port;		// destination port
								*(uint32_t*)(TCPHeader+4) = htonl(connect_socket->parent->seqnum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)]);	// sequence number
								*(uint32_t*)(TCPHeader+8) = htonl(connect_socket->parent->acknum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)]);
								*(TCPHeader+12) = 0x50;													// header size in 4bytes
								*(TCPHeader+13) = ACK;
								*(uint16_t*)(TCPHeader+14) = htons(WINDOWSIZE);	// window size
								new_packet->writeData(14+2, length, 2);
								new_packet->writeData(14+12, src_ip, 4);
								new_packet->writeData(14+16, dest_ip, 4);
	
								*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, (uint8_t*)elem->data, write_bytes, src_ip, dest_ip));
								new_packet->writeData(14+20, TCPHeader, 20);
								new_packet->writeData(14+20+20, elem->data, write_bytes);
								pinfo->seqnum = connect_socket->parent->seqnum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)];
								pinfo->size = write_bytes;
		
								timer->timerUUID = this->addTimer(timer, TIMEAFTER);
								timer->socket = connect_socket;
								timer->packet = this->clonePacket(new_packet);
								pinfo->timer = timer;
						
								this->sendPacket("IPv4", new_packet);
								this->returnSystemCall(connect_socket->write_blocked->syscallUUID, write_bytes);
								connect_socket->parent->seqnum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)] += write_bytes;
								connect_socket->write_buf.push_back(elem);
								connect_socket->write_buf_size += write_bytes;
								connect_socket->write_history.push_back(pinfo);
								
								written_bytes += write_bytes;
							}
							
							this->returnSystemCall(connect_socket->write_blocked->syscallUUID, written_bytes);
							delete connect_socket->write_blocked;
							connect_socket->write_blocked = NULL;
						}
					}
					else {			// fast retransmit
						struct timer_info *timer = connect_socket->write_history.front()->timer;
						Packet *packet = timer->packet;
						
						connect_socket->cwnd = connect_socket->cwnd / 2;
						connect_socket->acked_bytes = 0;
						connect_socket->ssthresh = connect_socket->cwnd;

						this->cancelTimer(timer->timerUUID);
						timer->timerUUID = this->addTimer(timer, TIMEAFTER);
						timer->packet = this->clonePacket(packet);
						this->sendPacket("IPv4", packet);
					}

					if (connect_socket->write_history.empty() && connect_socket->FIN_packet != NULL) {
						this->sendPacket("IPv4", connect_socket->FIN_packet);
						if (connect_socket->state == ST_ESTABLISHED)
							connect_socket->state = ST_FIN_WAIT_1;
						connect_socket->FIN_packet = NULL;
					}
				}
				else {																																						// ACK - data packet
					int datasize = ntohs(*(uint16_t*)length) - 40;
					int cur_acknum;
					bool duplicate = false;
					std::list<struct history_info*>::iterator it;
					
					cur_acknum = connect_socket->parent->acknum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)];

					for (it=connect_socket->read_history.begin(); it!=connect_socket->read_history.end(); ++it) { 		// check duplicate
						if ((*it)->seqnum == (int)ntohl(seqnum)) {
							duplicate = true;
							break;
						}
						else if ((*it)->seqnum > (int)ntohl(seqnum))
							break;
					}
 
					if (!duplicate) {																																									// read or save data only if it is not duplicate
						struct history_info* hinfo = new history_info;
						hinfo->seqnum = (int)ntohl(seqnum);
						hinfo->size = datasize;
						connect_socket->read_history.insert(it, hinfo);

						if (connect_socket->read_blocked != NULL && (connect_socket->read_history.size() == 1 || cur_acknum == (int)ntohl(seqnum))) {			// case 1: blocked read exists and arriving packet is in right order

							int read_bytes = datasize > connect_socket->read_blocked->size ? connect_socket->read_blocked->size : datasize;
							packet->readData(14+20+20, connect_socket->read_blocked->data, read_bytes);
	
							if (read_bytes < datasize) {
								struct buf_elem *elem = new buf_elem;
								elem->seqnum = (int)ntohl(seqnum);
								elem->size = datasize-read_bytes;
								elem->data = (char *)calloc(elem->size, sizeof(char));
								packet->readData(14+20+20+read_bytes, elem->data, elem->size);
								connect_socket->read_buf.push_front(elem);
								connect_socket->read_buf_size += elem->size;
							}

							this->returnSystemCall(connect_socket->read_blocked->syscallUUID, read_bytes);
							connect_socket->read_blocked = NULL;
						}
						else {																																					// case 2: no blocked read or arriving packet is out of order
							std::list<struct buf_elem*>::iterator buf_it;
							bool buf_duplicate = false;

							for (buf_it=connect_socket->read_buf.begin(); buf_it!=connect_socket->read_buf.end(); ++buf_it) {
								if ((*buf_it)->seqnum == (int)ntohl(seqnum)) {
									buf_duplicate = true;
									break;
								}
								else if ((*buf_it)->seqnum > (int)ntohl(seqnum))
									break;
							}

							if (!buf_duplicate) {											// save the data only if it is not in read_buf
								struct buf_elem *elem = new buf_elem;
								elem->seqnum = (int)ntohl(seqnum);
								elem->size = datasize;
								elem->data = (char *)calloc(elem->size, sizeof(char));
								packet->readData(14+20+20, elem->data, elem->size);
	
								connect_socket->read_buf.insert(buf_it, elem);
								connect_socket->read_buf_size += elem->size;
							}
						}	
					}

					// if the next packet arrives in right order, its sequence number should be nextAcknum() except duplicates
					connect_socket->parent->acknum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)] = nextAcknum(connect_socket);
					
					new_packet = this->allocatePacket(54);
					memset(TCPHeader, 0, 20);
					*(uint16_t*)length = htons(40);
					*(uint32_t*)src_ip = connect_socket->src_ip;
					*(uint32_t*)dest_ip = connect_socket->dest_ip;
					*(uint16_t*)TCPHeader = connect_socket->src_port;																																												// source port
					*(uint16_t*)(TCPHeader+2) = connect_socket->dest_port;																																									// destination port
					*(uint32_t*)(TCPHeader+4) = htonl(connect_socket->parent->seqnum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)]);	// sequence number
					*(uint32_t*)(TCPHeader+8) = htonl(connect_socket->parent->acknum[std::make_pair(connect_socket->dest_ip, connect_socket->dest_port)]);
					*(TCPHeader+12) = 0x50;																																																									// header size in 4bytes
					*(TCPHeader+13) = ACK;
					*(uint16_t*)(TCPHeader+14) = htons(BUFFERSIZE - connect_socket->read_buf_size);																													// window size
					new_packet->writeData(14+2, length, 2);
					new_packet->writeData(14+12, src_ip, 4);
					new_packet->writeData(14+16, dest_ip, 4);
	
					*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, src_ip, dest_ip));
					new_packet->writeData(14+20, TCPHeader, 20);
		
					this->sendPacket("IPv4", new_packet);																																																		// send ACK response
					
					if ((*connect_socket->read_history.rbegin())->seqnum < nextAcknum(connect_socket) && connect_socket->FIN_packet != NULL) {							// check postponed FIN
						this->sendPacket("IPv4", connect_socket->FIN_packet);
						if (connect_socket->state == ST_ESTABLISHED)
							connect_socket->state = ST_FIN_WAIT_1;
						connect_socket->FIN_packet = NULL;
					}
				}
			}
		}
		else if (normal_socket->state == ST_LISTEN && connect_socket == NULL) {			// ACK of SYNACK
			// find previous SYN request and remove it
			normal_socket->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] += 1;				// if not ACK of FIN, increase sequence number
			for (std::list<struct connection_info*>::iterator it=this->connection_SYN[normal_socket->listenUUID].begin(); it!=this->connection_SYN[normal_socket->listenUUID].end(); ++it) {
				if ((*it)->client_port == *(uint16_t*)src_port && ((*it)->client_ip == *(uint32_t*)src_ip)) {
					conninfo = *it;
					this->connection_SYN[normal_socket->listenUUID].erase(it);
					break;
				}
			}

			if (normal_socket->handshake_timer != NULL) {
				this->cancelTimer(normal_socket->handshake_timer->timerUUID);
				normal_socket->handshake_timer = NULL;
			}

			if (conninfo != NULL) {
				// search block_accept
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
					// blocked accept exists
					new_socket->state = ST_ESTABLISHED;
					new_socket->dest_ip = *(uint32_t*)src_ip;
					new_socket->dest_port = *(uint16_t*)src_port;
					new_socket->src_ip = *(uint32_t*)dest_ip;
					new_socket->src_port = *(uint16_t*)dest_port;

					for (std::list<std::pair<UUID, struct sockaddr_in*>>::iterator it=block_accept_addr.begin(); it!=block_accept_addr.end(); ++it) {
						if((*it).first == uuid) {
							(*it).second->sin_family = AF_INET;
							(*it).second->sin_addr.s_addr = new_socket->dest_ip;
							(*it).second->sin_port = new_socket->dest_port;
							break;
						}
					}
							
					// unblock
					this->returnSystemCall(uuid, new_socket->fd);
				}
				else {
					// no blocked accept
					this->connection_ACK[normal_socket->listenUUID].push_back(conninfo);	
				}
			}
		}
		else if (normal_socket->state == ST_ESTABLISHED) {
			if (ntohs(*(uint16_t*)length) == 40) {																										// ACK - response of data transfer
				if (normal_socket->write_history.empty())
					return;
				std::list<struct buf_elem*>::iterator it;	
				
				if (normal_socket->last_acknum != (int)ntohl(acknum)) {
					normal_socket->last_acknum = (int)ntohl(acknum);
					normal_socket->last_acknum_cnt = 1;
				}
				else {
					normal_socket->last_acknum_cnt++;
				}
				
				if (normal_socket->last_acknum_cnt < 3) {
					for (it=normal_socket->write_buf.begin(); it!=normal_socket->write_buf.end(); ++it) {		// remove data that the peer received from buffer
						if ((*it)->seqnum + (*it)->size <= (int)ntohl(acknum)) {																		// ... and adjust current data size in buffer
//							this->cancelTimer((*it)->timer->timerUUID);
							normal_socket->write_buf_size -= (*it)->size;
							normal_socket->acked_bytes += (*it)->size;
						}
						else
							break;
					}

					if (normal_socket->acked_bytes >= normal_socket->cwnd) {
						normal_socket->acked_bytes = 0;
						if (normal_socket->slow_start) {
							normal_socket->cwnd *= 2;
							if (normal_socket->cwnd > normal_socket->ssthresh)
								normal_socket->slow_start = 0;
						}
						else {
							normal_socket->cwnd += MSS;
						}
					}

					normal_socket->write_buf.erase(normal_socket->write_buf.begin(), it);

					while (!normal_socket->write_history.empty()) {
						struct packet_info* pinfo = normal_socket->write_history.front();
						if (pinfo->seqnum < (int)ntohl(acknum)) {
							this->cancelTimer(pinfo->timer->timerUUID);
							normal_socket->write_history.pop_front();
						}
						else
							break;
					}

					if (normal_socket->write_blocked != NULL) {																							// case: blocked write exists
						int written_bytes = 0;

						while (written_bytes < normal_socket->write_blocked->size) {
							struct buf_elem* elem = new buf_elem;
							struct timer_info* timer = new timer_info;
							struct packet_info* pinfo = new packet_info;
							uint8_t length[2];
							int writable = normal_socket->cwnd - normal_socket->write_buf_size;
							int write_bytes = writable >= normal_socket->write_blocked->size ? normal_socket->write_blocked->size : writable;
							write_bytes = 512 > write_bytes ? write_bytes : 512;
					
							if (writable <= 0)
								break;

							elem->seqnum = normal_socket->parent->seqnum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)];
							elem->size = write_bytes;
							elem->data = (char *)calloc(sizeof(char), write_bytes+1);
							memcpy(elem->data, normal_socket->write_blocked->data+written_bytes, write_bytes);

							new_packet = this->allocatePacket(54+write_bytes);
							memset(TCPHeader, 0, 20);
							*(uint32_t*)src_ip = normal_socket->src_ip;
							*(uint32_t*)dest_ip = normal_socket->dest_ip;
							*(uint32_t*)length = htons(write_bytes);
							*(uint16_t*)TCPHeader = normal_socket->src_port;																																										// source port
							*(uint16_t*)(TCPHeader+2) = normal_socket->dest_port;																																								// destination port
							*(uint32_t*)(TCPHeader+4) = htonl(normal_socket->parent->seqnum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)]);	// sequence number
							*(uint32_t*)(TCPHeader+8) = htonl(normal_socket->parent->acknum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)]);
							*(TCPHeader+12) = 0x50;																																																							// header size in 4bytes
							*(TCPHeader+13) = ACK;
							*(uint16_t*)(TCPHeader+14) = htons(WINDOWSIZE);																																											// window size
							new_packet->writeData(14+2, length, 2);
							new_packet->writeData(14+12, src_ip, 4);
							new_packet->writeData(14+16, dest_ip, 4);
	
							*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, (uint8_t*)elem->data, write_bytes, src_ip, dest_ip));
							new_packet->writeData(14+20, TCPHeader, 20);
							new_packet->writeData(14+20+20, elem->data, write_bytes);

							pinfo->seqnum = normal_socket->parent->seqnum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)];
							pinfo->size = write_bytes;

							timer->timerUUID = this->addTimer(timer, TIMEAFTER);
							timer->socket = normal_socket;
							timer->packet = this->clonePacket(new_packet);
							pinfo->timer = timer;

							this->sendPacket("IPv4", new_packet);
							normal_socket->parent->seqnum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)] += write_bytes;
							normal_socket->write_buf.push_back(elem);
							normal_socket->write_buf_size += write_bytes;
							normal_socket->write_history.push_back(pinfo);

							written_bytes += write_bytes;
						}

						this->returnSystemCall(normal_socket->write_blocked->syscallUUID, written_bytes);
						delete normal_socket->write_blocked;
						normal_socket->write_blocked = NULL;
					}
				}
				else {
					struct timer_info *timer = normal_socket->write_history.front()->timer;
					Packet *packet = timer->packet;

					normal_socket->cwnd = normal_socket->cwnd / 2;
					normal_socket->acked_bytes = 0;
					normal_socket->ssthresh = normal_socket->cwnd;

					this->cancelTimer(timer->timerUUID);
					timer->timerUUID = this->addTimer(timer, TIMEAFTER);
					timer->packet = this->clonePacket(packet);
					this->sendPacket("IPv4", packet);
				}

				if (normal_socket->write_history.empty() && normal_socket->FIN_packet != NULL) {		// check postponed FIN
					this->sendPacket("IPv4", normal_socket->FIN_packet);
					if (normal_socket->state == ST_ESTABLISHED)
						normal_socket->state = ST_FIN_WAIT_1;
					normal_socket->FIN_packet = NULL;
				}
			}
			else {																																								// ACK - data packet
				int datasize = ntohs(*(uint16_t*)length) - 40;
				int cur_acknum;
				bool duplicate = false;
				std::list<struct history_info*>::iterator it;
			
				cur_acknum = normal_socket->parent->acknum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)];

				for (it=normal_socket->read_history.begin(); it!=normal_socket->read_history.end(); ++it) {
					if ((*it)->seqnum == (int)ntohl(seqnum)) {
						duplicate = true;
						break;
					}
					else if ((*it)->seqnum > (int)ntohl(seqnum))
						break;
				}	

				if (!duplicate) {
					struct history_info* hinfo = new history_info;
					hinfo->seqnum = (int)ntohl(seqnum);
					hinfo->size = datasize;
					normal_socket->read_history.insert(it, hinfo);

					if (normal_socket->read_blocked != NULL && (normal_socket->read_history.size() == 1 || cur_acknum == (int)(int)ntohl(seqnum))) {	// case 1: blocked read exists and arriving packet is in right order
						int read_bytes = datasize > normal_socket->read_blocked->size ? normal_socket->read_blocked->size : datasize;
						packet->readData(14+20+20, normal_socket->read_blocked->data, read_bytes);	
	
						if (read_bytes < datasize) {
							struct buf_elem *elem = new buf_elem;
							elem->seqnum = (int)ntohl(seqnum);
							elem->size = datasize-read_bytes;
							elem->data = (char *)calloc(elem->size, sizeof(char));
							packet->readData(14+20+20+read_bytes, elem->data, elem->size);
							normal_socket->read_buf.push_front(elem);
							normal_socket->read_buf_size += elem->size;
						}

						this->returnSystemCall(normal_socket->read_blocked->syscallUUID, read_bytes);
						normal_socket->read_blocked = NULL;
					}
					else {																																							// case 2: no blocked read or arriving packet is out of order
						std::list<struct buf_elem*>::iterator buf_it;
						bool buf_duplicate = false;

						for (buf_it=normal_socket->read_buf.begin(); buf_it!=normal_socket->read_buf.end(); ++buf_it) {
							if ((*buf_it)->seqnum == (int)ntohl(seqnum)) {
								buf_duplicate = true;
								break;
							}
							else if ((*buf_it)->seqnum > (int)ntohl(seqnum))
								break;
						}

						if (!buf_duplicate) {																		// save it in read_buf only if the packet is not in the buffer
							struct buf_elem *elem = new buf_elem;
							elem->seqnum = (int)ntohl(seqnum);
							elem->size = datasize;
							elem->data = (char *)calloc(elem->size, sizeof(char));
							packet->readData(14+20+20, elem->data, elem->size);

							normal_socket->read_buf.insert(buf_it, elem);
							normal_socket->read_buf_size += elem->size;
						}
					}	
				}
					
				normal_socket->parent->acknum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)] = nextAcknum(normal_socket);
		
				new_packet = this->allocatePacket(54);
				memset(TCPHeader, 0, 20);
				*(uint16_t*)length = htons(40);
				*(uint32_t*)src_ip = normal_socket->src_ip;
				*(uint32_t*)dest_ip = normal_socket->dest_ip;
				*(uint16_t*)TCPHeader = normal_socket->src_port;					// source port
				*(uint16_t*)(TCPHeader+2) = normal_socket->dest_port;		// destination port
				*(uint32_t*)(TCPHeader+4) = htonl(normal_socket->parent->seqnum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)]);	// sequence number
				*(uint32_t*)(TCPHeader+8) = htonl(normal_socket->parent->acknum[std::make_pair(normal_socket->dest_ip, normal_socket->dest_port)]);
				*(TCPHeader+12) = 0x50;													// header size in 4bytes
				*(TCPHeader+13) = ACK;
				*(uint16_t*)(TCPHeader+14) = htons(BUFFERSIZE - normal_socket->read_buf_size);	// window size
				new_packet->writeData(14+2, length, 2);
				new_packet->writeData(14+12, src_ip, 4);
				new_packet->writeData(14+16, dest_ip, 4);
	
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, src_ip, dest_ip));
				new_packet->writeData(14+20, TCPHeader, 20);
		
				this->sendPacket("IPv4", new_packet);	
				
				if ((*normal_socket->read_history.rbegin())->seqnum < nextAcknum(normal_socket) && normal_socket->FIN_packet != NULL) {		// check postponed FIN
						this->sendPacket("IPv4", normal_socket->FIN_packet);
						if (normal_socket->state == ST_ESTABLISHED)
							normal_socket->state = ST_FIN_WAIT_1;
						normal_socket->FIN_packet = NULL;
				}
			}
		}
		else if (normal_socket->state == ST_LAST_ACK) {			// ACK of FIN (but it is not important because the socket is closed)
			if (normal_socket->handshake_timer != NULL) {
				this->cancelTimer(normal_socket->handshake_timer->timerUUID);
				normal_socket->handshake_timer = NULL;
			}
			normal_socket->state = ST_CLOSED;
		}
		else if (normal_socket->state == ST_FIN_WAIT_1) {		// ACK of FIN
			if (normal_socket->handshake_timer != NULL) {
				this->cancelTimer(normal_socket->handshake_timer->timerUUID);
				normal_socket->handshake_timer = NULL;
			}
			normal_socket->state = ST_FIN_WAIT_2;
		}
		else if (normal_socket->state == ST_CLOSING) {			// ACK of FIN
			if (normal_socket->handshake_timer != NULL) {
				this->cancelTimer(normal_socket->handshake_timer->timerUUID);
				normal_socket->handshake_timer = NULL;
			}
			normal_socket->state = ST_TIME_WAIT;
		}
	}
	else if (~bits & SYN && ~bits & ACK && bits & FIN) {
		// FIN
		
		struct socket_info* normal_socket, *connect_socket;

		normal_socket = NULL;
		connect_socket = NULL;
	
		// search connect_socket_list
		for (std::list<struct socket_info*>::iterator it=this->connect_socket_list.begin(); it!=this->connect_socket_list.end(); ++it) {
			if (((*it)->src_ip == 0 || (*it)->src_ip == *(uint32_t*)dest_ip) && (*it)->src_port == *(uint16_t*)dest_port && (*it)->dest_ip == *(uint32_t*)src_ip && (*it)->dest_port == *(uint16_t*)src_port) {
				if ((*it)->src_ip == 0)
					(*it)->src_ip = *(uint32_t*)dest_ip;
				connect_socket = *it;
				break;
			}
		}
		
		// search socket_list
		for (std::list<struct socket_info*>::iterator it=this->socket_list.begin(); it!=this->socket_list.end(); ++it) {
			if (((*it)->src_ip == 0 || (*it)->src_ip == *(uint32_t*)dest_ip) && (*it)->src_port == *(uint16_t*)dest_port) {
				normal_socket = *it;
				break;
			}
		}
	
		if (connect_socket != NULL){
			if (connect_socket->write_history.empty() || (!connect_socket->read_history.empty() && nextAcknum(connect_socket) != (*connect_socket->read_history.rbegin())->seqnum + (*connect_socket->read_history.rbegin())->size)) {
				return;
			}
		}
		else if (normal_socket != NULL) {
			if (normal_socket->write_history.empty() || (!normal_socket->read_history.empty() && nextAcknum(normal_socket) != (*normal_socket->read_history.rbegin())->seqnum + (*normal_socket->read_history.rbegin())->size)) {
				return;
			}
		}

		if (normal_socket != NULL) {
			new_packet = this->clonePacket(packet);
			if (normal_socket->state == ST_LISTEN) {	// server side
				if (connect_socket == NULL) {						// client closes a connection before it is actually constructed by accept()
					bits = ACK;
					new_seqnum = htonl(normal_socket->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);
					normal_socket->parent->acknum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = (int)ntohl(seqnum)+1;
					new_acknum = htonl((int)ntohl(seqnum)+1);
				
					new_packet->writeData(14+12, dest_ip, 4);
					new_packet->writeData(14+16, src_ip, 4);
					new_packet->writeData(14+20+0, dest_port, 2);
					new_packet->writeData(14+20+2, src_port, 2);
					new_packet->writeData(14+20+4, (uint8_t*)&new_seqnum, 4);
					new_packet->writeData(14+20+8, (uint8_t*)&new_acknum, 4);
					new_packet->writeData(14+20+13, &bits, 1);

					new_packet->readData(14+20, TCPHeader, 20);
					*(uint16_t*)(TCPHeader+16) = 0;
					*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, dest_ip, src_ip));

					new_packet->writeData(14+20, TCPHeader, 20);

					this->sendPacket("IPv4", new_packet);
				}
				else {																	// client closes a connection after it is constructed by accept()
					if (connect_socket->state == ST_ESTABLISHED || connect_socket->state == ST_FIN_WAIT_1 || connect_socket->state == ST_FIN_WAIT_2) {
						if (connect_socket->state == ST_ESTABLISHED)
							connect_socket->state = ST_CLOSE_WAIT;
						else if (connect_socket->state == ST_FIN_WAIT_1)
							connect_socket->state = ST_CLOSING;
						else
							connect_socket->state = ST_TIME_WAIT;

						bits = ACK;
						new_seqnum = htonl(connect_socket->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);
						connect_socket->parent->acknum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = (int)ntohl(seqnum)+1;
						new_acknum = htonl((int)ntohl(seqnum)+1);
				
						new_packet->writeData(14+12, dest_ip, 4);
						new_packet->writeData(14+16, src_ip, 4);
						new_packet->writeData(14+20+0, dest_port, 2);
						new_packet->writeData(14+20+2, src_port, 2);
						new_packet->writeData(14+20+4, (uint8_t*)&new_seqnum, 4);
						new_packet->writeData(14+20+8, (uint8_t*)&new_acknum, 4);
						new_packet->writeData(14+20+13, &bits, 1);

						new_packet->readData(14+20, TCPHeader, 20);
						*(uint16_t*)(TCPHeader+16) = 0;
						*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, dest_ip, src_ip));

						new_packet->writeData(14+20, TCPHeader, 20);

						this->sendPacket("IPv4", new_packet);

						if (connect_socket->write_blocked != NULL || connect_socket->read_blocked != NULL) {			// if there is pending system call, unblock it
							struct buf_elem* elem;

							if (connect_socket->write_blocked != NULL) {
								elem = connect_socket->write_blocked;
								connect_socket->write_blocked = NULL;
							}
							else {
								elem = connect_socket->read_blocked;
								connect_socket->read_blocked = NULL;
							}

							this->returnSystemCall(elem->syscallUUID, 0);
						}
					}
				}
			}
			else if (normal_socket->state == ST_ESTABLISHED || normal_socket->state == ST_FIN_WAIT_1 || normal_socket->state == ST_FIN_WAIT_2) {
				if (normal_socket->state == ST_ESTABLISHED)
					normal_socket->state = ST_CLOSE_WAIT;
				else if (normal_socket->state == ST_FIN_WAIT_1)
					normal_socket->state = ST_CLOSING;
				else
					normal_socket->state = ST_TIME_WAIT;

				bits = ACK;
				new_seqnum = htonl(normal_socket->parent->seqnum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)]);
				normal_socket->parent->acknum[std::make_pair(*(uint32_t*)src_ip, *(uint16_t*)src_port)] = (int)ntohl(seqnum)+1;
				new_acknum = htonl((int)ntohl(seqnum)+1);
				
				new_packet->writeData(14+12, dest_ip, 4);
				new_packet->writeData(14+16, src_ip, 4);
				new_packet->writeData(14+20+0, dest_port, 2);
				new_packet->writeData(14+20+2, src_port, 2);
				new_packet->writeData(14+20+4, (uint8_t*)&new_seqnum, 4);
				new_packet->writeData(14+20+8, (uint8_t*)&new_acknum, 4);
				new_packet->writeData(14+20+13, &bits, 1);

				new_packet->readData(14+20, TCPHeader, 20);
				*(uint16_t*)(TCPHeader+16) = 0;
				*(uint16_t*)(TCPHeader+16) = htons(makeChecksum(TCPHeader, NULL, 0, dest_ip, src_ip));

				new_packet->writeData(14+20, TCPHeader, 20);

				this->sendPacket("IPv4", new_packet);

				if (normal_socket->write_blocked != NULL || normal_socket->read_blocked != NULL) {								// if there is pending system call, unblock it
					struct buf_elem* elem;

					if (normal_socket->write_blocked != NULL) {
						elem = normal_socket->write_blocked;
						normal_socket->write_blocked = NULL;
					}
					else {
						elem = normal_socket->read_blocked;
						normal_socket->read_blocked = NULL;
					}

					this->returnSystemCall(elem->syscallUUID, 0);
				}
			}
		}
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	struct timer_info* timer = (struct timer_info*)payload;
	struct socket_info* socket = (struct socket_info*)timer->socket;
	Packet *packet = (Packet *)timer->packet;

	if (socket->handshake_timer != NULL) {
		timer->timerUUID = this->addTimer(timer, TIMEAFTER);
		timer->packet = this->clonePacket(packet);
		this->sendPacket("IPv4", packet);
	}
//	else {
//		socket->ssthresh = socket->cwnd / 2;
//		socket->cwnd = MSS;
//		socket->slow_start = 1;
//	}
}


}
