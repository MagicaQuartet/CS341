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


namespace E
{

struct connect_socket {
	int fd;
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dest_ip;
	uint16_t dest_port;
	int state;
};

BoundInfoHead* list = new BoundInfoHead();																		// the head of the list of BoundInfo instances
std::list<std::pair<UUID, std::pair<uint32_t, uint16_t> > > blocked;
std::map<std::pair<uint32_t, uint16_t>, int> server_backlog;
std::map<std::pair<uint32_t, uint16_t>, int> server_pid;
std::map<std::pair<uint32_t, uint16_t>, std::list<struct connect_socket*> > server_SYN;
std::map<std::pair<uint32_t, uint16_t>, std::list<struct connect_socket*> > server_ACK;

BoundInfo::BoundInfo(int fd)																									// the constructor of BoundInfo class
{
	this->fd = fd;
	this->bound = -1;																														// In default, this instance is not bound
	this->ip_addr = 0;																													// ... and does not have ip_addr
	this->port = 0;																															// ... and does not have port number
	this->next = NULL;																													// ... and does not have the next instance

	this->dest_ip_addr = 0;
	this->dest_port = 0;
	this->state = ST_CLOSED;
}																																							// ... (initializing ip_addr and port number as 0 can be problematic, but can be handled properly by other functions)

BoundInfo* BoundInfoHead::findInfo(int fd, uint32_t ip_addr, uint16_t port)		// search a BoundInfo instance (1) whose file descriptor is fd
{																																							// ... or (2) whose ip address is ip_addr and port number is port
	BoundInfo* info = this->next;																								// if such instance exists, return its pointer. Otherwise, return NULL.
	if (fd < 0) {					// case (2)
		while (info != NULL) {
			if (info->getBound() == 1) {				// this info has ip_addr and port number
				if (ip_addr == 0 || info->getIp() == 0) {			// either of them is INADDR_ANY
					if (port == info->getPort())								// ... then check port number
						break;
				}
				else {
					if ((ip_addr == info->getIp()) && (port == info->getPort()))
						break;
				}
			}

			info = info->getNext();
		}

		return info;
	}
	else {								// case (1)
		while (info != NULL) {
			if (fd == info->getFd())
				break;

			info = info->getNext();
		}

		return info;
	}
}

int BoundInfoHead::addInfo(int fd)																						// add a BoundInfo instance whose file descriptor is fd
{
	if (this->next == NULL) {																										// if the list is empty
		this->next = new BoundInfo(fd);																						// ... just add the instance
		return 0;
	}
	else {																																			// otherwise, check if there is the other instance whose file descriptor is also fd or not
		if (this->findInfo(fd, -1, -1) == NULL) {
			BoundInfo* new_elem = new BoundInfo(fd);
			BoundInfo* next_elem = this->next;
			new_elem->setNext(next_elem);
			this->next = new_elem;
			return 0;
		}
		else
			return -1;
	}
}

int BoundInfoHead::bindInfo(int fd, uint32_t ip_addr, uint16_t port)					// bind a socket whose file descriptor is fd where ip address is ip_addrr and port number is port
{
	if (ntohs(port) > 10000)
		return -1;
	
	BoundInfo* info = this->findInfo(fd, -1, -1);

	if (info == NULL)																														// check if a socket whose file descriptor is fd is already created
		return -1;
	else if (info->getBound() == 1)																							// if exists, check if it is bound or not.
		return -1;
	else {
		BoundInfo* temp = this->findInfo(-1, ip_addr, port);											// if not bound, check if this socket can be bound without violating bind rules
		if (temp != NULL)
			return -1;
		else {
			info->setBound(1);
			info->setIp(ip_addr);
			info->setPort(port);
			return 0;
		}
	}
}

void BoundInfoHead::unboundInfo(int fd)																				// this function is called when handling close() system call
{																																							// remove a BoundInfo instance whose file descriptor is fd from the list
	BoundInfo* info = this->next;
	BoundInfo* prev = NULL;

	while (info != NULL) {
		if (info->getFd() == fd) {
			if (prev == NULL) {
				this->next = info->getNext();
			}
			else {
				prev->setNext(info->getNext());
			}
		}

		prev = info;
		info = info->getNext();
	}
}

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

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	unsigned int fd;
	int ret;
	struct sockaddr_in *ptr;
	uint8_t ip[4], src_ip[4], dest_ip[4];
	uint8_t src_port[2], dest_port[2];
	Host* host;
	Packet* packet;
	BoundInfo* info;
	struct connect_socket* sock;

	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		fd = this->createFileDescriptor(pid);
		list->addInfo(fd);
		this->returnSystemCall(syscallUUID, fd);
		break;
	case CLOSE:
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		this->removeFileDescriptor(pid, param.param1_int);
		list->unboundInfo(param.param1_int);
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
		ptr = (struct sockaddr_in *)param.param2_ptr;
		info = list->findInfo(param.param1_int, -1, -1);
		if (info == NULL)
			this->returnSystemCall(syscallUUID, -1);
		else {
			if (info->getBound() == -1) {
				host = this->getHost();
				info->setIp(host->getIPAddr(ip, host->getRoutingTable((uint8_t *)&(ptr->sin_addr.s_addr))));
				info->setPort(info->getFd());
				//info->setBound(1);
			}

			info->setDestIp(ptr->sin_addr.s_addr);
			info->setDestPort(ptr->sin_port);

			packet = allocatePacket(1000);
			*(uint32_t*)src_ip = info->getIp();
			*(uint32_t*)dest_ip = info->getDestIp();
			*(uint16_t*)src_port = info->getPort();
			*(uint16_t*)dest_port = info->getDestPort();
			packet->writeData(14+12, src_ip, 4);
			packet->writeData(14+16, dest_ip, 4);
			packet->writeData(14+20+0, src_port, 2);
			packet->writeData(14+20+2, dest_port, 2);

			blocked.push_back(std::make_pair(syscallUUID, std::make_pair(info->getIp(), info->getPort())));

			this->sendPacket("IPv4", packet);
			info->setState(ST_ESTABLISHED);
//			this->freePacket(packet);
		}
		
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		info = list->findInfo(param.param1_int, -1, -1);
		if (info == NULL || info->getBound() == -1)
			this->returnSystemCall(syscallUUID, -1);
		else {
			info->setState(ST_LISTEN);
			server_backlog[std::make_pair(info->getIp(), info->getPort())] = param.param2_int;
			server_pid[std::make_pair(info->getIp(), info->getPort())] = pid;
			server_SYN[std::make_pair(info->getIp(), info->getPort())] = std::list<struct connect_socket*>();
			server_ACK[std::make_pair(info->getIp(), info->getPort())] = std::list<struct connect_socket*>();
			this->returnSystemCall(syscallUUID, 0);
		}
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		ptr = (struct sockaddr_in *)param.param2_ptr;
		info = list->findInfo(param.param1_int, -1, -1);
		
		sock = NULL;

		for (std::map<std::pair<uint32_t, uint16_t>, std::list<struct connect_socket*>>::iterator it=server_ACK.begin(); it!=server_ACK.end(); ++it) {
			if (it->first.second == info->getPort()) {
				if (!it->second.empty()) {
					sock = it->second.front();
					it->second.pop_front();
					break;
				}
			}
		}

		if (sock == NULL)
			blocked.push_back(std::make_pair(syscallUUID, std::make_pair(info->getIp(), info->getPort())));
		else {
			ptr->sin_family = AF_INET;
			ptr->sin_port = sock->dest_port;
			ptr->sin_addr.s_addr = sock->dest_ip;
			this->returnSystemCall(syscallUUID, sock->fd);
		}
		break;
	case BIND:
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		ptr = (struct sockaddr_in *)param.param2_ptr;
		ret = list->bindInfo(param.param1_int, ptr->sin_addr.s_addr, ptr->sin_port);
		this->returnSystemCall(syscallUUID, ret);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		ptr = (struct sockaddr_in *)param.param2_ptr;
		info = list->findInfo(param.param1_int, -1, -1);
		if (info == NULL || info->getBound() == -1)				// if a socket whose file descriptor is fd is not created or not bound
			ret = -1;
		else {
			ptr->sin_family = AF_INET;
			ptr->sin_addr.s_addr = info->getIp();
			ptr->sin_port = info->getPort();
			ret = 0;
		}
		this->returnSystemCall(syscallUUID, ret);
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint8_t src_ip[4], dest_ip[4], src_port[2], dest_port[2];
	uint8_t bits, syn = 0x02, ack = 0x10;
	
	Packet* myPacket = this->clonePacket(packet);

	packet->readData(14+12, src_ip, 4);
	packet->readData(14+16, dest_ip, 4);
	packet->readData(14+20+0, src_port, 2);
	packet->readData(14+20+2, dest_port, 2);
	packet->readData(14+20+13, &bits, 1);

	myPacket->writeData(14+12, dest_ip, 4);
	myPacket->writeData(14+16, src_ip, 4);
	myPacket->writeData(14+20+0, dest_port, 2);
	myPacket->writeData(14+20+2, src_port, 2);

	if (!(bits & syn)) {
		// third step, server-side
		UUID uuid;
		bool found = false;
		for (std::list<std::pair<UUID, std::pair<uint32_t, uint16_t> > >::iterator it=blocked.begin(); it!=blocked.end(); ++it) {
			uint32_t ip = (*it).second.first;
			uint16_t port = (*it).second.second;

			if ((ip == *(uint32_t*)dest_ip || ip == 0) && port == *(uint16_t*)dest_port) {
				uuid = (*it).first;
				blocked.erase(it);
				break;
			}
		}

		std::map<std::pair<uint32_t, uint16_t>, std::list<struct connect_socket*>>::iterator it = server_SYN.find(std::make_pair(*(uint32_t*)dest_ip, *(uint16_t*)dest_port));

		if (it == server_SYN.end())
			it = server_SYN.find(std::make_pair(0, *(uint16_t*)dest_port));
			
		struct connect_socket* sock = NULL;
		for (std::list<struct connect_socket*>::iterator list_it=(it->second).begin(); list_it!=(it->second).end(); ++list_it) {
			if ((*list_it)->src_ip == *(uint32_t*)dest_ip && (*list_it)->src_port == *(uint16_t*)dest_port) {
				sock = *list_it;
				break;
			}
		}
		server_SYN.erase(it);

		if (found) {	
			this->returnSystemCall(uuid, sock->fd);
			// free(sock);
		}
		else {
			it = server_ACK.find(std::make_pair(*(uint32_t*)dest_ip, *(uint16_t*)dest_port));

			if (it == server_ACK.end())
				it = server_ACK.find(std::make_pair(0, *(uint16_t*)dest_port));
			it->second.push_back(sock);
		}

		this->freePacket(myPacket);
	}
	else {
		if (bits & ack) {
			// second step, client-side
			
			bits = bits & ~syn;
			myPacket->writeData(14+20+13, &bits, 1);
			this->sendPacket("IPv4", myPacket);

			for (std::list<std::pair<UUID, std::pair<uint32_t, uint16_t> > >::iterator it=blocked.begin(); it!=blocked.end(); ++it) {
				uint32_t ip = (*it).second.first;
				uint16_t port = (*it).second.second;

				if (ip == *(uint32_t*)dest_ip && port == *(uint16_t*)dest_port) {
					this->returnSystemCall((*it).first, 0);
					blocked.erase(it);
					break;
				}
			}

			this->freePacket(myPacket);
		}
		else {
			// first step, server-side
			int backlog;
			int pid;
			std::list<struct connect_socket *> SYN_list;
			
			std::map<std::pair<uint32_t, uint16_t>, int>::iterator it = server_backlog.find(std::make_pair(*(uint32_t*)dest_ip, *(uint16_t*)dest_port));

			if (it != server_backlog.end()) {
				backlog = server_backlog[std::make_pair(*(uint32_t*)dest_ip, *(uint16_t*)dest_port)];
				pid = server_pid[std::make_pair(*(uint32_t*)dest_ip, *(uint16_t*)dest_port)];
				SYN_list = server_SYN[std::make_pair(*(uint32_t*)dest_ip, *(uint16_t*)dest_port)];
			}
			else {
				backlog = server_backlog[std::make_pair(0, *(uint16_t*)dest_port)];
				pid = server_pid[std::make_pair(0, *(uint16_t*)dest_port)];
				SYN_list = server_SYN[std::make_pair(0, *(uint16_t*)dest_port)];
			}

			if (backlog > SYN_list.size()) {
				struct connect_socket *sock = (struct connect_socket *)calloc(sizeof(struct connect_socket), 1);

				sock->fd = this->createFileDescriptor(pid);
				sock->src_ip = *(uint32_t*)dest_ip;
				sock->src_port = *(uint16_t*)dest_port;
				sock->dest_ip = *(uint32_t*)src_ip;
				sock->dest_port = *(uint16_t*)src_port;
				sock->state = ST_SYN_RCVD;

				SYN_list.push_back(sock);
			}

			bits = bits | ack;
			myPacket->writeData(14+20+13, &bits, 1);
			this->sendPacket("IPv4", myPacket);
			
			//this->freePacket(myPacket);*/
		}
	}
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
