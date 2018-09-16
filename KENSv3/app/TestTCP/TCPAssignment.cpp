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
#include "TCPAssignment.hpp"


namespace E
{

BoundInfoHead* list = new BoundInfoHead();																		// the head of the list of BoundInfo instances

BoundInfo::BoundInfo(int fd)																									// the constructor of BoundInfo class
{
	this->fd = fd;
	this->bound = -1;																														// In default, this instance is not bound
	this->ip_addr = 0;																													// ... and does not have ip_addr
	this->port = 0;																															// ... and does not have port number
	this->next = NULL;																													// ... and does not have the next instance
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
	BoundInfo* info;

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
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
