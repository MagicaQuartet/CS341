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

BoundInfoHead* list = new BoundInfoHead();

BoundInfo::BoundInfo(int fd)
{
	this->fd = fd;
	this->bound = -1;
	this->ip_addr = 0;
	this->port = 0;
	this->next = NULL;
}

BoundInfo* BoundInfoHead::findInfo(int fd, uint32_t ip_addr, uint16_t port)
{
	BoundInfo* info = this->next;
	if (fd < 0) {
		while (info != NULL) {
			if (info->getBound() == 1) {
				if (ip_addr == 0 || info->getIp() == 0) {
					if (port == info->getPort())
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
	else {
		while (info != NULL) {
			if (fd == info->getFd())
				break;

			info = info->getNext();
		}

		return info;
	}
}

int BoundInfoHead::addInfo(int fd)
{
	if (this->next == NULL) {
		this->next = new BoundInfo(fd);
		return 0;
	}
	else {
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

int BoundInfoHead::bindInfo(int fd, uint32_t ip_addr, uint16_t port)
{
	if (ntohs(port) > 10000)
		return -1;

	BoundInfo* info = this->findInfo(fd, -1, -1);

	if (info == NULL)
		return -1;
	else if (info->getBound() == 1)
		return -1;
	else {
		BoundInfo* temp = this->findInfo(-1, ip_addr, port);
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

void BoundInfoHead::unboundInfo(int fd)
{
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
		if (info == NULL || info->getBound() == -1)
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
