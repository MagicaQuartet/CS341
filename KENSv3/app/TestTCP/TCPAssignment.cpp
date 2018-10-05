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

enum {ST_CLOSED, ST_LISTEN, ST_SYN_SENT, ST_SYN_RCVD, ST_ESTABLISHED};

struct socket_info {
	int fd;
	bool explicit_bind;
	int state;
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dest_ip;
	uint32_t dest_port;
};

std::list<struct socket_info*> socket_list;

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
	struct socket_info* sock;
	struct sockaddr_in* ptr;
	int fd, ret;

	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		fd = this->createFileDescriptor(pid);
		sock = (struct socket_info*)calloc(sizeof(struct socket_info), 1);

		sock->fd = fd;
		sock->state = ST_CLOSED;
		sock->explicit_bind = false;
		sock->src_ip = 0;
		sock->src_port = 0;
		sock->dest_ip = 0;
		sock->dest_port = 0;

		socket_list.push_back(sock);

		this->returnSystemCall(syscallUUID, fd);
		break;
	case CLOSE:
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		this->removeFileDescriptor(pid, param.param1_int);
		
		for (std::list<struct socket_info*>::iterator it=socket_list.begin(); it!=socket_list.end(); ++it) {
			if ((*it)->fd == param.param1_int) {
				free(*it);
				socket_list.erase(it);
				break;
			}
		}

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
		sock = NULL;

		for (std::list<struct socket_info*>::iterator it=socket_list.begin(); it!=socket_list.end(); ++it) {
			if ((*it)->fd == param.param1_int) {
				sock = *it;
				break;
			}
		}
		
		if (sock == NULL)
			ret = -1;
		else {
			if (sock->explicit_bind)
				ret = -1;
			else {
				ret = 0;
				for (std::list<struct socket_info*>::iterator it=socket_list.begin(); it!=socket_list.end(); ++it) {
					if ((ptr->sin_addr.s_addr == 0 || (*it)->src_ip == 0 || ptr->sin_addr.s_addr == (*it)->src_ip) && ptr->sin_port == (*it)->src_port) {
						ret = -1;
						break;
					}
				}
			}
		}

		if (!ret) {
			sock->explicit_bind = true;
			sock->src_ip = ptr->sin_addr.s_addr;
			sock->src_port = ptr->sin_port;
		}

		this->returnSystemCall(syscallUUID, ret);
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		ptr = (struct sockaddr_in *)param.param2_ptr;
		sock = NULL;

		for (std::list<struct socket_info*>::iterator it=socket_list.begin(); it!=socket_list.end(); ++it) {
			if ((*it)->fd == param.param1_int) {
				sock = *it;
				break;
			}
		}

		if (sock == NULL)				// if a socket whose file descriptor is fd is not created or not bound
			ret = -1;
		else {
			ptr->sin_family = AF_INET;
			ptr->sin_addr.s_addr = sock->src_ip;
			ptr->sin_port = sock->src_port;
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
