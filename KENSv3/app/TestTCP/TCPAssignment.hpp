/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

struct socket_info {
	int fd;
	int pid;

	bool bind;
	int state;

	int seqnum;
	uint32_t backlog;
	
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dest_ip;
	uint16_t dest_port;
};

struct connection_info {
	uint32_t client_ip;
	uint16_t client_port;
	uint32_t server_ip;
	uint16_t server_port;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::list<struct socket_info*> socket_list;
	std::list<struct socket_info*> connect_socket_list;
	std::list<std::pair<struct socket_info*, UUID>> block_connect;
	std::list<std::pair<struct socket_info*, std::pair<UUID, struct socket_info*>>> block_accept;
	std::list<std::pair<UUID, struct sockaddr_in*>> block_accept_addr;

	std::map<int, std::list<struct connection_info*>> connection_SYN;
	std::map<int, std::list<struct connection_info*>> connection_ACK;
private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	int syscall_socket(int pid);
	void syscall_close(int pid, int fd);
	// int syscall_read();
	// int syscall_write();
	void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t len);
	// void syscall_listen();
	// int syscall_accept();
	int syscall_bind(int pid, int fd, struct sockaddr * addr, socklen_t len);
	int syscall_getsockname(int pid, int fd, struct sockaddr *addr, socklen_t *lenptr);
	int syscall_getpeername(int pid, int fd, struct sockaddr *addr, socklen_t *lenptr);
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}

#endif /* E_TCPASSIGNMENT_HPP_ */
