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

struct timer_info {
	UUID timerUUID;
	void *socket;
	Packet *packet;
};

struct packet_info {
	int seqnum;
	int size;
	struct timer_info* timer;
};

struct buf_elem {									// element of write_buf and read_buf
	UUID syscallUUID;								// syscallUUID of write/read call
	int seqnum;											// sequence number when write/read is called
	int size;												// size parameter
	char *data;											// buffer pointer parameter
};

struct socket_info {
	int fd;													// file descripter
	int pid;												// id of process which created this socket
	int listenUUID;									// syscallUUID of LISTEN (if passive open)
	struct socket_info* parent;			// if created during accept(), the listening socket. otherwise, itself.

	bool bind;											// bound or not
	int state;

	std::map<std::pair<uint32_t, uint16_t>, int> seqnum;				// sequence number for each connection
																															// | (<destination ip>, <destination port>) can distinguish every connection
	std::map<std::pair<uint32_t, uint16_t>, int> acknum;
	std::map<std::pair<uint32_t, uint16_t>, int> readnum;

	int last_acknum;
	int last_acknum_cnt;

	uint32_t backlog;
	
	uint32_t src_ip;			// name of this socket
	uint16_t src_port;
	uint32_t dest_ip;			// name of peer
	uint16_t dest_port;

	std::list<struct buf_elem*> write_buf;		// write buffer
	int write_buf_size;												// write buffer size
	struct buf_elem* write_blocked;						// blocked write call
	std::list<struct packet_info*> sent_packet;

	std::list<struct buf_elem*> read_buf;			// read buffer
	int read_buf_size;												// read buffer size
	struct buf_elem* read_blocked;						// blocked read

	struct timer_info* handshake_timer;
	Packet *FIN_packet;
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
	std::list<struct socket_info*> socket_list;														// all sockets except ones created when SYN_RCVD
	std::list<struct socket_info*> connect_socket_list;										// sockets created when SYN_RCVD
	std::list<struct socket_info*> closed_socket_list;										// (maybe not useful)
	std::list<std::pair<struct socket_info*, UUID>> block_connect;									// blocked CONNECT
	std::list<std::pair<struct socket_info*, std::pair<UUID, struct socket_info*>>> block_accept;	// blocked ACCEPT
	std::list<std::pair<UUID, struct sockaddr_in*>> block_accept_addr;							// sockaddr to be filled

	std::map<int, std::list<struct connection_info*>> connection_SYN;								// SYN request queue
	std::map<int, std::list<struct connection_info*>> connection_ACK;								// ACK request queue
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
	void syscall_read(UUID syscallUUID, int pid, int fd, void *buf, int size);
	void syscall_write(UUID syscallUUID, int pid, int fd, void *buf, int size);
	void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t len);
	int syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *lenptr);
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
