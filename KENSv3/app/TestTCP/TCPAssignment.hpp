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

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

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
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

class BoundInfo
{
	int fd;
	int bound;
	uint32_t ip_addr;
	uint16_t port;
	BoundInfo* next;

	public:
		BoundInfo(int fd);
		int getFd() { return this->fd; }
		int getBound() { return this->bound; }
		void setBound(int bound) { this->bound = bound; }
		uint32_t getIp() { return this->ip_addr; }
		void setIp(uint32_t ip_addr) { this->ip_addr = ip_addr; }
		uint16_t getPort() { return this->port; }
		void setPort(uint16_t port) { this->port = port; }
		BoundInfo* getNext() { return this->next; }
		void setNext(BoundInfo* next) { this->next = next; }
};

class BoundInfoHead
{
	BoundInfo* next;

	public:
		BoundInfoHead() { this->next = NULL; }
		BoundInfo* findInfo(int fd, uint32_t ip_addr, uint16_t port);
		int addInfo(int fd);
		int bindInfo(int fd, uint32_t ip_addr, uint16_t port);
		void unboundInfo(int fd);
};

}

#endif /* E_TCPASSIGNMENT_HPP_ */
