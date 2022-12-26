#pragma once
#include <string>
#include <cstdint>
#include <ostream>
#include <boost/asio/ip/tcp.hpp>
#include <boost/noncopyable.hpp>

using boost::asio::ip::tcp;
using boost::asio::io_context;

constexpr size_t PACKET_SIZE = 1024;

class ClientSocket : boost::noncopyable
{
private:
	std::string m_address;
	std::string m_port;
	std::unique_ptr<io_context> m_ioContext;
	std::unique_ptr<tcp::resolver> m_resolver;
	std::unique_ptr<tcp::socket> m_socket;
	bool m_connected = false;  // True if socket opend and connected else False

	static bool IsValidAddress(const std::string& address);
	static bool IsValidPort(const std::string& port);

	bool Connect();
	void Close();
	bool Receive(uint8_t* const buffer, const size_t size, size_t packetSize = PACKET_SIZE) const;
	bool Send(const uint8_t* const buffer, const size_t size) const;

public:
	ClientSocket(const std::string& address, const std::string& port);
	ClientSocket(const std::string& address, int port);
	virtual ~ClientSocket();

	friend std::ostream& operator<<(std::ostream& os, const ClientSocket& socket)
	{
		os << socket.m_address << ':' << socket.m_port;
		return os;
	}

	bool ConnectAndSend(const uint8_t* const toSend, const size_t size);
	uint8_t* SendAndReceive(const uint8_t* const toSend, const size_t size);
	uint8_t* RetryableSendAndReceive(const uint8_t* const toSend, const size_t size, int retries, const std::string& errorDesc);
};
