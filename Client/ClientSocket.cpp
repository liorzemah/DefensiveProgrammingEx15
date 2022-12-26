#include "ClientSocket.h"
#include "Endianess.h"
#include <boost/asio.hpp>
#include "Protocol.h"
#include <iostream>
#include "ClientLogic.h"
#include "FatalError.h"

using boost::asio::ip::tcp;
using boost::asio::io_context;

ClientSocket::ClientSocket(const std::string& address, const std::string& port)
{
	if (!IsValidAddress(address))
	{
		throw std::invalid_argument(address + " is invalid ip address");
	}

	if (!IsValidPort(port))
	{
		throw std::invalid_argument(address + " is invalid port");
	}

	m_address = address;
	m_port = port;
	m_ioContext = std::make_unique<io_context>();
	m_resolver = std::make_unique<tcp::resolver>(*m_ioContext);
	m_socket = std::make_unique<tcp::socket>(*m_ioContext);
}

ClientSocket::ClientSocket(const std::string& address, int port) : ClientSocket(address, std::to_string(port))
{
}

ClientSocket::~ClientSocket()
{
	Close();
}

// Try to parse IP Address. Return false if failed
bool ClientSocket::IsValidAddress(const std::string& address)
{
	if ((address == "localhost") || (address == "LOCALHOST"))
		return true;
	try
	{
		(void) boost::asio::ip::address_v4::from_string(address);
	}
	catch(...)
	{
		return false;
	}
	return true;
}

// Try to parse a port number from a string. Return false if failed
bool ClientSocket::IsValidPort(const std::string& port)
{
	try
	{
		const int p = std::stoi(port);
		return (p > 0 && p <= 65535);  // port value must be between 1-65535
	}
	catch(...)
	{
		return false;
	}
}


// Clear socket and connect to new socket
bool ClientSocket::Connect()
{
	try
	{
		boost::asio::connect(*m_socket, m_resolver->resolve(m_address, m_port, tcp::resolver::query::canonical_name));
		m_socket->non_blocking(false);
		m_connected = true;
	}
	catch(...)
	{
		m_connected = false;
	}
	return m_connected;
}


// Close socket and clear it
void ClientSocket::Close()
{
	try
	{
		if (m_socket != nullptr)
			m_socket->close();
	}
	catch (...) {} // Do Nothing
	m_connected = false;
}


/**
 * Receive size bytes from _socket to buffer.
 * Return false if unable to receive expected size bytes.
 */
bool ClientSocket::Receive(uint8_t* const buffer, const size_t size, size_t packetSize) const
{
	if (m_socket == nullptr || buffer == nullptr || size == 0 || !m_connected)
	{
		return false;
	}

	size_t bytesLeft = size;
	uint8_t* ptr = buffer;
	while (bytesLeft > 0)
	{
		uint8_t* tempBuffer = new uint8_t[packetSize] { 0 };
		boost::system::error_code errorCode; // read() will not throw exception when error_code is passed as argument.
		
		size_t bytesRead = read(*m_socket, boost::asio::buffer(tempBuffer, packetSize), errorCode); // receive bytes in little endian
		if (bytesRead == 0)
		{
			delete[] tempBuffer;
			return false;     // Failed receiving and shouldn't use buffer.
		}

		if (!Endianess::IsLittleEndian())
		{
			Endianess::Swap(tempBuffer, bytesRead); // It's required to convert from little endian to big endian.
		}
		
		const size_t bytesToCopy = (bytesLeft > bytesRead) ? bytesRead : bytesLeft;  // prevent buffer overflow.
		memcpy(ptr, tempBuffer, bytesToCopy);
		ptr += bytesToCopy;
		bytesLeft = (bytesLeft < bytesToCopy) ? 0 : (bytesLeft - bytesToCopy);  // unsigned protection.
		delete[] tempBuffer;
	}
	
	return true;
}

/**
 * Send size bytes from buffer to _socket.
 * Return false if unable to send expected size bytes.
 */
bool ClientSocket::Send(const uint8_t* const buffer, const size_t size) const
{
	if (m_socket == nullptr || !m_connected || buffer == nullptr || size == 0)
		return false;
	
	size_t bytesLeft   = size;
	const uint8_t* ptr = buffer;
	while (bytesLeft > 0)
	{
		boost::system::error_code errorCode; // write() will not throw exception when error_code is passed as argument.
		uint8_t tempBuffer[PACKET_SIZE] = { 0 };
		const size_t bytesToSend = (bytesLeft > PACKET_SIZE) ? PACKET_SIZE : bytesLeft;
		
		memcpy(tempBuffer, ptr, bytesToSend);

		Endianess::ToLittle(tempBuffer, bytesToSend); // need to send data in little endian for compatibility between client and server

		const size_t bytesWritten = write(*m_socket, boost::asio::buffer(tempBuffer, PACKET_SIZE), errorCode);
		if (bytesWritten == 0)
		{
			return false;
		}

		ptr += bytesWritten;
		bytesLeft = (bytesLeft < bytesWritten) ? 0 : (bytesLeft - bytesWritten);  // unsigned protection.
	}
	return true;
}

bool ClientSocket::ConnectAndSend(const uint8_t* const toSend, const size_t size)
{
	if (!Connect())
	{
		return false;
	}
	if (!Send(toSend, size))
	{
		Close();
		return false;
	}

	Close();
	return true;
}

// dynamic allocate response size
uint8_t* ClientSocket::SendAndReceive(const uint8_t* const toSend, const size_t size)
{
	if (!Connect())
	{
		return nullptr;
	}
	if (!Send(toSend, size))
	{
		Close();
		return nullptr;
	}
	auto responseHeaderBytes = new uint8_t[sizeof(ResponseHeader)];
	if (!Receive(responseHeaderBytes, sizeof(ResponseHeader), sizeof(ResponseHeader)))
	{
		Close();
		return nullptr;
	}

	ResponseHeader* resHeader = (ResponseHeader*)responseHeaderBytes;
	auto payloadSize = resHeader->payloadSize;
	auto response = new uint8_t[sizeof(ResponseHeader) + payloadSize];
	std::copy(responseHeaderBytes, responseHeaderBytes + sizeof(ResponseHeader), response);
	delete[] responseHeaderBytes;
	if (!Receive(response + sizeof(ResponseHeader), payloadSize))
	{
		Close();
		return nullptr;
	}
	Close();
	return response;
}

uint8_t* ClientSocket::RetryableSendAndReceive(const uint8_t* const toSend, const size_t size, int retries, const std::string& errorDesc)
{
	uint8_t* response{};
	bool failed = false;
	int leftRetries = retries;
	do
	{
		leftRetries--;
		response = SendAndReceive(toSend, size);
		if (!response)
		{
			std::cerr << errorDesc << std::endl;
			failed = true;
		}
		else
		{
			failed = ClientLogic::IsGlobalError(*(ResponseHeader*)response);
		}
	} while (failed && leftRetries > 0);

	if (failed)
	{
		throw FatalException(errorDesc);
	}

	return response;
}




