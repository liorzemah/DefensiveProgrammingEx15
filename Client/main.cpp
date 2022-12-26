#include "protocol.h"
#include <fstream>
#include <array>
#include "MeInfo.hpp"
#include <iostream>
#include "ClientSocket.h"
#include "RSAWrapper.h"
#include "ClientLogic.h"
#include "AESWrapper.h"
#include <boost/crc.hpp>
#include "Base64.h"
#include "FatalError.h"
#include <modes.h>
#include <aes.h>

static const std::string TRANSFER_FILE = "transfer.info";

void ReadTransferInfo(std::string& ip, int& port, ClientName& clientName, FileName& filePath)
{
	constexpr static auto MAX_CLIENT_NAME_IN_FILE = 100;

	std::ifstream infile(TRANSFER_FILE);
	if (!infile.is_open())
	{
		throw std::invalid_argument("File me.info not exists");
	}
	std::array<std::string, 3> lines;
	std::string line;
	int i = 0;
	while (i < 3 && std::getline(infile, line))
	{
		lines[i++] = line;
	}

	if (i < 3)
	{
		throw std::invalid_argument(TRANSFER_FILE + " contains less than 3 lines");
	}

	const auto dots = lines[0].find(":");
	ip = lines[0].substr(0, dots);
	port = std::stoi(lines[0].substr(dots + 1, lines[0].size()));
	if (lines[1].size() > MAX_CLIENT_NAME_IN_FILE)
	{
		throw std::invalid_argument("The second line should contains client name that will be with max of " + std::to_string(MAX_CLIENT_NAME_IN_FILE) + " letters, the name contains " + std::to_string(lines[1].size()) + " letters");
	}
	std::copy(lines[1].begin(), lines[1].end(), std::begin(clientName.name));
	if (lines[2].size() > NAME_SIZE)
	{
		throw std::invalid_argument("The third line should contains file path that will be with max of " + std::to_string(NAME_SIZE) + " letters, the path contains " + std::to_string(lines[1].size()) + " letters");
	}
	std::copy(lines[2].begin(), lines[2].end(), std::begin(filePath.name));
}

uint32_t GetCrc32(const std::string& str)
{
	boost::crc_32_type result;
	result.process_bytes(str.c_str(), str.size());
	return result.checksum();
}


int main(int argc, char* argv[])
{
	ClientName clientName;
	FileName filePath;
	std::string ip;
	int port{};

	try
	{
		// Read Tranfer info for get ip and port, client name and file path, using client name only if me.info file not exists
		ReadTransferInfo(ip, port, clientName, filePath);
		std::cout << "Server ip: " << ip << std::endl;
		std::cout << "Server port: " << port << std::endl;
		std::cout << "Client name: " << clientName << std::endl;
		std::cout << "File path: " << filePath << std::endl;
	}
	catch (std::exception& e)
	{
		std::cerr << "Can't read " << TRANSFER_FILE << ", error details: " << e.what() << std::endl;
		return 0;
	}

	try
	{
		ClientSocket socket(ip, std::to_string(port));
		std::shared_ptr<MeInfo> meInfo;
		std::shared_ptr<AESWrapper> aesWrapper;
		try
		{
			meInfo = std::make_shared<MeInfo>();
			aesWrapper = ClientLogic::SendReconnect(meInfo, ip, port);
			if (aesWrapper == nullptr)
			{
				std::cout << "Tried reconnect to unexists client name, restart as new client. program exited" << std::endl;
				return 0;
			}
			std::cout << meInfo->GetClientName().ToString() << " reconnected." << std::endl;
		}
		catch (const FatalException& e)
		{
			throw e;
		}
		catch (const std::exception& e)
		{
			std::cout << e.what() << std::endl;
			ClientID clientID;

			if (!ClientLogic::Register(clientName, ip, port, clientID))
			{
				return 0;
			}

			meInfo = std::make_shared<MeInfo>(clientName, clientID);

			// Our client has been registered, send public key
			aesWrapper = ClientLogic::SendPublicKey(meInfo, ip, port);
			if (aesWrapper == nullptr)
			{
				return 0;
			}
		}

		// read file content
		std::ifstream infile(filePath.ToString());
		if (!infile.is_open())
		{
			throw std::invalid_argument("File " + filePath.ToString() + " not exists");
		}

		std::string content;
		std::string line;
		while (std::getline(infile, line))
		{
			content += line + "\n";
		}

		std::cout << filePath.ToString() << " content: " << content << std::endl;

		// Calculate crc from the content
		const auto fileCRC = GetCrc32(content);

		std::cout << "content size: " << content.size() << std::endl;
		std::cout << "content in base 64: " << Base64::Encode(content) << std::endl;

		// encrypt content with AES
		const auto encryptedContent = aesWrapper->Encrypt(content);

		std::cout << "encrypted content size: " << encryptedContent.size() << std::endl;
		std::cout << "encrypted content in base 64: " << Base64::Encode(encryptedContent) << std::endl;
		std::cout << "encrypted content in base 64: " << encryptedContent << std::endl;


		constexpr static int MAX_RETRIES = 3;
		bool accept = false;
		int tryIndex = 1;
		while (!accept && tryIndex <= MAX_RETRIES)
		{
			// Send encrypted content to the server and get crc 
			const auto serverCrc = ClientLogic::SendFileContent(meInfo, ip, port, filePath, encryptedContent);
			std::cout << "Recieved crc from server: " << serverCrc << ", original crc: " << fileCRC << std::endl;
			// Compare our crc vs server crc
			if (serverCrc == fileCRC)
			{
				RequestValidCrc reqValidCrc(meInfo->GetClientID());
				reqValidCrc.fileName = filePath;
				const auto response = socket.SendAndReceive((uint8_t*)(&reqValidCrc), sizeof(RequestValidCrc));
				if (response == nullptr)
				{
					return 0;
				}

				ResponseHeader* resHeader = (ResponseHeader*)response;
				if (resHeader->code == RESPONSE_MSG_RECEIVED)
				{
					if (ClientLogic::ValidateResponse(*(ResponseHeader*)(response), RESPONSE_MSG_RECEIVED))
					{
						ResponseWithClientID* resWithClient = (ResponseWithClientID*)(response);
						std::cout << "Finish communication with server" << std::endl;
						return 0;
					}
				}
				accept = true;
			}
			else
			{
				std::cerr << "Received invalid CRC, this is the " << tryIndex << " attemp, try to send file again" << std::endl;

				// resend file again up to 3 times
				RequestInvalidCrc reqinvalidCrc(meInfo->GetClientID());
				reqinvalidCrc.fileName = filePath;
				const auto status = socket.ConnectAndSend((uint8_t*)(&reqinvalidCrc), sizeof(RequestInvalidCrc));
			}

			++tryIndex;
		}


		std::cerr << "Fatal: Received invalid CRC in the fourth time" << std::endl;
		// Send invalid crc with finish 
		RequestInvalidCrcFinish reqinvalidCrcFinish(meInfo->GetClientID());
		reqinvalidCrcFinish.fileName = filePath;
		const auto response = socket.SendAndReceive((uint8_t*)(&reqinvalidCrcFinish), sizeof(RequestInvalidCrcFinish));
		if (response == nullptr)
		{
			return 0;
		}

		ResponseHeader* resHeader = (ResponseHeader*)response;
		if (resHeader->code == RESPONSE_MSG_RECEIVED)
		{
			if (ClientLogic::ValidateResponse(*(ResponseHeader*)(response), RESPONSE_MSG_RECEIVED))
			{
				ResponseWithClientID* resWithClient = (ResponseWithClientID*)(response);
				std::cout << "Finish communication with server" << std::endl;
			}
		}

	}
	catch (const FatalException& e)
	{
		std::cerr << "Fatal Error: " << e.what() << ". program exited" << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << ". program exited" << std::endl;
	}

	system("pause");
	return 0;
}

