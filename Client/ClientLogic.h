#pragma once
#include "Protocol.h"
#include "AESWrapper.h"
#include "MeInfo.hpp"

// Client logical functional, each method send request and extract data from server response
class ClientLogic
{
	ClientLogic() = delete;
public:
	static bool IsGlobalError(const ResponseHeader& header);
	static bool ValidateResponse(const ResponseHeader& header, const ResponseCode expectedCode);
	static bool Register(const ClientName& clientName, const std::string& ip, int port, ClientID& clientID);
	static std::shared_ptr<AESWrapper> ExtractAesFromResponse(const std::shared_ptr<MeInfo>& meInfo, uint8_t* response, ResponseCode excpectedCode);
	static std::shared_ptr<AESWrapper> SendPublicKey(const std::shared_ptr<MeInfo>& meInfo, const std::string& ip, int port);
	static uint32_t SendFileContent(const std::shared_ptr<MeInfo>& meInfo, const std::string& ip, int port, const FileName& filename, const std::string& content);
	static std::shared_ptr<AESWrapper> SendReconnect(const std::shared_ptr<MeInfo>& meInfo, const std::string& ip, int port);
};

