#include "ClientLogic.h"
#include "FatalError.h"
#include <iostream>
#include "ClientSocket.h"
#include "Base64.h"


bool ClientLogic::IsGlobalError(const ResponseHeader& header)
{
	if (header.code == RESPONSE_GLOBAL_ERROR)
	{
		std::cerr << "server responded with an error" << std::endl;
		return true;
	}

	return false;
}

bool ClientLogic::ValidateResponse(const ResponseHeader& header, const ResponseCode expectedCode)
{
	if (IsGlobalError(header))
	{
		return false;
	}

	if (header.version != CLIENT_VERSION)
	{
		throw FatalException("Received unsupported client version " + std::to_string(header.version) + ", expected to " + std::to_string(CLIENT_VERSION));
	}

	if (header.code != expectedCode)
	{
		throw FatalException("Unexpected response code received " + std::to_string(header.code) + " but expected to " + std::to_string(expectedCode));
	}

	uint32_t expectedSize = DEFAULT_INT_VAL;
	switch (header.code)
	{
	case RESPONSE_REGISTRATION_SUCCEEDED:
	{
		expectedSize = sizeof(ResponseWithClientID) - sizeof(ResponseHeader);
		break;
	}
	case RESPONSE_REGISTRATION_FAILED:
	{
		expectedSize = sizeof(ResponseRegistrationFailed) - sizeof(ResponseHeader);
		break;
	}
	case RESPONSE_VALID_CRC:
	{
		expectedSize = sizeof(ResponseValidCrc) - sizeof(ResponseHeader);
		break;
	}
	case RESPONSE_MSG_RECEIVED:
	case RESPONSE_RECONNECT_REJECTED:
	{
		expectedSize = sizeof(ResponseWithClientID) - sizeof(ResponseHeader);
		break;
	}
	case RESPONSE_AES_KEY:
	case RESPONSE_RECONNECT_ALLOWED:
	default:
	{
		return true; 
	}
	}

	if (header.payloadSize != expectedSize)
	{
		throw FatalException("Unexpected payload size " + std::to_string(header.payloadSize) + " but expected to " + std::to_string(expectedSize));
	}
	return true;
}

// Send register request and update clientID if the registration success, return status true if success else false
bool ClientLogic::Register(const ClientName& clientName, const std::string& ip, int port, ClientID& clientID)
{
	RequestRegistration request;
	request.clientName = clientName;
	ClientSocket socket(ip, std::to_string(port));
	const auto response = socket.RetryableSendAndReceive((uint8_t*)(&request), sizeof(RequestRegistration), 3, "Failed to send registration request to server");
	ResponseHeader* resHeader = (ResponseHeader*)response;
	if (resHeader->code == RESPONSE_REGISTRATION_SUCCEEDED)
	{
		if (ClientLogic::ValidateResponse(*(ResponseHeader*)(response), RESPONSE_REGISTRATION_SUCCEEDED))
		{
			ResponseWithClientID* reg = (ResponseWithClientID*)(response);
			clientID = reg->clientId;
			delete[] response;
			return true;
		}
	}
	else //RESPONSE_REGISTRATION_FAILED
	{
		if (ClientLogic::ValidateResponse(*(ResponseHeader*)(response), RESPONSE_REGISTRATION_FAILED))
		{
			std::cerr << "Failed to register, client name already in exists" << std::endl;
		}
	}

	delete[] response;
	return false;
}

std::shared_ptr<AESWrapper> ClientLogic::ExtractAesFromResponse(const std::shared_ptr<MeInfo>& meInfo, uint8_t* response, ResponseCode excpectedCode)
{
	ResponseHeader* resHeader = (ResponseHeader*)response;
	if (!ClientLogic::ValidateResponse(*resHeader, excpectedCode))
	{
		return nullptr;
	}

	uint8_t* encryptedAesKey = response + sizeof(ResponseHeader) + CLIENT_ID_SIZE;
	std::cout << "encrypted aes: " << Base64::Encode(encryptedAesKey, resHeader->payloadSize - CLIENT_ID_SIZE) << std::endl;
	const auto rsa = meInfo->GetRsaObject();
	const auto aes = rsa->decrypt(encryptedAesKey, resHeader->payloadSize - CLIENT_ID_SIZE);
	std::cout << "aes key: " << Base64::Encode(aes) << std::endl;

	return std::make_shared<AESWrapper>(reinterpret_cast<const uint8_t*>(aes.c_str()), aes.size());
}

/* return AES symmatric key */
std::shared_ptr<AESWrapper> ClientLogic::SendPublicKey(const std::shared_ptr<MeInfo>& meInfo, const std::string& ip, int port)
{
	RequestPublicKey request(meInfo->GetClientID());
	request.payload.clientName = meInfo->GetClientName();
	auto publicKey = meInfo->GetRsaPublicKey();
	std::copy(publicKey.begin(), publicKey.end(), std::begin(request.payload.clientPublicKey.publicKey));

	ClientSocket socket(ip, port);
	const auto response = socket.RetryableSendAndReceive((uint8_t*)(&request), sizeof(RequestPublicKey), 3, "Failed to send request public key to server");
	if (response == nullptr)
	{
		return nullptr;
	}

	const auto aesWrapper = ExtractAesFromResponse(meInfo, response, RESPONSE_AES_KEY);
	delete[] response;
	return aesWrapper;
}

/* Return crc that receviced from the server */
uint32_t ClientLogic::SendFileContent(const std::shared_ptr<MeInfo>& meInfo, const std::string& ip, int port, const FileName& filename, const std::string& content)
{
	RequestSendFileWithoutContent request(meInfo->GetClientID());
	std::copy(filename.name, filename.name + NAME_SIZE, std::begin(request.payload.fileName.name));
	request.payload.contentSize = content.size();
	request.header.payloadSize += content.size();

	int totalSize = sizeof(RequestHeader) + request.header.payloadSize;

	// copy all bytes from the request without the file content bytes
	uint8_t* requestBytes = new uint8_t[totalSize];
	std::copy((uint8_t*)(&request), (uint8_t*)(&request) + totalSize - content.size(), requestBytes);

	// add the content bytes to the end
	std::copy(content.begin(), content.end(), requestBytes + totalSize - content.size());
	std::cout << "request size : " << totalSize << std::endl;
	std::cout << "request in base64: " << Base64::Encode(requestBytes, totalSize) << std::endl;
	ClientSocket socket(ip, port);
	const auto response = socket.RetryableSendAndReceive(requestBytes, totalSize, 3, "Failed to send request send file to server");
	delete[] requestBytes;

	if (response == nullptr)
	{
		return 0;
	}

	uint32_t crc = 0;
	ResponseHeader* resHeader = (ResponseHeader*)response;
	if (resHeader->code == RESPONSE_VALID_CRC)
	{
		if (ClientLogic::ValidateResponse(*(ResponseHeader*)(response), RESPONSE_VALID_CRC))
		{
			ResponseValidCrc* validCrc = (ResponseValidCrc*)(response);
			crc = validCrc->payload.crc;
		}
	}

	delete[] response;
	return 0;
}

std::shared_ptr<AESWrapper> ClientLogic::SendReconnect(const std::shared_ptr<MeInfo>& meInfo, const std::string& ip, int port)
{
	RequestReconnect request(meInfo->GetClientID());
	const auto clientName = meInfo->GetClientName();
	std::copy(clientName.name, clientName.name + NAME_SIZE, std::begin(request.clientName.name));

	ClientSocket socket(ip, port);
	const auto response = socket.RetryableSendAndReceive((uint8_t*)&request, sizeof(RequestReconnect), 3, "Failed to send reconnect to server");
	ResponseHeader* resHeader = (ResponseHeader*)response;
	if (resHeader->code == RESPONSE_RECONNECT_REJECTED)
	{
		if (ClientLogic::ValidateResponse(*(ResponseHeader*)(response), RESPONSE_RECONNECT_REJECTED))
		{
			delete[] response;
			return nullptr;
		}
	}
	else if (resHeader->code == RESPONSE_RECONNECT_ALLOWED)
	{
		const auto aesWrapper = ExtractAesFromResponse(meInfo, response, RESPONSE_RECONNECT_ALLOWED);
		delete[] response;
		return aesWrapper;
	}

	throw FatalException("Received unexpected response code " + std::to_string(resHeader->code));
}

