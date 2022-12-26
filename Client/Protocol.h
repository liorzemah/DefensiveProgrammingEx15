#pragma once
#include <cstdint>
#include <ostream>
#include <iomanip>
#include <sstream>

constexpr int DEFAULT_INT_VAL = 0; // Default value for integers fields in Requests and Responses

 // Common types
typedef uint32_t messageID_t;

// Constants 
constexpr uint8_t CLIENT_VERSION = 3;
constexpr size_t CLIENT_ID_SIZE = 16;
constexpr size_t NAME_SIZE = 255;
constexpr size_t PUBLIC_KEY_SIZE = 160;
constexpr size_t AES_KEY_SIZE = 16;   
constexpr size_t REQUEST_OPTIONS = 5;
constexpr size_t RESPONSE_OPTIONS = 6;

enum RequestCode
{
	REQUEST_REGISTRATION   = 1100,  
	REQUEST_SEND_PUBLIC_KEY = 1101,   
	REQUEST_RECONNECT = 1002,   
	REQUEST_SEND_FILE = 1003,
	REQUEST_VALID_CRC = 1004,
	REQUEST_INVALID_CRC_RETRY = 1005,   
	REQUEST_INVALID_CRC_FINISH = 1006
};

enum ResponseCode
{
	RESPONSE_REGISTRATION_SUCCEEDED = 2100,
	RESPONSE_REGISTRATION_FAILED = 2101,
	RESPONSE_AES_KEY = 2102,
	RESPONSE_VALID_CRC = 2103,
	RESPONSE_MSG_RECEIVED = 2104,
	RESPONSE_RECONNECT_ALLOWED = 2105,
	RESPONSE_RECONNECT_REJECTED = 2106,
	RESPONSE_GLOBAL_ERROR = 2107,
};

#pragma pack(push, 1)

struct ClientID
{
	uint8_t uuid[CLIENT_ID_SIZE];
	ClientID() : uuid{ DEFAULT_INT_VAL } {}

	bool operator==(const ClientID& otherID) const 
	{
		for (size_t i = 0; i < CLIENT_ID_SIZE; ++i)
			if (uuid[i] != otherID.uuid[i])
				return false;
		return true;
	}
	
	bool operator!=(const ClientID& otherID) const 
	{
		return !(*this == otherID);
	}

	friend std::ostream& operator<<(std::ostream& os, const ClientID& clientID)
	{
		char tmp[3] = {'\0'};
		for (const auto octet : clientID.uuid)
		{
			sprintf_s(tmp, "%02X", octet);
			os << tmp;
		}
		return os;
	}
};

struct ClientName
{
	uint8_t name[NAME_SIZE];
	ClientName() : name{ '\0' } {}
	friend std::ostream& operator<<(std::ostream& os, const ClientName& clientName)
	{
		os << reinterpret_cast<const char*>(clientName.name);
		return os;
	}

	std::string ToString() { return reinterpret_cast<const char*>(name); }
};

struct FileName
{
	uint8_t name[NAME_SIZE];
	FileName() : name{ '\0' } {}
	friend std::ostream& operator<<(std::ostream& os, const FileName& fileName)
	{
		os << reinterpret_cast<const char*>(fileName.name);
		return os;
	}

	std::string ToString() { return reinterpret_cast<const char*>(name);}
};

struct PublicKey
{
	uint8_t publicKey[PUBLIC_KEY_SIZE];
	PublicKey() : publicKey{ DEFAULT_INT_VAL } {}
};

struct AesKey
{
	uint8_t aesKey[AES_KEY_SIZE];
	AesKey() : aesKey{ DEFAULT_INT_VAL } {}
};

struct RequestHeader
{
	ClientID clientId;
	const uint8_t version;
	const uint16_t code;
	uint32_t payloadSize;
	RequestHeader(const uint16_t reqCode) : version(CLIENT_VERSION), code(reqCode), payloadSize(DEFAULT_INT_VAL) {}
	RequestHeader(const ClientID& id, const uint16_t reqCode) : clientId(id), version(CLIENT_VERSION), code(reqCode), payloadSize(DEFAULT_INT_VAL) {}
};

struct ResponseHeader
{
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
	ResponseHeader() : version(DEFAULT_INT_VAL), code(DEFAULT_INT_VAL), payloadSize(DEFAULT_INT_VAL) {}
};

struct RequestRegistration
{
	RequestHeader header;
	ClientName clientName;
	RequestRegistration() : header(REQUEST_REGISTRATION) 
	{
		header.payloadSize = sizeof(ClientName);
	}
};

struct RequestReconnect
{
	RequestHeader header;
	ClientName clientName;
	RequestReconnect(const ClientID& id) : header(id, REQUEST_RECONNECT)
	{
		header.payloadSize = sizeof(ClientName);
	}
};

struct RequestValidCrc
{
	RequestHeader header;
	FileName fileName;
	RequestValidCrc(const ClientID& id) : header(id, REQUEST_VALID_CRC)
	{
		header.payloadSize = sizeof(FileName);
	}
};

struct RequestInvalidCrc
{
	RequestHeader header;
	FileName fileName;
	RequestInvalidCrc(const ClientID& id) : header(id, REQUEST_INVALID_CRC_RETRY)
	{
		header.payloadSize = sizeof(FileName);
	}
};

struct RequestInvalidCrcFinish
{
	RequestHeader header;
	FileName fileName;
	RequestInvalidCrcFinish(const ClientID& id) : header(id, REQUEST_INVALID_CRC_FINISH)
	{
		header.payloadSize = sizeof(FileName);
	}
};
struct RequestPublicKey
{
	RequestHeader header;
	struct
	{
		ClientName clientName;
		PublicKey clientPublicKey;
	}payload;
	
	RequestPublicKey(const ClientID& id) : header(id, REQUEST_SEND_PUBLIC_KEY)
	{
		header.payloadSize = sizeof(payload);
	}
};

/* struct for response that contains only client id in the payload such as:
	RESPONSE_MSG_RECEIVED = 2104
	RESPONSE_RECONNECT_ALLOWED = 2105 (the dynamic field of symmtric key handled outside the struct)
	RESPONSE_RECONNECT_REJECTED = 2106
*/
struct ResponseWithClientID
{
	ResponseHeader header;
	ClientID clientId;
};

struct ResponseRegistrationFailed
{
	ResponseHeader header;
};

/* need after serialization add content bytes to the end and update payloadSize */
struct RequestSendFileWithoutContent
{
	RequestHeader header;
	struct
	{
		int contentSize;
		FileName fileName;

	}payload;

	RequestSendFileWithoutContent(const ClientID& id) : header(id, REQUEST_SEND_FILE)
	{
		header.payloadSize = sizeof(payload);
	}
};

struct ResponseValidCrc
{
	ResponseHeader header;
	struct
	{
		ClientID clientId;
		uint32_t contentSize;
		FileName filename;
		uint32_t crc;
	}payload;
};

#pragma pack(pop)
