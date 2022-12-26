///**
// * MessageU Client
// * @file CClientLogic.cpp
// * @brief The core logic of Client.
// * CClientLogic received commands from CClientMenu and invokes internal logic such as CFileHandler, CSocketHandler.
// * @author Roman Koifman
// * https://github.com/Romansko/MessageU/blob/main/client/src/CClientLogic.cpp
// */
//#include "CClientLogic.h"
//#include "CStringer.h"
//#include "RSAWrapper.h"
//#include "AESWrapper.h"
//#include "CFileHandler.h"
//#include "ClientSocket.h"
//
//std::ostream& operator<<(std::ostream& os, const EMessageType& type)
//{
//	os << static_cast<uint8_t>(type);
//	return os;
//}
//
//CClientLogic::CClientLogic() : _fileHandler(nullptr), _rsaDecryptor(nullptr)
//{
//	_fileHandler = new CFileHandler();
//}
//
//CClientLogic::~CClientLogic()
//{
//	delete _fileHandler;
//	delete _rsaDecryptor;
//}
//
///**
// * Parse SERVER_INFO file for server address & port.
// */
//bool CClientLogic::parseServeInfo()
//{
//	std::stringstream err;
//	if (!_fileHandler->open(SERVER_INFO))
//	{
//		clearLastError();
//		_lastError << "Couldn't open " << SERVER_INFO;
//		return false;
//	}
//	std::string info;
//	if (!_fileHandler->readLine(info))
//	{
//		clearLastError();
//		_lastError << "Couldn't read " << SERVER_INFO;
//		return false;
//	}
//	_fileHandler->close();
//	CStringer::trim(info);
//	const auto pos = info.find(':');
//	if (pos == std::string::npos)
//	{
//		clearLastError();
//		_lastError << SERVER_INFO << " has invalid format! missing separator ':'";
//		return false;
//	}
//	m_address = info.substr(0, pos);
//	m_port = info.substr(pos + 1);
//	return true;
//}
//
///**
// * Parse CLIENT_INFO file.
// */
//bool CClientLogic::parseClientInfo()
//{
//	std::string line;
//	if (!_fileHandler->open(CLIENT_INFO))
//	{
//		clearLastError();
//		_lastError << "Couldn't open " << CLIENT_INFO;
//		return false;
//	}
//
//	// Read & Parse username
//	if (!_fileHandler->readLine(line))
//	{
//		clearLastError();
//		_lastError << "Couldn't read username from " << CLIENT_INFO;
//		return false;
//	}
//	CStringer::trim(line);
//	if (line.length() >= CLIENT_NAME_SIZE)
//	{
//		clearLastError();
//		_lastError << "Invalid username read from " << CLIENT_INFO;
//		return false;
//	}
//	_self.username = line;
//
//	// Read & Parse Client's UUID.
//	if (!_fileHandler->readLine(line))
//	{
//		clearLastError();
//		_lastError << "Couldn't read client's UUID from " << CLIENT_INFO;
//		return false;
//	}
//
//	line = CStringer::unhex(line);
//	const char* unhexed = line.c_str();
//	if (strlen(unhexed) != sizeof(_self.id.uuid))
//	{
//		memset(_self.id.uuid, 0, sizeof(_self.id.uuid));
//		clearLastError();
//		_lastError << "Couldn't parse client's UUID from " << CLIENT_INFO;
//		return false;
//	}
//	memcpy(_self.id.uuid, unhexed, sizeof(_self.id.uuid));
//
//	// Read & Parse Client's private key.
//	std::string decodedKey;
//	while (_fileHandler->readLine(line))
//	{
//		decodedKey.append(CStringer::decodeBase64(line));
//	}
//	if (decodedKey.empty())
//	{
//		clearLastError();
//		_lastError << "Couldn't read client's private key from " << CLIENT_INFO;
//		return false;
//	}
//	try
//	{
//		delete _rsaDecryptor;
//		_rsaDecryptor = new RSAPrivateWrapper(decodedKey);
//	}
//	catch(...)
//	{
//		clearLastError();
//		_lastError << "Couldn't parse private key from " << CLIENT_INFO;
//		return false;
//	}
//	_fileHandler->close();
//	return true;
//}
//
//
///**
// * Copy usernames into vector & sort them alphabetically.
// * If _clients is empty, an empty vector will be returned.
// */
//std::vector<std::string> CClientLogic::getUsernames() const
//{
//	std::vector<std::string> usernames(_clients.size());
//	std::transform(_clients.begin(), _clients.end(), usernames.begin(),
//		[](const SClient& client) { return client.username; });
//	std::sort(usernames.begin(), usernames.end());
//	return usernames;
//}
//
///**
// * Reset _lastError StringStream: Empty string, clear errors flag and reset formatting.
// */
//void CClientLogic::clearLastError()
//{
//	const std::stringstream clean;
//	_lastError.str("");
//	_lastError.clear();
//	_lastError.copyfmt(clean);
//}
//
///**
// * Store client info to CLIENT_INFO file.
// */
//bool CClientLogic::storeClientInfo()
//{
//	if (!_fileHandler->open(CLIENT_INFO, true))
//	{
//		clearLastError();
//		_lastError << "Couldn't open " << CLIENT_INFO;
//		return false;
//	}
//
//	// Write username
//	if (!_fileHandler->writeLine(_self.username))
//	{
//		clearLastError();
//		_lastError << "Couldn't write username to " << CLIENT_INFO;
//		return false;
//	}
//
//	// Write UUID.
//	const auto hexifiedUUID = CStringer::hex(_self.id.uuid, sizeof(_self.id.uuid));
//	if (!_fileHandler->writeLine(hexifiedUUID))
//	{
//		clearLastError();
//		_lastError << "Couldn't write UUID to " << CLIENT_INFO;
//		return false;
//	}
//
//	// Write Base64 encoded private key
//	const auto encodedKey = CStringer::encodeBase64(_rsaDecryptor->getPrivateKey());
//	if (!_fileHandler->write(reinterpret_cast<const uint8_t*>(encodedKey.c_str()), encodedKey.size()))
//	{
//		clearLastError();
//		_lastError << "Couldn't write client's private key to " << CLIENT_INFO;
//		return false;
//	}
//
//	_fileHandler->close();
//	return true;
//}
//
///**
// * Validate SResponseHeader upon an expected EResponseCode.
// */
//bool CClientLogic::validateHeader(const SResponseHeader& header, const ResponseCode expectedCode)
//{
//	if (header.code == RESPONSE_ERROR)
//	{
//		clearLastError();
//		_lastError << "Generic error response code (" << RESPONSE_ERROR << ") received.";
//		return false;
//	}
//	
//	if (header.code != expectedCode)
//	{
//		clearLastError();
//		_lastError << "Unexpected response code " << header.code << " received. Expected code was " << expectedCode;
//		return false;
//	}
//
//	uint32_t expectedSize = DEFAULT_INT_VAL;
//	switch (header.code)
//	{
//	case RESPONSE_REGISTRATION:
//	{
//		expectedSize = sizeof(SResponseRegistration) - sizeof(SResponseHeader);
//		break;
//	}
//	case RESPONSE_PUBLIC_KEY:
//	{
//		expectedSize = sizeof(SResponsePublicKey) - sizeof(SResponseHeader);
//		break;
//	}
//	case RESPONSE_MSG_SENT:
//	{
//		expectedSize = sizeof(SResponseMessageSent) - sizeof(SResponseHeader);
//		break;
//	}
//	default:
//	{
//		return true;  // variable payload size. 
//	}
//	}
//
//	if (header.payloadSize != expectedSize)
//	{
//		clearLastError();
//		_lastError << "Unexpected payload size " << header.payloadSize << ". Expected size was " << expectedSize;
//		return false;
//	}
//	
//	return true;
//}
//
///**
// * Receive unknown payload. Payload size is parsed from header.
// * Caller responsible for deleting payload upon success.
// */
//bool CClientLogic::receiveUnknownPayload(const uint8_t* const request, const size_t reqSize, const ResponseCode expectedCode, uint8_t*& payload, size_t& size)
//{
//	SResponseHeader response;
//	uint8_t buffer[PACKET_SIZE];
//	payload = nullptr;
//	size = 0;
//	if (request == nullptr || reqSize == 0)
//	{
//		clearLastError();
//		_lastError << "Invalid request was provided";
//		return false;
//	}
//	ClientSocket socket(m_address, m_port);
//	if (!socket.Connect())
//	{
//		clearLastError();
//		_lastError << "Failed connecting to server on " << socket;
//		return false;
//	}
//	if (!socket.Send(request, reqSize))
//	{
//		socket.Close();
//		clearLastError();
//		_lastError << "Failed sending request to server on " << socket;
//		return false;
//	}
//	if (!socket.Receive(buffer, sizeof(buffer)))
//	{
//		clearLastError();
//		_lastError << "Failed receiving response header from server on " << socket;
//		return false;
//	}
//	memcpy(&response, buffer, sizeof(SResponseHeader));
//	if (!validateHeader(response, expectedCode))
//	{
//		clearLastError();
//		_lastError << "Received unexpected response code from server on  " << socket;
//		return false;
//	}
//	if (response.payloadSize == 0)
//		return true;  // no payload. but not an error.
//
//	size = response.payloadSize;
//	payload = new uint8_t[size];
//	uint8_t* ptr = static_cast<uint8_t*>(buffer) + sizeof(SResponseHeader);
//	size_t recSize = sizeof(buffer) - sizeof(SResponseHeader);
//	if (recSize > size)
//		recSize = size;
//	memcpy(payload, ptr, recSize);
//	ptr = payload + recSize;
//	while(recSize < size)
//	{
//		size_t toRead = (size - recSize);
//		if (toRead > PACKET_SIZE)
//			toRead = PACKET_SIZE;
//		if (!socket.Receive(buffer, toRead))
//		{
//			clearLastError();
//			_lastError << "Failed receiving payload data from server on " << socket;
//			delete[] payload;
//			payload = nullptr;
//			size = 0;
//			return false;
//		}
//		memcpy(ptr, buffer, toRead);
//		recSize += toRead;
//		ptr += toRead;
//	}
//	
//	return true;
//}
//
///**
// * Store a client's public key on RAM.
// */
//bool CClientLogic::setClientPublicKey(const SClientID& clientID, const SPublicKey& publicKey)
//{
//	for (SClient& client : _clients)
//	{
//		if (client.id == clientID)
//		{
//			client.publicKey = publicKey;
//			client.publicKeySet = true;
//			return true;
//		}
//	}
//	return false;
//}
//
///**
// * Store a client's symmetric key on RAM.
// */
//bool CClientLogic::setClientSymmetricKey(const SClientID& clientID, const SSymmetricKey& symmetricKey)
//{
//	for (SClient& client : _clients)
//	{
//		if (client.id == clientID)
//		{
//			client.symmetricKey = symmetricKey;
//			client.symmetricKeySet = true;
//			return true;
//		}
//	}
//	return false;
//}
//
//
///**
// * Find a client using client ID.
// * Clients list must be retrieved first.
// */
//bool CClientLogic::getClient(const SClientID& clientID, SClient& client) const
//{
//	for (const SClient& itr : _clients)
//	{
//		if (itr.id == clientID)
//		{
//			client = itr;
//			return true;
//		}
//	}
//	return false;  // client invalid.
//}
//
///**
// * Find a client using username.
// * Clients list must be retrieved first.
// */
//bool CClientLogic::getClient(const std::string& username, SClient& client) const
//{
//	for (const SClient& itr : _clients)
//	{
//		if (username == itr.username)
//		{
//			client = itr;
//			return true;
//		}
//	}
//	return false; // client invalid.
//}
//
///**
// * Register client via the server.
// */
//bool CClientLogic::registerClient(const std::string& username)
//{
//	RequestRegistration request;
//	SResponseRegistration response;
//
//	if (username.length() >= CLIENT_NAME_SIZE)  // >= because of null termination.
//	{
//		clearLastError();
//		_lastError << "Invalid username length!";
//		return false;
//	}
//	for (auto ch : username)
//	{
//		if (!std::isalnum(ch))  // check that username is alphanumeric. [a-zA-Z0-9].
//		{
//			clearLastError();
//			_lastError << "Invalid username! Username may only contain letters and numbers!";
//			return false;
//		}
//	}
//
//	delete _rsaDecryptor;
//	_rsaDecryptor = new RSAPrivateWrapper();
//	const auto publicKey = _rsaDecryptor->getPublicKey();
//	if (publicKey.size() != PUBLIC_KEY_SIZE)
//	{
//		clearLastError();
//		_lastError << "Invalid public key length!";
//		return false;
//	}
//
//	// fill request data
//	request.header.payloadSize = sizeof(request.payload);
//	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), CLIENT_NAME_SIZE, username.c_str());
//	memcpy(request.payload.clientPublicKey.publicKey, publicKey.c_str(), sizeof(request.payload.clientPublicKey.publicKey));
//
//	try
//	{
//		ClientSocket socket(m_address, m_port);
//		if (!socket.SendAndReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
//			reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
//		{
//			clearLastError();
//			_lastError << "Failed send and recv data from server";
//			return false;
//		}
//	}
//	catch (const std::invalid_argument& e)
//	{
//		clearLastError();
//		_lastError << e.what() << ", check config file: " << SERVER_INFO;
//		return false;
//	}
//	catch (const std::exception& e)
//	{
//		clearLastError();
//		_lastError << e.what();
//		return false;
//	}
//
//	// parse and validate SResponseRegistration
//	if (!validateHeader(response.header, RESPONSE_REGISTRATION))
//		return false;  // error message updated within.
//
//	// store received client's ID
//	_self.id        = response.payload;
//	_self.username  = username;
//	_self.publicKey = request.payload.clientPublicKey;
//	if (!storeClientInfo())
//	{
//		clearLastError();
//		_lastError << "Failed writing client info to " << CLIENT_INFO << ". Please register again with different username.";
//		return false;
//	}
//
//	return true;
//}
//
///**
// * Invoke logic: request client list from server.
// */
//bool CClientLogic::requestClientsList()
//{
//	SRequestClientsList request(_self.id);
//	uint8_t* payload   = nullptr;
//	uint8_t* ptr       = nullptr;
//	size_t payloadSize = 0;
//	size_t parsedBytes = 0;
//	struct
//	{
//		SClientID   clientId;
//		SClientName clientName;
//	}client;
//	
//	if (!receiveUnknownPayload(reinterpret_cast<uint8_t*>(&request), sizeof(request), RESPONSE_USERS,payload, payloadSize))
//		return false;  // description was set within.
//	
//	if (payloadSize == 0)
//	{
//		delete[] payload;
//		clearLastError();
//		_lastError << "Server has no users registered. Empty Clients list.";
//		return false;
//	}
//	if (payloadSize % sizeof(client) != 0)
//	{
//		delete[] payload;
//		clearLastError();
//		_lastError << "Clients list received is corrupted! (Invalid size).";
//		return false;
//	}
//	ptr = payload;
//	_clients.clear();
//	while (parsedBytes < payloadSize)
//	{
//		memcpy(&client, ptr, sizeof(client));
//		ptr += sizeof(client);
//		parsedBytes += sizeof(client);
//		client.clientName.name[sizeof(client.clientName.name) - 1] = '\0'; // just in case..
//		_clients.push_back({ client.clientId, reinterpret_cast<char*>(client.clientName.name) });
//	}
//	delete[] payload;
//	return true;
//}
//
//
///**
// * Invoke logic: request client public key from server.
// */
//bool CClientLogic::requestClientPublicKey(const std::string& username)
//{
//	SRequestPublicKey  request(_self.id);
//	SResponsePublicKey response;
//	SClient            client;
//	
//	// self validation
//	if (username == _self.username)
//	{
//		clearLastError();
//		_lastError << username << ", your key is stored in the system already.";
//		return false;
//	}
//	
//	if (!getClient(username, client))
//	{
//		clearLastError();
//		_lastError << "username '" << username << "' doesn't exist. Please check your input or try to request users list again.";
//		return false;
//	}
//	request.payload = client.id;
//
//	ClientSocket socket(m_address, m_port);
//	if (!socket.SendAndReceive(reinterpret_cast<const uint8_t* const>(&request), sizeof(request),
//		reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
//	{
//		clearLastError();
//		_lastError << "Failed communicating with server on " << socket;
//		return false;
//	}
//
//	// parse and validate SResponseRegistration
//	if (!validateHeader(response.header, RESPONSE_PUBLIC_KEY))
//		return false;  // error message updated within.
//
//	if (request.payload != response.payload.clientId)
//	{
//		clearLastError();
//		_lastError << "Unexpected clientID was received.";
//		return false;
//	}
//
//	// Set public key.
//	if (!setClientPublicKey(response.payload.clientId, response.payload.clientPublicKey))
//	{
//		clearLastError();
//		_lastError << "Couldn't assign public key for user " << username << ". ClientID was not found. Please try retrieve users list again..";
//		return false;
//	}
//	return true;
//}
//
//
///**
// * Invoke logic: request pending messages from server.
// */
//bool CClientLogic::requestPendingMessages(std::vector<SMessage>& messages)
//{
//	SRequestMessages  request(_self.id);
//	uint8_t*          payload     = nullptr;
//	uint8_t*          ptr         = nullptr;
//	size_t            payloadSize = 0;
//	size_t            parsedBytes = 0;
//
//	messages.clear();
//	if (!receiveUnknownPayload(reinterpret_cast<uint8_t*>(&request), sizeof(request), RESPONSE_PENDING_MSG, payload, payloadSize))
//		return false;  // description was set within.
//
//	if (payloadSize == 0)
//	{
//		delete[] payload;
//		clearLastError();
//		_lastError << "There are no pending messages for you";
//		return false;
//	}
//	if (payload == nullptr || payloadSize < sizeof(SPendingMessage))
//	{
//		delete[] payload;
//		clearLastError();
//		_lastError << "Unexpected payload";
//		return false;
//	}
//
//	clearLastError();
//	ptr = payload;
//	while (parsedBytes < payloadSize)
//	{
//		SClient      client;
//		SMessage     message;
//		const size_t msgHeaderSize = sizeof(SPendingMessage);
//		const auto   header        = reinterpret_cast<SPendingMessage*>(ptr);
//		const size_t leftover      = payloadSize - parsedBytes;
//
//		/***
//		 * Split validation into two expressions in order to not violate memory access by header pointer.
//		 * This is a fatal error. This means the entire payload was not parsed correctly.
//		 * Report error as if the entire payload is corrupt.
//		 */ 
//		if ((msgHeaderSize > leftover) || (msgHeaderSize + header->messageSize) > leftover)
//		{
//			delete[] payload;
//			clearLastError();
//			_lastError << "Payload is corrupt and ignored. (Invalid Message Header length).";
//			return false;
//		}
//
//		
//		if (getClient(header->clientId, client))
//		{
//			message.username = client.username;
//		}
//		else
//		{
//			// unknown clientID. yet allow receiving messages from unknown clients.
//			message.username = "Unknown client ID: ";
//			message.username.append(CStringer::hex(header->clientId.uuid, sizeof(header->clientId.uuid)));
//		}
//
//		ptr         += msgHeaderSize;
//		parsedBytes += msgHeaderSize;
//		
//		switch (header->messageType)
//		{
//		case MSG_SYMMETRIC_KEY_REQUEST:
//		{
//			// Message content size should be 0. There is no special parsing logic
//			message.content = "Request for symmetric key.";
//			messages.push_back(message);
//			break;
//		}
//		case MSG_SYMMETRIC_KEY_SEND:
//		{				
//			if (header->messageSize == 0)  // invalid symmetric key
//			{
//				_lastError << "\tMessage ID #" << header->messageId << ": ";
//				_lastError << "Can't decrypt symmetric key. Content length is " << header->messageSize << "." << std::endl;
//				parsedBytes += header->messageSize;
//				ptr         += header->messageSize;
//				continue;
//			}
//
//			std::string key;
//			try
//			{
//				key = _rsaDecryptor->decrypt(ptr, header->messageSize);
//			}
//			catch(...)
//			{
//				_lastError << "\tMessage ID #" << header->messageId << ": ";
//				_lastError << "Can't decrypt symmetric key." << std::endl;
//				parsedBytes += header->messageSize;
//				ptr         += header->messageSize;
//				continue;
//			}
//				
//			const size_t keySize = key.size();
//			if (keySize != SYMMETRIC_KEY_SIZE)  // invalid symmetric key
//			{
//				_lastError << "\tMessage ID #" << header->messageId << ": ";
//				_lastError << "Invalid symmetric key size (" << keySize << ")." << std::endl;
//			}
//			else
//			{
//				memcpy(client.symmetricKey.symmetricKey, key.c_str(), keySize);
//				if (setClientSymmetricKey(header->clientId, client.symmetricKey))
//				{
//					message.content = "symmetric key received";
//					messages.push_back(message);
//				}
//				else
//				{
//					_lastError << "\tMessage ID #" << header->messageId << ": ";
//					_lastError << "Couldn't set symmetric key of user: " << message.username << std::endl;
//				}
//			}
//			parsedBytes += header->messageSize;
//			ptr         += header->messageSize;
//			break;
//		}
//		case MSG_TEXT:
//		case MSG_FILE:
//		{
//			if (header->messageSize == 0)
//			{
//				_lastError << "\tMessage ID #" << header->messageId << ": ";
//				_lastError << "Message with no content provided." << std::endl;
//				parsedBytes += header->messageSize;
//				ptr += header->messageSize;
//				continue;
//			}
//			message.content = "can't decrypt message"; // assume failure
//			bool push = true;  // push to msg queue
//			if (client.symmetricKeySet)
//			{
//				AESWrapper aes(client.symmetricKey.symmetricKey, sizeof(client.symmetricKey.symmetricKey));
//				std::string data;
//				try
//				{
//					data = aes.Decrypt(ptr, header->messageSize);
//				}
//				catch (...) {}  // do nothing. failure already assumed.
//				if (header->messageType == MSG_FILE)
//				{
//					// Set filename with timestamp.
//					std::stringstream filepath;
//					filepath << _fileHandler->getTempFolder() << "\\MessageU\\" << message.username << "_" << CStringer::getTimestamp();
//					message.content = filepath.str();
//					if (!_fileHandler->writeAtOnce(message.content, data))
//					{
//						_lastError << "\tMessage ID #" << header->messageId << ": ";
//						_lastError << "Failed to save file on disk." << std::endl;
//						push = false;
//					}
//				}
//				else  // MSG_TEXT
//				{
//					message.content = data;
//				}
//			}
//			if (push)
//				messages.push_back(message);
//			parsedBytes += header->messageSize;
//			ptr         += header->messageSize;
//			break;
//		}
//		default:
//		{
//			message.content = ""; // Corrupted message. Don't store.
//			break;
//		}
//		}
//
//	}
//	delete[] payload;
//
//	return true;
//}
//
///**
// * Send a message to another client via the server.
// */
//bool CClientLogic::sendMessage(const std::string& username, const EMessageType type, const std::string& data)
//{
//	SClient              client; // client to send to
//	SRequestSendMessage  request(_self.id, (type));
//	SResponseMessageSent response;
//	uint8_t*             content = nullptr;
//	std::map<const EMessageType, const std::string> descriptions = {
//		{MSG_SYMMETRIC_KEY_REQUEST, "symmetric key request"},
//		{MSG_SYMMETRIC_KEY_SEND,    "symmetric key"},
//		{MSG_TEXT,                  "text message"},
//		{MSG_FILE,                  "file"}
//	};
//	
//	// self validation.
//	if (username == _self.username)
//	{
//		clearLastError();
//		_lastError << username << ", you can't send a " << descriptions[type] << " to yourself..";
//		return false;
//	}
//	
//	if (!getClient(username, client))
//	{
//		clearLastError();
//		_lastError << "username '" << username << "' doesn't exist. Please check your input or try to request users list again.";
//		return false;
//	}
//	request.payloadHeader.clientId = client.id;
//
//	if (type == MSG_SYMMETRIC_KEY_SEND)
//	{
//		if (!client.publicKeySet)
//		{
//			clearLastError();
//			_lastError << "Couldn't find " << client.username << "'s public key.";
//			return false;
//		}
//		SSymmetricKey symKey;
//		AESWrapper::GenerateKey(symKey.symmetricKey, sizeof(symKey.symmetricKey));
//		AESWrapper aes(symKey.symmetricKey, sizeof(symKey.symmetricKey));
//		if (!setClientSymmetricKey(request.payloadHeader.clientId, symKey))
//		{
//			clearLastError();
//			_lastError << "Failed storing symmetric key of clientID "
//				<< CStringer::hex(request.payloadHeader.clientId.uuid, sizeof(request.payloadHeader.clientId.uuid))
//				<< ". Please try to request clients list again..";
//			return false;
//		}
//
//		RSAPublicWrapper rsa(client.publicKey);
//		const std::string encryptedKey = rsa.encrypt(symKey.symmetricKey, sizeof(symKey.symmetricKey));
//		request.payloadHeader.contentSize = encryptedKey.size();  // 128
//		content = new uint8_t[request.payloadHeader.contentSize];
//		memcpy(content, encryptedKey.c_str(), request.payloadHeader.contentSize);
//	}
//	else if (type == MSG_TEXT || type == MSG_FILE)
//	{
//		// Common Logic for MSG_TEXT, MSG_FILE
//		if (data.empty())
//		{
//			clearLastError();
//			_lastError << "Empty input was provided!";
//			return false;
//		}
//		if (!client.symmetricKeySet)
//		{
//			clearLastError();
//			_lastError << "Couldn't find " << client.username << "'s symmetric key.";
//			return false;
//		}
//
//		uint8_t* file = nullptr;
//		size_t bytes;
//		if ((type == MSG_FILE) && !_fileHandler->readAtOnce(data, file, bytes))  // data = filename
//		{
//			clearLastError();
//			_lastError << "file not found";
//			return false;
//		}
//		AESWrapper aes(client.symmetricKey.symmetricKey, sizeof(client.symmetricKey.symmetricKey));
//		const std::string encrypted = (type == MSG_TEXT) ? aes.Encrypt(data) : aes.Encrypt(file, bytes);
//		request.payloadHeader.contentSize = encrypted.size();
//		content = new uint8_t[request.payloadHeader.contentSize];
//		memcpy(content, encrypted.c_str(), request.payloadHeader.contentSize);
//		delete[] file;
//	}
//
//	// prepare message to send
//	size_t msgSize;
//	uint8_t* msgToSend;
//	request.header.payloadSize = sizeof(request.payloadHeader) + request.payloadHeader.contentSize;
//	if (content == nullptr)
//	{
//		msgToSend = reinterpret_cast<uint8_t*>(&request);
//		msgSize   = sizeof(request);
//	}
//	else
//	{
//		msgToSend = new uint8_t[sizeof(request) + request.payloadHeader.contentSize];
//		memcpy(msgToSend, &request, sizeof(request));
//		memcpy(msgToSend + sizeof(request), content, request.payloadHeader.contentSize);
//		msgSize = sizeof(request) + request.payloadHeader.contentSize;
//	}
//
//	// send request and receive response
//	ClientSocket socket(m_address, m_port);
//	if (!socket.SendAndReceive(msgToSend, msgSize, reinterpret_cast<uint8_t* const>(&response), sizeof(response)))
//	{
//		delete[] content;
//		if (msgToSend != reinterpret_cast<uint8_t*>(&request))
//			delete[] msgToSend;
//		clearLastError();
//		_lastError << "Failed communicating with server on " << socket;
//		return false;
//	}
//
//	delete[] content;
//	if (msgToSend != reinterpret_cast<uint8_t*>(&request))  // check if msgToSend was allocated by current code.
//		delete[] msgToSend;
//
//	// Validate SResponseMessageSent header
//	if (!validateHeader(response.header, RESPONSE_MSG_SENT))
//		return false;  // error message updated within.
//
//	// Validate destination clientID
//	if (request.payloadHeader.clientId != response.payload.clientId)
//	{
//		clearLastError();
//		_lastError << "Unexpected clientID was received.";
//		return false;
//	}
//
//	return true;
//}
//
