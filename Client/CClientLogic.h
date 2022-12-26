/////**
//// * MessageU Client
//// * @file CClientLogic.h
//// * @brief The core logic of Client.
//// * CClientLogic received commands from CClientMenu and invokes internal logic such as CFileHandler, CSocketHandler.
//// * @author Roman Koifman
//// * https://github.com/Romansko/MessageU/blob/main/client/header/CClientLogic.h
//// */
//#pragma once
//#include "protocol.h"
//#include <sstream>
//#include <string>
//#include <vector>
//
//constexpr auto CLIENT_INFO = "me.info";   // Should be located near exe file.
//constexpr auto SERVER_INFO = "server.info";  // Should be located near exe file.
//
//class CFileHandler;
//class ClientSocket;
//class RSAPrivateWrapper;
//
//class CClientLogic
//{
//public:
//	
//	struct SClient
//	{
//		ClientID     id;
//		std::string   username;
//		SPublicKey    publicKey;
//		bool          publicKeySet    = false;
//		SSymmetricKey symmetricKey;
//		bool          symmetricKeySet = false;
//	};
//
//	struct SMessage
//	{
//		std::string username; // source username
//		std::string content;
//	};
//
//public:
//	CClientLogic();
//	virtual ~CClientLogic();
//	CClientLogic(const CClientLogic& other) = delete;
//	CClientLogic(CClientLogic&& other) noexcept = delete;
//	CClientLogic& operator=(const CClientLogic& other) = delete;
//	CClientLogic& operator=(CClientLogic&& other) noexcept = delete;
//
//	// inline getters
//	std::string getLastError() const { return _lastError.str(); }
//	std::string getSelfUsername() const { return _self.username; }
//	ClientID   getSelfClientID() const { return _self.id; }
//	
//	// client logic to be invoked by client menu.
//	bool parseServeInfo();
//	bool parseClientInfo();
//	std::vector<std::string> getUsernames() const;
//	bool registerClient(const std::string& username);
//	bool requestClientsList();
//	bool requestClientPublicKey(const std::string& username);
//	bool requestPendingMessages(std::vector<SMessage>& messages);
//	bool sendMessage(const std::string& username, const EMessageType type, const std::string& data = "");
//
//private:
//	void clearLastError();
//	bool storeClientInfo();
//	bool validateHeader(const SResponseHeader& header, const ResponseCode expectedCode);
//	bool receiveUnknownPayload(const uint8_t* const request, const size_t reqSize, const ResponseCode expectedCode, uint8_t*& payload, size_t& size);
//	bool setClientPublicKey(const SClientID& clientID, const SPublicKey& publicKey);
//	bool setClientSymmetricKey(const SClientID& clientID, const SSymmetricKey& symmetricKey);
//	bool getClient(const std::string& username, SClient& client) const;
//	bool getClient(const SClientID& clientID, SClient& client) const;
//
//	SClient              _self;           // self symmetric key invalid.
//	std::vector<SClient> _clients;
//	std::stringstream    _lastError;
//	CFileHandler*        _fileHandler;
//	RSAPrivateWrapper*   _rsaDecryptor;
//	std::string m_address;
//	std::string m_port;
//};
