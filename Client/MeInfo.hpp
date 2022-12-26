#pragma once
#include <string>
#include <fstream>
#include <array>
#include "protocol.h"
#include "RSAWrapper.h"

// Keep MeInfo data on the disk and in the memory, use this object for relevent requests
class MeInfo
{
	static const std::string ME_FILE;
	ClientName m_name;
	ClientID m_uuid;
	std::shared_ptr<RSAPrivateWrapper> m_rsa;

	void SaveRsaPrivateKey(); // save RSA private key on disk

public:

	MeInfo();
	MeInfo(const ClientName& name, const ClientID& uuid);

	ClientName GetClientName() { return m_name; }
	ClientID GetClientID() { return m_uuid; }
	std::shared_ptr<RSAPrivateWrapper> GetRsaObject() { return m_rsa; }
	std::string GetRsaPrivateKey() { return m_rsa->getPrivateKey(); }
	std::string GetRsaPublicKey() { return m_rsa->getPublicKey(); }
};

