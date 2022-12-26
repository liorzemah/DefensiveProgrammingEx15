#pragma once
#include <string>
#include <boost/noncopyable.hpp>

class AESWrapper : boost::noncopyable
{
	const uint8_t* m_symmetricKey;
	size_t m_symmetricKeySize;

public:
	AESWrapper(const uint8_t* symmetricKey, size_t symmetricKeySize); // symmetricKey allocate outside therefor dont free in the destructor
	virtual ~AESWrapper() = default;
	
	std::string Encrypt(const std::string& plain) const;
	std::string Encrypt(const uint8_t* plain,  size_t length) const;
	std::string Decrypt(const uint8_t* cipher, size_t length) const;
};
