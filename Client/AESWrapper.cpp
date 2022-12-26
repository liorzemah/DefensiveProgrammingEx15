#include "AESWrapper.h"
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step


AESWrapper::AESWrapper(const uint8_t* symmetricKey, size_t symmetricKeySize) : m_symmetricKey(symmetricKey), m_symmetricKeySize(symmetricKeySize)
{
}

std::string AESWrapper::Encrypt(const std::string& plain) const
{
	return Encrypt(reinterpret_cast<const uint8_t*>(plain.c_str()), plain.size());
}

std::string AESWrapper::Encrypt(const uint8_t* text, size_t length) const
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(m_symmetricKey, m_symmetricKeySize);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(text, length);
	stfEncryptor.MessageEnd();

	return cipher;
}

std::string AESWrapper::Decrypt(const uint8_t* cipher, size_t length) const
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(m_symmetricKey, m_symmetricKeySize);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(cipher, length);
	stfDecryptor.MessageEnd();

	return decrypted;
}
