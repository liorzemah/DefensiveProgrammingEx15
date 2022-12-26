#pragma once
#include <cstdint>
#include <string>

class Base64
{
	Base64() = delete;
	static const std::string BASE64_CHARS;
	static bool isBase64Letter(unsigned char c);

public:
	static std::string Encode(const std::string& bytes);
	static std::string Encode(const uint8_t* bytes, size_t len);
	static std::string Decode(const std::string& base64Str);
};

