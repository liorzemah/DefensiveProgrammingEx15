#pragma once
#include <cstdint>

class Endianess
{
public:
	Endianess();
	static void ToLittle(uint8_t* buffer, size_t size); // convert bytes to little, if host work in little do nothing else swap the bytes
	static void Swap(uint8_t* buffer, size_t size);
	static bool IsLittleEndian(); // check if the host work in little or big endian
};