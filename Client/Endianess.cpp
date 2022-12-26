#include "Endianess.h"
#include <mutex>
#include <iostream>
#include <intrin.h>

Endianess::Endianess()
{
}

bool Endianess::IsLittleEndian()
{
	static bool isLittle = true;
	static std::once_flag flag;
	std::call_once(flag, [&]() 
		{
		union
		{
			uint32_t i;
			uint8_t c[sizeof(uint32_t)];
		}tester{ 1 };
		isLittle = (tester.c[0] != 0); // is little
		});

	return isLittle;
}

void Endianess::ToLittle(uint8_t* buffer, size_t size)
{
	// if the buffer not initialized or the his size is smaller than one address block size
	if (buffer == nullptr || size < sizeof(uint32_t))
	{
		return;
	}
	// check if the endianess in the host is little, if yes there is nothing to do, if no swap the bytes
	if (IsLittleEndian())
	{
		return;
	}

	size -= (size % sizeof(uint32_t));
	uint32_t* ptr = reinterpret_cast<uint32_t*>(buffer);
	for (size_t i = 0; i < size; ++i)
	{
		ptr[i] = _byteswap_ulong(ptr[i]);
	}
}

void Endianess::Swap(uint8_t* buffer, size_t size)
{
	// if the buffer not initialized or the his size is smaller than one address block size
	if (buffer == nullptr || size < sizeof(uint32_t))
	{
		return;
	}

	size -= (size % sizeof(uint32_t));
	uint32_t* ptr = reinterpret_cast<uint32_t*>(buffer);
	for (size_t i = 0; i < size; ++i)
	{
		ptr[i] = _byteswap_ulong(ptr[i]);
	}
}