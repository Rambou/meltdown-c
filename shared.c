#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include "shared.h"

void strlower(char *dest, const char *src)
{
	for (; *src != 0; dest++, src++)
		*dest = (char)tolower(*src);
	*dest = 0; // Null-term
}

void Encrypt(uint8_t *dest, const uint8_t *src, size_t size,
	NextSeedFunction Next)
{
	uint16_t seed;
	size_t i, index;
	seed = GetIOControlSeed();
	for (i = 0; i < size; i++) {
		index = (size - 1) - i;
		seed = Next(seed);
		dest[index] = src[index] ^ (i + 3) ^ (seed & 0xFF);
	}
}

uint16_t GetIOControlSeed()
{
	uint64_t value;
	GetSystemTimeAsFileTime((FILETIME*)&value);
	value -= 0x019DB1DED53E8000;
	value /= 0x989680;
	return (uint16_t)value;
}

BOOL IsGoodBufferSize(uint32_t buffer_size)
{
	return (buffer_size >= 0x1000 && buffer_size <= 0x1000000);
}

HANDLE OpenVolume()
{
	TCHAR windows_dir[MAX_PATH], volume_path[7];
	if (!GetWindowsDirectory(windows_dir, MAX_PATH))
		return NULL;
	_snprintf(volume_path, 7, "\\\\.\\%c%c",
		(char)windows_dir[0], (char)windows_dir[1]);
	return CreateFileA(volume_path, 0, 0, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

void Print16Bytes(const char *prefix, const uint8_t *b)
{
	printf("%s: { %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x, %02x }\n",
		prefix, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

BOOL ParseHex(uint32_t *value, const char *str)
{
	return sscanf(str, "%x", value) == 1 ? TRUE : FALSE;
}

void XorBytes(uint8_t *dest, const uint8_t *xorpad, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++) {
		dest[i] ^= xorpad[i];
	}
}
