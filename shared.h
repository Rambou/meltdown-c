#pragma once

#include <stdio.h>
#include <stdint.h>
#include <Windows.h>

// Describes a function that takes a seed and returns the "next" seed
typedef uint16_t (*NextSeedFunction)(uint16_t seed);

void strlower(char *dest, const char *src);
void Encrypt(uint8_t *dest, const uint8_t *src, size_t size, NextSeedFunction Next);
BOOL FindEndOfLastSection(size_t *end_offset, FILE *file);
uint16_t GetIOControlSeed();
BOOL IsGoodBufferSize(uint32_t buffer_size);
HANDLE OpenVolume();
BOOL ParseHex(uint32_t *value, const char *str);
void Print16Bytes(const char *prefix, const uint8_t *b);
void XorBytes(uint8_t *dest, const uint8_t *xorpad, size_t size);
