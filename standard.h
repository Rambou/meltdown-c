#pragma once

#include <stdint.h>

typedef struct {
	uint32_t initial_seed;
	uint16_t remaining_size;
	uint16_t decoded_size;
} password_header_t;

void STD_DecodePassword(uint8_t *dest, const uint8_t *src, const password_header_t *header);
void STD_Encrypt(uint8_t *dest, const uint8_t *src, size_t size);
uint16_t STD_GetNextIOControlSeed(uint16_t seed);
uint32_t STD_GetNextPasswordSeed(uint32_t seed);
void STD_ReadPasswordHeader(password_header_t *header, const uint8_t *src);
int STD_RequestConfig(uint8_t **config);
int STD_RequestPassword(uint8_t *dest, size_t size);
