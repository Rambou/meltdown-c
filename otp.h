#pragma once

#include <stdint.h>

uint32_t OTP_CR(const char *str);
void OTP_Encrypt(uint8_t *dest, const uint8_t *src, size_t size);
int OTP_Generate(uint8_t *dest, size_t size, uint32_t cch, uint32_t token);
uint16_t OTP_GetNextIOControlSeed(uint16_t seed);
int32_t OTP_HL(int32_t src);
void OTP_PWD(uint8_t *dest, size_t size, uint32_t token, uint32_t cch);
int OTP_RequestCCH(uint32_t *key, uint32_t token);
