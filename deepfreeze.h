#pragma once

#include <stdint.h>
#include <Windows.h>

#define ERR_VERSION_INFO (-230)
#define ERR_VERSION_QUERY (-231)

void DF_GetDriverPath(char *dest, size_t size);
void DF_GetDfcPath(char *dest, size_t size);
void DF_GetFrzState2kPath(char *dest, size_t size);
void DF_GetServPath(char *dest, size_t size);
int DF_GetVersion(int *v);
int DF_GetVersionString(char *dest, size_t size);
int DF_GetVersionFull(int *version, char *version_str, size_t size);
BOOL DF_IsEnterprise();
