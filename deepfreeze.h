#pragma once

#include <stdint.h>
#include <Windows.h>

void DF_GetDriverPath(char *dest, size_t size);
void DF_GetDfcPath(char *dest, size_t size);
void DF_GetFrzState2kPath(char *dest, size_t size);
void DF_GetServPath(char *dest, size_t size);
BOOL DF_GetVersion(int *v);
BOOL DF_GetVersionString(char *dest, size_t size);
BOOL DF_GetVersionFull(int *version, char *version_str, size_t size);
BOOL DF_IsEnterprise();
BOOL DF_IsVersionOrGreater(int v1, int v2, const int *version);
