#include <stdio.h>
#include <stdint.h>
#include <Shlwapi.h>
#include <Shlobj.h>
#include <Windows.h>
#include "deepfreeze.h"

static void DF_GetInstallPath(char *dest, size_t size)
{
	char pf_path[MAX_PATH];
	SHGetSpecialFolderPath(0, pf_path, CSIDL_PROGRAM_FILES, FALSE);
	_snprintf(dest, size, "%s\\Faronics\\Deep Freeze\\Install C-0", pf_path);
}

void DF_GetDriverPath(char *dest, size_t size)
{
	char system_path[MAX_PATH];
	GetSystemDirectory(system_path, MAX_PATH);
	_snprintf(dest, size, "%s\\drivers\\DeepFrz.sys", system_path);
}

void DF_GetDfcPath(char *dest, size_t size)
{
	char system_path[MAX_PATH];
	GetSystemDirectory(system_path, MAX_PATH);
	_snprintf(dest, size, "%s\\dfc.exe", system_path);
}

void DF_GetServPath(char *dest, size_t size)
{
	char install_path[MAX_PATH];
	DF_GetInstallPath(install_path, MAX_PATH);
	_snprintf(dest, size, "%s\\DFServ.exe", install_path);
}

void DF_GetFrzState2kPath(char *dest, size_t size)
{
	char install_path[MAX_PATH];
	DF_GetInstallPath(install_path, MAX_PATH);
	_snprintf(dest, size, "%s\\_$Df\\FrzState2k.exe", install_path);
}

int DF_GetVersion(int *v)
{
	char driver_path[MAX_PATH];
	DWORD dummy, infoSize;
	uint8_t *infoRaw;
	VS_FIXEDFILEINFO *info;

	DF_GetDriverPath(driver_path, MAX_PATH);
	infoSize = GetFileVersionInfoSize(driver_path, &dummy);
	infoRaw = (uint8_t*)malloc(infoSize);
	if (!GetFileVersionInfo(driver_path, 0, infoSize, infoRaw)) {
		free(infoRaw);
		return ERR_VERSION_INFO;
	}

	if (!VerQueryValue(infoRaw, "\\", &info, &infoSize)) {
		free(infoRaw);
		return ERR_VERSION_QUERY;
	}

	free(infoRaw);

	v[0] = HIWORD(info->dwFileVersionMS);
	v[1] = LOWORD(info->dwFileVersionMS);
	v[2] = HIWORD(info->dwFileVersionLS);
	v[3] = LOWORD(info->dwFileVersionLS);

	return 0;
}

int DF_GetVersionString(char *dest, size_t size)
{
	int version[4], result;
	if ((result = DF_GetVersion(version)) != 0)
		return result;
	_snprintf(dest, size, "%d.%.2d.%.3d.%d",
		version[0], version[1], version[2], version[3]);
	return 0;
}

int DF_GetVersionFull(int *version, char *version_str, size_t size)
{
	int result;
	if ((result = DF_GetVersion(version)) != 0)
		return result;
	if ((result = DF_GetVersionString(version_str, size)) != 0)
		return result;
	return 0;
}

BOOL DF_IsVersionOrGreater(int v1, int v2, const int *version)
{
	if (version[0] > v1 || (version[0] == v1 && version[1] >= v2))
		return TRUE;
	else
		return FALSE;
}

BOOL DF_IsEnterprise()
{
	char dfc_path[MAX_PATH];
	DF_GetDfcPath(dfc_path, MAX_PATH);
	return PathFileExists(TEXT(dfc_path));
}
