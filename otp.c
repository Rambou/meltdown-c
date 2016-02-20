#include <stdint.h>
#include <Windows.h>
// #include "data.h"
#include "errors.h"
#include "ioctl.h"
#include "shared.h"

// Offset of the key
#define KEY_OFFSET (0x289)

uint8_t config_e_size_request_g[] = {
	0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11,
	0xDC, 0xEF, 0x89, 0x67, 0x00, 0x00, 0x00, 0x00
};

// Sent with: CTRL_CONFIG_ENTERPRISE
uint8_t config_e_request_g[] = {
	0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x00,
	0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0xDC, 0xEF,
	0x89, 0x67, 0x0C, 0x00, 0x00, 0x00
};

// Relevant to: Enterprise v8.31
uint16_t OTP_GetNextIOControlSeed(uint16_t seed)
{
	return (((seed % 0xAD) * 0x89) - ((seed / 0xAD) * 2)) * -1;
}

void OTP_Encrypt(uint8_t *dest, const uint8_t *src, size_t size)
{
	Encrypt(dest, src, size, OTP_GetNextIOControlSeed);
}

uint32_t OTP_CR(const char *str)
{
	uint32_t v4, v5, result = 0;

	while (*str != 0) {
		v5 = (result << 4) + *str;
		v4 = v5 & 0xF0000000;
		if (v4 != 0)
			v5 ^= (v4 >> 24);
		result = ~v4 & v5;
		str++;
	}

	return result;
}

int32_t OTP_HL(int32_t src)
{
	return 32767 * (171 * (src % 177) - 2 * (src / 177));
}

void OTP_PWD(uint8_t *dest, size_t size, uint32_t token, uint32_t cch)
{
	uint32_t v5;
	uint16_t v6, v9, v10;

	v5 = cch ^ token ^ OTP_CR("igor zagoruchenko");
	v6 = v5 >> 0x10;
	v5 &= 0xFFFF;
	if (cch != 0) {
		v10 = OTP_HL(v5 ^ v6);
		v9 = v5 ^ OTP_HL(v6);
	} else {
		v10 = OTP_HL(v5);
		v9 = OTP_HL(v6);
	}

	_snprintf(dest, size, "%.04X%.04X", v10, v9);
}

int OTP_Generate(uint8_t *dest, size_t size, uint32_t cch, uint32_t token)
{
	char pass[16], pass_lower[16], prefix[9];
	uint32_t prefix_value;
	// Setup password
	OTP_PWD(pass, 16, token, cch);
	strlower(pass_lower, pass);
	// Setup prefix
	prefix_value = OTP_CR(pass_lower);
	_snprintf(prefix, 9, "%X", prefix_value);
	prefix[4] = '\0';
	// Format together
	_snprintf(dest, size, "%s-%s", prefix, pass);
	return 0;
}

/**
 * Communicates with the driver to get key necessary to generate the OTP.
 * Relevant to: Enterprise v8.31
 */
int OTP_RequestCCH(uint32_t *key, uint32_t token)
{
	HANDLE hDrive;
	uint8_t config_e_size_request[16], config_e_request[158];
	uint32_t buffer_size, recv_count;
	uint8_t *config;

	hDrive = OpenVolume();
	if (hDrive == INVALID_HANDLE_VALUE) {
		return ERR_OPEN_VOLUME;
	}

	memcpy(config_e_size_request, config_e_size_request_g, 16);
	*(uint32_t*)(config_e_size_request + 4) = token;
	OTP_Encrypt(config_e_size_request, config_e_size_request, 16);
	if (!DeviceIoControl(hDrive, IOCTL_DF_CCH_SIZE_REQ,
		config_e_size_request, 16,
		&buffer_size, 4,
		&recv_count, NULL)) {
		CloseHandle(hDrive);
		return ERR_IOCTL_GET_CONFIG_SIZE;
	}

	if (!IsGoodBufferSize(buffer_size)) {
		CloseHandle(hDrive);
		return ERR_IOCTL_BUFFER_SIZE;
	}

	// Allocate enough memory for the config data
	config = (uint8_t*)malloc(sizeof(uint8_t) * buffer_size);
	if (config == NULL) {
		CloseHandle(hDrive);
		return ERR_MALLOC;
	}

	// Set token to two spots in the config buffer
	memcpy(config_e_request, config_e_request_g, 158);
	*(uint32_t*)(config_e_request) = token;
	*(uint32_t*)(config_e_request + 0x92) = token;

	// Extra encrypt?
	uint8_t i, temp = 0xBC;
	for (i = 0; i < 0x92; i++, temp++)
		config_e_request[i] ^= (temp ^ i);

	OTP_Encrypt(config_e_request, config_e_request, 158);
	if (!DeviceIoControl(hDrive, IOCTL_DF_CCH_REQ,
		config_e_request, 158,
		config, buffer_size,
		&recv_count, NULL)) {
		free(config);
		CloseHandle(hDrive);
		return ERR_IOCTL_GET_CONFIG;
	}

	*key = *(uint32_t*)(config + KEY_OFFSET);
	free(config);
	CloseHandle(hDrive);

	return 0;
}
