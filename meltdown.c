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

#define OTP_REQUIRED_MSG "\n" \
	"The OTP token cannot be automagically generated  for\n" \
	"this version of Deep Freeze Enterprise, please enter\n" \
	"it manually\n"

// Also not sure if xorpad
const uint8_t entry_data_xorpad[] = {
	0xF9, 0x70, 0x25, 0x4F, 0x4B, 0x8A, 0x2A, 0x81,
	0x1D, 0x65, 0x02, 0xAD, 0x37, 0x21, 0x83, 0x48,
	0xF4, 0x13, 0xFA, 0x4D, 0xA8, 0xC4, 0x56, 0xB5,
	0x4F, 0xD6, 0x15, 0x84, 0xE7, 0x3A, 0x32, 0xF9
};

static void print_version(const char *edition, const char *version)
{
	printf("Detected DeepFreeze %s version %s\n", edition, version);
}

int main(int argc, char *argv[])
{
	int result, version[4];
	uint32_t cch, token, otp_token;
	char *edition, otp[64], version_str[64];
	BOOL is_enterprise;

	result = DF_GetVersionFull(version, version_str, 64);
	switch (result) {
		case ERR_VERSION_INFO:
		case ERR_VERSION_QUERY:
			fprintf(stderr, "Deep Freeze driver not found, are you sure it's installed?\n");
			return 1;
	}

	is_enterprise = DF_IsEnterprise();
	edition = is_enterprise ? "Enterprise" : "Standard";

	// For now, only Enterprise is supported
	if (!is_enterprise) {
		print_version(edition, version_str);
		fprintf(stderr, "Deep Freeze %s is not yet supported\n", edition);
		return 1;
	}

	// If Deep Freeze Enterprise earlier than v7.20, the OTP token needs
	// to be provided by the user
	// Otherwise, ask the driver for it :)
	if (is_enterprise && !DF_IsVersionOrGreater(7, 20, version)) {
		if (argc < 2) {
			printf("usage: %s <otp-token>\n", argv[0]);
			print_version(edition, version_str);
			printf(OTP_REQUIRED_MSG);
			return 1;
		} else if (!ParseHex(&otp_token, argv[1])) {
			print_version(edition, version_str);
			fprintf(stderr, "Unable to parse given OTP token: %s\n", argv[1]);
			return 1;
		}
	} else if (!OTP_RequestToken(&otp_token)) {
		fprintf(stderr, "Driver request for OTP Token failed\n");
		return 1;
	}

	print_version(edition, version_str);

	if (!DFS_ExtractToken(&token, version)) {
		fprintf(stderr, "Unable to extract token from DFServ.exe\n");
		return 1;
	}

	// printf("Extracted token for driver comm: %08x\n", token);

	if (DF_IsVersionOrGreater(8, 31, version)) {
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
	} else {
		// If prior to v8.31, the token we extracted was the CCH itself
		cch = token;
	}

	// printf("Retrieved CCH from driver: %08x\n", cch);

	OTP_Generate(otp, 64, cch, otp_token);
	printf("One-time Password: %s\n", otp);

	return 0;
}
