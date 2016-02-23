#include <stdint.h>
#include "data.h"
#include "deepfreeze.h"
#include "dfserv.h"
#include "pe.h"
#include "shared.h"

void DFS_Decrypt1(uint8_t *dest, const uint8_t *src, size_t size)
{
	size_t i;
	uint8_t al = 0x5, cl = 0x25;
	for (i = 0; i < size; i++) {
		cl++;
		dest[i] = src[i] ^ al ^ cl;
		al++;
	}
}

void DFS_Decrypt2(uint8_t *dest, const uint8_t *src, size_t size)
{
	size_t i;
	uint8_t al = 0x0, cl = 0x78;
	for (i = 0; i < size; i++) {
		cl++;
		dest[i] = src[i] ^ al ^ cl;
		al++;
	}
}

/**
 * Decrypt 16 bytes of src to dest using the hardcoded table.
 */
void DFS_DecryptFromTable(uint8_t *dest, const uint8_t *src)
{
	size_t i;
	uint8_t copy[0x10];
	// Use a copy buffer in case dest == src
	memcpy(copy, src, 0x10);
	for (i = 0; i < 4; i++)
		dest[i*4] = table_g[copy[i*4]];
	dest[0xD] = table_g[copy[0x9]];
	dest[0x9] = table_g[copy[0x5]];
	dest[0x5] = table_g[copy[0x1]];
	dest[0x1] = table_g[copy[0xD]];
	dest[0x2] = table_g[copy[0xA]];
	dest[0xA] = table_g[copy[0x2]];
	dest[0x6] = table_g[copy[0xE]];
	dest[0xE] = table_g[copy[0x6]];
	dest[0x3] = table_g[copy[0x7]];
	dest[0x7] = table_g[copy[0xB]];
	dest[0xB] = table_g[copy[0xF]];
	dest[0xF] = table_g[copy[0x3]];
}

/**
 * Build the "key thing".
 * @param src  - Initial buffer, should be at least 0x20 in size.
 * @param dest - Destination buffer, must be at least 0xF0 in size.
 */
void DFS_BuildKeyThing(uint8_t *dest, const uint8_t *src)
{
	uint32_t i, j, s;
	uint8_t arr[4], *block, bl, cl, dl, temp1, temp2, temp3 = 0;
	block = dest;

	// Copy first 0x20 bytes of src into dest
	memcpy(dest, src, 0x20);

	for (i = 8; i < 0x3C; i++, block += 4) {
		cl = block[0x1C];
		dl = block[0x1D];
		bl = block[0x1E];
		temp1 = bl;
		bl = block[0x1F];
		temp2 = bl;

		if ((i & 7) == 0) {
			temp3 = temp2;
			temp2 = b_469954[block[0x1C]];
			cl = b_469954[dl];
			cl ^= b_469F54[i >> 3];
			dl = b_469954[temp1];
			bl = b_469954[temp3];
			temp1 = bl;
		} else if ((i & 7) == 4) {
			bl = b_469954[temp1];
			cl = b_469954[cl];
			dl = b_469954[dl];
			temp1 = bl;
			bl = b_469954[temp2];
			temp2 = bl;
		}

		s = ((i << 2) - 0x20);
		arr[0] = cl ^ block[0];
		arr[1] = dl ^ dest[s + 1];
		arr[2] = dest[s + 2] ^ temp1;
		arr[3] = dest[s + 3] ^ temp2;

		memcpy(block + 0x20, arr, 4);
	}
}

/**
 * What the fuck.
 */
void DFS_Wtf(uint8_t *dest, const uint8_t *src)
{
	uint8_t a, b, copy[0x10], i, j, m;

	struct {
		uint8_t index;
		uint8_t t[4];
	} s[] = {
		{ 0x0, { 3, 1, 2, 0 } },
		{ 0x5, { 0, 3, 1, 2 } },
		{ 0xA, { 2, 0, 3, 1 } },
		{ 0xF, { 1, 2, 0, 3 } },
		{ 0x4, { 3, 1, 2, 0 } },
		{ 0x9, { 0, 3, 1, 2 } },
		{ 0xE, { 2, 0, 3, 1 } },
		{ 0x3, { 1, 2, 0, 3 } },
		{ 0x8, { 3, 1, 2, 0 } },
		{ 0xD, { 0, 3, 1, 2 } },
		{ 0x2, { 2, 0, 3, 1 } },
		{ 0x7, { 1, 2, 0, 3 } },
		{ 0xC, { 3, 1, 2, 0 } },
		{ 0x1, { 0, 3, 1, 2 } },
		{ 0x6, { 2, 0, 3, 1 } },
		{ 0xB, { 1, 2, 0, 3 } }
	};

	for (i = 0; i < 0x10; i++) {
		a = 0;
		m = (i / 4) * 4;
		for (j = 0; j < 4; j++) {
			b = src[m + j]; // Original byte from src
			a ^= wtf_tables_g[s[i].t[j]][b];
		}
		copy[s[i].index] = a;
	}

	for (i = 0; i < 0x10; i++) {
		dest[i] = another_table_g[copy[i]];
	}
}

// Decrypt 0x10 bytes, key_thing is 0xF0 bytes
void DFS_DecryptWhatever(uint8_t *dest, uint8_t *key_thing)
{
	int i;
	uint8_t buffer[0x10];

	memcpy(buffer, dest, 0x10);
	// Xor the first 0x10 bytes by the bytes at offset 0xE0
	XorBytes(buffer, (key_thing + 0xE0), 0x10);
	for (i = 0xD; i >= 0; i--) {
		// Decrypt first 0x10 bytes of key_thing
		DFS_DecryptFromTable(buffer, buffer);
		XorBytes(buffer, (key_thing + (i * 0x10)), 0x10);
		if (i != 0) {
			DFS_Wtf(buffer, buffer);
		}
	}
	memcpy(dest, buffer, 0x10);
}

/**
 * Build the initial seed (used for decrypting the tail data) from
 * the DFServ.exe tail header.
 **/
int32_t DFS_BuildSeed(const dfserv_tail_header_t *header)
{
	int32_t i, key = 0;
	for (i = 0; i < 4; i++)
		key ^= header->xor_keys[i];
	key ^= (key >> 16);
	return key;
}

uint8_t DFS_GetNextSeed(int32_t seed)
{
	seed = OTP_HL((int16_t)seed);
	return ((seed & 0xFF00) >> 8) ^ (seed & 0xFF);
}

/**
 * Decrypt the tail data found at the end of DFServ.exe.
 **/
void DFS_DecryptTailData(uint8_t *dest, const uint8_t *src,
	const dfserv_tail_header_t *header, size_t size)
{
	size_t i;
	uint32_t seed;
	seed = DFS_BuildSeed(header);
	for (i = 0; i < size; i++) {
		dest[i] = src[i] ^ DFS_GetNextSeed(seed + i);
	}
}

BOOL DFS_ReadTailHeader(dfserv_tail_header_t *header, FILE *file)
{
	int i;
	uint32_t *header32 = (uint32_t*)header;

	// For now, it's sufficient to just read all as 32-bit LE
	for (i = 0; i < (0x60 / 4); i++) {
		if (!fread((header32 + i), 4, 1, file))
			return FALSE;
	}

	return TRUE;
}

/**
 * Perform a "triple decrypt" on some data.
 * @param dest - Buffer to decrypt.
 */
void DFS_TripleDecrypt(uint8_t *dest, size_t size, const int* version)
{
	uint8_t full_key_thing[0xF0];

	if (DF_IsVersionOrGreater(8, 11, version) && size >= 0x10) {
		DFS_BuildKeyThing(full_key_thing, key_thing_init_g);
		DFS_DecryptWhatever(dest, full_key_thing);
	}

	if (version[0] > 5) {
		DFS_Decrypt1(dest, dest, size);
		DFS_Decrypt2(dest, dest, size);
	}
}

BOOL DFS_FindAndReadTail(dfserv_tail_header_t *header, uint8_t **data, FILE *file)
{
	size_t end_offset, tail_size, tail_data_size;
	long int file_size;

	if (!FindEndOfLastSection(&end_offset, file)) {
		fprintf(stderr, "DFServ.exe does not appear to be a valid PE\n");
		return FALSE;
	}

	file_size = FileSize(file);
	if (file_size < 0) {
		fprintf(stderr, "Unable to determine file size of DFServ.exe\n");
		return FALSE;
	}

	tail_size = (size_t)file_size - end_offset;

	// Read the DFServ.exe tail header
	fseek(file, end_offset, SEEK_SET);
	if (!DFS_ReadTailHeader(header, file)) {
		fprintf(stderr, "Unable to read the tail header\n");
		return FALSE;
	}

	tail_data_size = header->full_size - header->header_size;

	if (tail_data_size < 0x100) {
		fprintf(stderr, "Tail data must be at least 0x100 in size\n");
		return FALSE;
	}

	*data = (uint8_t*)malloc(sizeof(uint8_t) * tail_data_size);
	if (*data == NULL) {
		fprintf(stderr, "Unable to allocate memory for tail data\n");
		return FALSE;
	}

	if (fread(*data, 1, tail_data_size, file) != tail_data_size) {
		fprintf(stderr, "Unable to read all tail data\n");
		free(*data);
		return FALSE;
	}

	return TRUE;
}

/**
 * Extract the token from the DFServ.exe binary.
 * @param token - Assigned the token upon success.
 * @return TRUE if successful, FALSE if not.
 */
BOOL DFS_ExtractToken(uint32_t *token, const int *version)
{
	// --- Read DFServ.exe and grab its tail
	size_t end_offset, tail_size;
	long int file_size;
	char dfserv_path[MAX_PATH];
	FILE *dfserv;

	dfserv_tail_header_t tail_header;
	uint8_t *tail_data;

	// In v8.11 or greater, the data we want is in DFServ.exe
	// Otherwise, it is in FrzState2k.exe
	if (DF_IsVersionOrGreater(8, 11, version)) {
		DF_GetServPath(dfserv_path, MAX_PATH);
	} else {
		DF_GetFrzState2kPath(dfserv_path, MAX_PATH);
	}

	dfserv = fopen(dfserv_path, "rb");
	if (dfserv == NULL) {
		fprintf(stderr, "Unable to open DFServ.exe, may not be installed?\n");
		return FALSE;
	}

	if (!DFS_FindAndReadTail(&tail_header, &tail_data, dfserv)) {
		fprintf(stderr, "Unable to read DFServ.exe tail\n");
		return FALSE;
	}

	// Decrypt the tail data (first 0x100 bytes)
	DFS_DecryptTailData(tail_data, tail_data, &tail_header, 0xC0 /* 0x100 */);

	// Check each entry to make sure at least one starts with: 0xFFFFFFF0
	uint32_t entry_data_offset = 0, entry_data_size = 0;
	uint32_t *entries = (uint32_t*)tail_data;
	for (uint32_t i = 0; i < tail_header.entry_count; i++, entries += 8) {
		if (entries[0] == 0xFFFFFFF0) {
			entry_data_offset = entries[1];
			entry_data_size = entries[2];
		}
	}

	if (entry_data_offset == 0 && entry_data_size == 0) {
		fprintf(stderr, "Unable to find FFFFFFF0 entry\n");
		free(tail_data);
		return FALSE;
	}

	uint8_t *entry_data;
	entry_data_offset -= tail_header.header_size;

	// Decrypt the entry data
	entry_data = tail_data + entry_data_offset;
	DFS_DecryptTailData(entry_data, entry_data, &tail_header, entry_data_size);

	if (DF_IsVersionOrGreater(8, 31, version)) {
		if (entry_data_size >= 8
		&& *(uint32_t*)(entry_data + (entry_data_size - 4)) == 0xDCBA1234) {
			entry_data_size -= 0x8;
		}
	}

	//if (entry_data_size < 0x10) {
	//	fprintf(stderr, "Entry data size is less than 16\n");
	//	free(tail_data);
	//	return FALSE;
	//}

	// "Triple decrypt" the entry data
	DFS_TripleDecrypt(entry_data, entry_data_size, version);

	// After the 3-way decryption, first 4 bytes is the token
	// (unsure if the other data is useful in any way?)
	*token = *(uint32_t*)entry_data;
	free(tail_data);
	return TRUE;
}
