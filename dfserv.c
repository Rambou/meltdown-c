#include <stdint.h>
#include "data.h"
#include "deepfreeze.h"
#include "dfserv.h"
#include "shared.h"

#pragma pack(push,1)
typedef struct {
		uint32_t id;
		uint32_t offset;
		uint32_t size;
		uint32_t size_2;
		uint32_t unknown[4];
} tail_entry_t;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct {
	uint32_t header_size;
	uint32_t unknowns_1[3];
	uint32_t entry_count;
	uint32_t unknowns_2[4];
	uint32_t full_size;
	uint32_t unknowns_3[2];
	uint32_t xor_keys[4];
	tail_entry_t dir_entry;
} tail_header_t;
#pragma pack(pop)

#define TAIL_HEADER_SIZE (sizeof(tail_header_t))

/**
 * Set the given tail_entry_t from memory.
 * @param entry - Entry to set.
 * @param src   - Memory to read from.
 */
static void DFS_SetTailEntry(tail_entry_t *entry, const void *src)
{
	memcpy(entry, src, sizeof(*entry));
}

/**
 * Set the given tail_header_t from memory.
 * @param header - Header to set.
 * @param src    - Memory to read from.
 */
static void DFS_SetTailHeader(tail_header_t *header, const void *src)
{
	memcpy(header, src, sizeof (*header));
}

static void DFS_Decrypt1(uint8_t *dest, const uint8_t *src, size_t size)
{
	size_t i;
	uint8_t al = 0x5, cl = 0x25;
	for (i = 0; i < size; i++) {
		cl++;
		dest[i] = src[i] ^ al ^ cl;
		al++;
	}
}

static void DFS_Decrypt2(uint8_t *dest, const uint8_t *src, size_t size)
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
static void DFS_DecryptFromTable(uint8_t *dest, const uint8_t *src)
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
 * Build the key buffer.
 * @param src  - Initial buffer, must be at least 0x20 in size.
 * @param dest - Destination buffer, must be at least 0xF0 in size.
 */
static void DFS_BuildKeyBuffer(uint8_t *dest, const uint8_t *src)
{
	uint32_t i, j, s;
	const uint8_t *table = key_buffer_table_g,
	              *small_table = key_buffer_small_table_g;
	uint8_t arr[4], *block, x1, x2, x3, x4;
	block = dest;

	// Copy first 0x20 bytes of src into dest
	memcpy(dest, src, 0x20);
	for (i = 8; i < 0x3C; i++, block += 4) {
		x1 = block[0x1C];
		x2 = block[0x1D];
		x3 = block[0x1E];
		x4 = block[0x1F];

		if ((i & 7) == 0) {
			x1 = table[block[0x1D]] ^ small_table[i >> 3];
			x2 = table[block[0x1E]];
			x3 = table[block[0x1F]];
			x4 = table[block[0x1C]];
		} else if ((i & 7) == 4) {
			x1 = table[x1];
			x2 = table[x2];
			x3 = table[x3];
			x4 = table[x4];
		}

		s = ((i << 2) - 0x20);
		arr[0] = x1 ^ block[0];
		arr[1] = x2 ^ dest[s + 1];
		arr[2] = x3 ^ dest[s + 2];
		arr[3] = x4 ^ dest[s + 3];
		memcpy(block + 0x20, arr, 4);
	}
}

/**
 * What the fuck.
 */
static void DFS_Wtf(uint8_t *dest, const uint8_t *src)
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

// Decrypt 0x10 bytes, key_buffer is 0xF0 bytes
static void DFS_DecryptWhatever(uint8_t *dest, uint8_t *key_buffer)
{
	int i;
	uint8_t buffer[0x10];

	memcpy(buffer, dest, 0x10);
	// Xor the first 0x10 bytes by the bytes at offset 0xE0
	XorBytes(buffer, (key_buffer + 0xE0), 0x10);
	for (i = 0xD; i >= 0; i--) {
		// Decrypt first 0x10 bytes of key_buffer
		DFS_DecryptFromTable(buffer, buffer);
		XorBytes(buffer, (key_buffer + (i * 0x10)), 0x10);
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
static int32_t DFS_BuildSeed(const tail_header_t *header)
{
	int32_t i, key = 0;
	for (i = 0; i < 4; i++)
		key ^= header->xor_keys[i];
	key ^= (key >> 16);
	return key;
}

static uint8_t DFS_GetNextSeed(int32_t seed)
{
	seed = OTP_HL((int16_t)seed);
	return ((seed & 0xFF00) >> 8) ^ (seed & 0xFF);
}

/**
 * Decrypt the tail data found at the end of DFServ.exe.
 **/
static void DFS_DecryptTailData(uint8_t *dest, const uint8_t *src,
	const tail_header_t *header, size_t size)
{
	size_t i;
	uint32_t seed;
	seed = DFS_BuildSeed(header);
	for (i = 0; i < size; i++) {
		dest[i] = src[i] ^ DFS_GetNextSeed(seed + i);
	}
}

/**
 * Perform a "triple decrypt" on some data.
 * @param dest - Buffer to decrypt.
 */
static void DFS_TripleDecrypt(uint8_t *dest, size_t size, const int* version)
{
	uint8_t key_buffer[0xF0];

	if (DF_IsVersionOrGreater(8, 11, version) && size >= 0x10) {
		DFS_BuildKeyBuffer(key_buffer, key_buffer_init_g);
		DFS_DecryptWhatever(dest, key_buffer);
	}

	if (version[0] > 5) {
		DFS_Decrypt1(dest, dest, size);
		DFS_Decrypt2(dest, dest, size);
	}
}

static size_t DFS_GetTailDataSize(const tail_header_t *header)
{
	if (header->full_size < header->header_size)
		return 0;
	else
		return header->full_size - header->header_size;
}

static BOOL DFS_FindAndReadTail(tail_header_t *header, uint8_t **data, FILE *file)
{
	size_t end_offset, /* tail_size, */ tail_data_size;
	long int file_size;
	uint8_t raw_tail_header[TAIL_HEADER_SIZE];

	if (!FindEndOfLastSection(&end_offset, file)) {
		fprintf(stderr, "DFServ.exe does not appear to be a valid PE\n");
		return FALSE;
	}

	// Read the DFServ.exe tail header
	fseek(file, end_offset, SEEK_SET);
	if (fread(raw_tail_header, 1, TAIL_HEADER_SIZE, file) != TAIL_HEADER_SIZE) {
		fprintf(stderr, "Unable to read the tail header\n");
		return FALSE;
	}
	DFS_SetTailHeader(header, raw_tail_header);

	// Header size should be 0x60
	if (header->header_size != TAIL_HEADER_SIZE) {
		fprintf(stderr, "Unexpected tail header size: 0x%08x\n", header->header_size);
		return FALSE;
	}

	// Allocate memory for tail data
	tail_data_size = DFS_GetTailDataSize(header);
	*data = (uint8_t*)malloc(sizeof(uint8_t) * tail_data_size);
	if (*data == NULL) {
		fprintf(stderr, "Unable to allocate memory for tail data\n");
		return FALSE;
	}

	// Read tail data
	if (fread(*data, 1, tail_data_size, file) != tail_data_size) {
		fprintf(stderr, "Unable to read all tail data\n");
		free(*data);
		return FALSE;
	}

	return TRUE;
}

static BOOL DFS_IsEntryDataInScope(const tail_entry_t *entry, const tail_header_t *header)
{
	return (header->header_size <= entry->offset)
	&& (header->full_size >= (entry->offset + entry->size));
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
	char file_path[MAX_PATH];
	uint8_t *dir_data, *entries, *entry_data, *tail_data;
	tail_header_t tail_header = { 0 };
	tail_entry_t entry = { 0 };
	FILE *file;

	// In v8.11 or greater, the data we want is in DFServ.exe
	// Otherwise, it is in FrzState2k.exe
	if (DF_IsVersionOrGreater(8, 11, version)) {
		DF_GetServPath(file_path, MAX_PATH);
	} else {
		DF_GetFrzState2kPath(file_path, MAX_PATH);
	}

	file = fopen(file_path, "rb");
	if (file == NULL) {
		fprintf(stderr, "Unable to open DFServ.exe, may not be installed?\n");
		return FALSE;
	}

	if (!DFS_FindAndReadTail(&tail_header, &tail_data, file)) {
		fprintf(stderr, "Unable to read DFServ.exe tail\n");
		return FALSE;
	}

	if (!DFS_IsEntryDataInScope(&(tail_header.dir_entry), &tail_header)) {
		fprintf(stderr, "Directory entry data is out-of-scope\n");
		free(tail_data);
		return FALSE;
	}

	// Decrypt the "directory" data
	dir_data = tail_data + (tail_header.dir_entry.offset - tail_header.header_size);
	DFS_DecryptTailData(dir_data, dir_data, &tail_header, tail_header.dir_entry.size);

	entries = tail_data;
	for (uint32_t i = 0; i < tail_header.entry_count; i++, entries += sizeof(entry)) {
		DFS_SetTailEntry(&entry, entries);
		if (entry.id == 0xFFFFFFF0)
			break;
	}

	if (entry.id != 0xFFFFFFF0) {
		fprintf(stderr, "Unable to find FFFFFFF0 entry\n");
		free(tail_data);
		return FALSE;
	}

	if (!DFS_IsEntryDataInScope(&entry, &tail_header)) {
		fprintf(stderr, "FFFFFFF0 entry data is out-of-scope\n");
		free(tail_data);
		return FALSE;
	}

	entry.offset -= tail_header.header_size;

	// Decrypt the entry data
	entry_data = tail_data + entry.offset;
	DFS_DecryptTailData(entry_data, entry_data, &tail_header, entry.size);

	if (DF_IsVersionOrGreater(8, 31, version)) {
		if (entry.size >= 8
		&& *(uint32_t*)(entry_data + (entry.size - 4)) == 0xDCBA1234) {
			entry.size -= 0x8;
		}
	}

	// "Triple decrypt" the entry data
	DFS_TripleDecrypt(entry_data, entry.size, version);

	// After the 3-way decryption, first 4 bytes is the token
	// (unsure if the other data is useful in any way?)
	*token = *(uint32_t*)entry_data;
	free(tail_data);
	return TRUE;
}
