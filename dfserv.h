#pragma once

#include <stdio.h>
#include <stdint.h>
#include <Windows.h>

typedef struct {
	uint32_t header_size;
	uint32_t unknowns_1[3];
	uint32_t entry_count;
	uint32_t unknowns_2[4];
	uint32_t full_size;
	uint32_t unknowns_3[2];
	uint32_t xor_keys[4];
	uint32_t unknowns_4[8];
} dfserv_tail_header_t;

typedef struct {
	uint32_t id;
	uint32_t data_offset;
	uint32_t data_size;
	uint32_t data_size_2;
	uint32_t unknowns[4];
} dfserv_tail_entry_t;

int32_t DFS_BuildSeed(const dfserv_tail_header_t *header);
void DFS_Decrypt1(uint8_t *dest, const uint8_t *src, size_t size);
void DFS_Decrypt2(uint8_t *dest, const uint8_t *src, size_t size);
void DFS_DecryptFromTable(uint8_t *dest, const uint8_t *src);
void DFS_DecryptTailData(uint8_t *dest, const uint8_t *src,
                         const dfserv_tail_header_t *header, size_t size);
int32_t DFS_GetNextSeed(int32_t seed);
BOOL DFS_ReadTailHeader(dfserv_tail_header_t *header, FILE *file);
void DFS_Wtf(uint8_t *dest, const uint8_t *src);
void DFS_DecryptWhatever(uint8_t *dest, uint8_t *key_thing);
BOOL DFS_ExtractToken(uint32_t *token);
void DFS_TripleDecrypt(uint8_t *dest);
BOOL DFS_FindAndReadTail(dfserv_tail_header_t *header, uint8_t **data, FILE *file);
