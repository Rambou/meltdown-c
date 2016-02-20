#include <stdio.h>
#include <stdint.h>

long int FileSize(FILE *file)
{
	long int orig, size;

	if (file == NULL)
		return 0;

	orig = ftell(file);
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fseek(file, orig, SEEK_SET);
	return size;
}

int FindEndOfLastSection(size_t *end_offset, FILE *file)
{
	uint32_t dos_hdr_offset, raw_size, raw_addr;
	uint16_t i, section_num, opt_hdr_size;
	*end_offset = 0;

	// Read offset of DOS header
	fseek(file, 0x3c, SEEK_SET);
	if (!fread(&dos_hdr_offset, 4, 1, file))
		return 0;
	// Read section count
	fseek(file, dos_hdr_offset + 0x6, SEEK_SET);
	if (!fread(&section_num, 2, 1, file))
		return 0;
	// Read size of optional header
	fseek(file, dos_hdr_offset + 0x14, SEEK_SET);
	if (!fread(&opt_hdr_size, 2, 1, file))
		return 0;
	// Read sections
	fseek(file, dos_hdr_offset + 0x18 + opt_hdr_size, SEEK_SET);
	for (i = 0; i < section_num; i++) {
		// Read raw size and address
		fseek(file, 0x10, SEEK_CUR);
		if (!fread(&raw_size, 4, 1, file)
			|| !fread(&raw_addr, 4, 1, file))
			return 0;
		if (*end_offset < (raw_addr + raw_size))
			*end_offset = (raw_addr + raw_size);
		// Seek past other fields
		fseek(file, 0x10, SEEK_CUR);
	}

	return 1;
}
