/**
 * @file filter.c
 * @brief Some implementations and definitions of variables and functions 
 * declared in file for end user to use.
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "../include/filter.h"

enum ewf_comp wfc_arr[_EWF_COUNT] = {
	[EWF_RAW] = EWFC_BLOB,
	[EWF_DECODED] = EWFC_BLOB,
	[EWF_UINT] = EWFC_INT,
	[EWF_STR] = EWFC_STR,
	[EWF_HEX_STR] = EWFC_STR,
	[EWF_HEXDUMP] = EWFC_STR,
	[EWF_HEX_DT] = EWFC_STR,
	[EWF_DEC_DT] = EWFC_STR,
	[EWF_B64_STR] = EWFC_STR,
};

//compatability matrix between read and write formats
//lines - write
//columns - read
unsigned char rw_comp_mat[_EWF_COUNT][_ERF_COUNT] = {
	{1, 1, 1, 1, 1},
	{0, 0, 0, 0, 1},
	{1, 1, 0, 0, 0},
	{1, 1, 1, 0, 1},
	{1, 1, 1, 1, 1},
	{1, 1, 1, 1, 1},
	{1, 1, 1, 1, 1},
	{1, 1, 1, 1, 1},
	{1, 1, 1, 1, 1},
};

int fe_idx(struct filter *f, const char *tag)
{
	struct f_entry *fe_arr = f->entries;
	for (size_t i = 0; i < f->n_entries; i++) {
		if (!strcmp(fe_arr[i].tag, tag)) {
			return i;
		}
	}

	return -1;
}

