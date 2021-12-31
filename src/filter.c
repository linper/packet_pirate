#include <sys/types.h>

#include "../include/filter.h"

enum ewf_comp wfc_arr[_EWF_COUNT] = {
	[EWF_NONE] = EWFC_NONE,
	[EWF_RAW] = EWFC_BLOB,
	[EWF_UINT] = EWFC_INT,
	[EWF_STR] = EWFC_STR,
	[EWF_HEX_STR] = EWFC_STR,
	[EWF_B64_STR] = EWFC_STR,
};

enum erf_comp rfc_arr[_ERF_COUNT] = {
	[ERF_UINT_LE] = ERFC_INT,
	[ERF_UINT_BE] = ERFC_INT,
	[ERF_STR] = ERFC_STR,
	[ERF_BIN] = ERFC_BLOB,
};

//compatability matrix between read and write formats
//lines - write
//columns - read
unsigned char rw_comp_mat[_EWF_COUNT][_ERF_COUNT] = {
	{0, 0, 0, 0},
	{1, 1, 1, 1},
	{1, 0, 0, 0},
	{0, 0, 0, 0},
	{1, 1, 1, 1},
	{0, 0, 0, 0},
};

