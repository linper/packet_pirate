
#include <sys/types.h>

#include "../include/converter.h"

status_val bytes_to_uint(u_char *data, u_int u_len, u_long *res)
{
	switch (u_len) { //TODO: this may break on big endian machines
	case 1:
		*res = *data;
		break;

	case 2:
		*res = __bswap_16(*(u_short *)data);
		break;

	case 4:
		*res = __bswap_32(*(u_short *)data);
		break;

	case 8:
		*res = __bswap_64(*(u_short *)data);
		break;

	default:
		LOGF(L_ERR, STATUS_BAD_INPUT, "Unsupported integer length detected:%ld",
			 u_len);
		return STATUS_BAD_INPUT;
	}

	return STATUS_OK;
}

static status_val uintle_to_uint(struct p_entry *e)
{
	status_val status;
	if ((status =
			 bytes_to_uint(e->raw_data, e->raw_len, &e->conv_data.ulong))) {
		LOGF(L_ERR, status, "Unsupported integer length detected:%ld",
			 e->raw_len);
	}

	return status;
}

static status_val to_hex(struct p_entry *e)
{
	e->conv_data.string = calloc(5 * e->raw_len + 8, sizeof(char));
	if (!e->conv_data.string) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	char *ptr = (char *)e->conv_data.string;
	for (long i = 0; i < e->raw_len; ++i) {
		ptr += sprintf(ptr, "0x%02x ", e->raw_data[i]);
	}

	return STATUS_OK;
}

static status_val to_raw(struct p_entry *e)
{
	//not allocating memory to save time and memory
	e->conv_data.blob.arr = e->raw_data;
	e->conv_data.blob.len = e->raw_len;

	return STATUS_OK;
}

converter converter_mat[_EWF_COUNT][_ERF_COUNT] = {
	[EWF_HEX_STR][ERF_UINT_LE] = to_hex,
	[EWF_HEX_STR][ERF_UINT_BE] = to_hex,
	[EWF_HEX_STR][ERF_STR] = to_hex,
	[EWF_HEX_STR][ERF_BIN] = to_hex,
	[EWF_UINT][ERF_UINT_LE] = uintle_to_uint,
	[EWF_RAW][ERF_UINT_LE] = to_raw,
	[EWF_RAW][ERF_UINT_BE] = to_raw,
	[EWF_RAW][ERF_STR] = to_raw,
	[EWF_RAW][ERF_BIN] = to_raw,
};
