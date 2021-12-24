
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

static status_val to_hex(struct p_entry *e)
{
	e->conv_data = calloc(5 * e->raw_len + 8, sizeof(char));
	if (!e->conv_data) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	char *ptr = (char *)e->conv_data;
	for (size_t i = 0; i < e->raw_len; ++i) {
		ptr += sprintf(ptr, "0x%02x ", e->raw_data[i]);
	}

	e->conv_len = ptr - (char *)e->conv_data;

	return STATUS_OK;
}

converter converter_mat[_EWF_COUNT][_ERF_COUNT] = {
	[EWF_HEX_STR][ERF_UINT_LE] = to_hex,
	[EWF_HEX_STR][ERF_UINT_BE] = to_hex,
	[EWF_HEX_STR][ERF_STR] = to_hex,
};
