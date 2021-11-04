
#include "../include/converter.h"

static status_val to_hex(struct p_entry *e)
{
    e->conv_data = calloc(5*e->raw_len+8, sizeof(char));
    if (!e->conv_data) {
	LOG(L_CRIT, STATUS_OMEM);
	return STATUS_OMEM;
    }

    char *ptr = (char*)e->conv_data;
    for (size_t i = 0; i < e->raw_len; ++i) {
        ptr += sprintf(ptr, "0x%02x ", e->raw_data[i]);
    }

    e->conv_len = ptr - (char*)e->conv_data;
       
    return STATUS_OK;
}

converter converter_mat[_EWF_COUNT][_ERF_COUNT] = {
    [EWF_HEX_STR][ERF_UINT] = to_hex,
    [EWF_HEX_STR][ERF_UINT_BE] = to_hex,
    [EWF_HEX_STR][ERF_STR] = to_hex,
};
