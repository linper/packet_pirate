
#include "../include/converter.h"
#include <sys/types.h>


status_val bytes_to_uint(u_char *data, unsigned u_len, unsigned long *res)
{
    if (u_len > 8) {
	LOGM(L_ERR, STATUS_BAD_INPUT, "Int longer than 64 bits detected");
	return STATUS_BAD_INPUT;
    }
    
    unsigned padding = 8 - u_len;
    memcpy((void*)(((u_char*)(res)) + padding), data, u_len); //TODO never tested, hope this works
    /*memcpy((void*)(((u_char*)(&res->data)) + padding), data, u_len);*/
    return STATUS_OK;
}

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
    [EWF_HEX_STR][ERF_UINT_LE] = to_hex,
    [EWF_HEX_STR][ERF_UINT_BE] = to_hex,
    [EWF_HEX_STR][ERF_STR] = to_hex,
};
