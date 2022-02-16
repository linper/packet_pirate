
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "../include/converter.h"

//TODO add support for integer lengths from 1 to 8 bytes with different endianess

status_val bytes_to_uint(u_char *data, u_int u_len, u_long *res)
{
	if (u_len > sizeof(u_long)) {
		LOGF(L_DEBUG, STATUS_BAD_INPUT, "Too long integer:%ld", u_len);
		return STATUS_BAD_INPUT;
	}

	*res = 0;
	memcpy(res, data, u_len);

	return STATUS_OK;
}

static status_val uintle_to_uint(struct p_entry *e)
{
	status_val status;
	if ((status = bytes_to_uint(e->raw_data, BITOBY(e->raw_len),
								&e->conv_data.ulong))) {
		LOG(L_DEBUG, status);
	}

	return status;
}

static status_val uintbe_to_uint(struct p_entry *e)
{
	u_long u_len = (u_long)(BITOBY(e->raw_len));
	if (u_len > sizeof(u_long)) {
		LOGF(L_DEBUG, STATUS_BAD_INPUT, "Too long integer:%ld", u_len);
		return 1;
	}
	u_char *resb = (u_char *)&e->conv_data.ulong;
	e->conv_data.ulong = 0;

	for (u_int i = 0; i < u_len; i++) {
		resb[u_len - (i + 1)] = e->raw_data[i];
	}

	return STATUS_OK;
}


//TODO fix rest of integer cconversions
static status_val uintbe_to_string(struct p_entry *e)
{
	switch (BITOBY(e->raw_len)) {
	case 1:
		asprintf(&e->conv_data.string, "%u", *e->raw_data);
		break;

	case 2:
		asprintf(&e->conv_data.string, "%u", *(u_short *)e->raw_data);
		break;

	case 4:
		asprintf(&e->conv_data.string, "%u", *(u_int *)e->raw_data);
		break;

	case 8:
		asprintf(&e->conv_data.string, "%lu", *(u_long *)e->raw_data);
		break;

	default:
		LOGF(L_DEBUG, STATUS_BAD_INPUT, "Unsupported integer length detected:%ld",
			 BITOBY(e->raw_len));
		return STATUS_BAD_INPUT;
	}

	return STATUS_OK;
}

static status_val uintle_to_string(struct p_entry *e)
{
	switch (BITOBY(e->raw_len)) {
	case 1:
		asprintf(&e->conv_data.string, "%u", *e->raw_data);
		break;

	case 2:
		asprintf(&e->conv_data.string, "%u",
				 __bswap_16(*(u_short *)e->raw_data));
		break;

	case 4:
		asprintf(&e->conv_data.string, "%u",
				 __bswap_32(*(u_short *)e->raw_data));
		break;

	case 8:
		asprintf(&e->conv_data.string, "%lu",
				 __bswap_64(*(u_short *)e->raw_data));
		break;

	default:
		LOGF(L_DEBUG, STATUS_BAD_INPUT, "Unsupported integer length detected:%ld",
			 BITOBY(e->raw_len));
		return STATUS_BAD_INPUT;
	}

	return STATUS_OK;
}

static status_val to_hex(struct p_entry *e)
{
	e->conv_data.string = calloc(5 * BITOBY(e->raw_len) + 8, sizeof(char));
	if (!e->conv_data.string) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	char *ptr = (char *)e->conv_data.string;
	for (long i = 0; i < BITOBY(e->raw_len); ++i) {
		ptr += sprintf(ptr, "0x%02x%s", e->raw_data[i],
					   i + 1 == BITOBY(e->raw_len) ? "" : " ");
	}

	return STATUS_OK;
}

static status_val to_hexdump(struct p_entry *e)
{
	e->conv_data.string = calloc(5 * BITOBY(e->raw_len) + 8, sizeof(char));
	if (!e->conv_data.string) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	char *ptr = (char *)e->conv_data.string;
	for (long i = 0; i < BITOBY(e->raw_len); ++i) {
		ptr += sprintf(ptr, "%02x%s", e->raw_data[i],
					   i + 1 == BITOBY(e->raw_len) ? "" : " ");
	}

	return STATUS_OK;
}

static status_val to_dotted_hex(struct p_entry *e)
{
	e->conv_data.string = calloc(5 * BITOBY(e->raw_len) + 8, sizeof(char));
	if (!e->conv_data.string) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	char *ptr = (char *)e->conv_data.string;
	for (long i = 0; i < BITOBY(e->raw_len); ++i) {
		ptr += sprintf(ptr, "%02x%s", e->raw_data[i],
					   i + 1 == BITOBY(e->raw_len) ? "" : ".");
	}

	return STATUS_OK;
}

static status_val to_dotted_byte(struct p_entry *e)
{
	e->conv_data.string = calloc(5 * BITOBY(e->raw_len) + 8, sizeof(char));
	if (!e->conv_data.string) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	char *ptr = (char *)e->conv_data.string;
	for (long i = 0; i < BITOBY(e->raw_len); ++i) {
		ptr += sprintf(ptr, "%d%s", e->raw_data[i],
					   i + 1 == BITOBY(e->raw_len) ? "" : ".");
	}

	return STATUS_OK;
}

static status_val to_raw(struct p_entry *e)
{
	//not allocating memory to save time and memory
	e->conv_data.blob.arr = e->raw_data;
	e->conv_data.blob.len = BITOBY(e->raw_len);

	return STATUS_OK;
}

static status_val str_to_str(struct p_entry *e)
{
	for (int i = 0; i < BITOBY(e->raw_len); i++) {
		if (!isprint((int)e->raw_data[i])) {
			LOGM(L_DEBUG, STATUS_BAD_INPUT, "Unprintable characters");
			return STATUS_BAD_INPUT;
		}
	}

	e->conv_data.string = calloc(BITOBY(e->raw_len) + 1, sizeof(char));
	if (!e->conv_data.string) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	snprintf(e->conv_data.string, BITOBY(e->raw_len), "%s", e->raw_data);

	return STATUS_OK;
}

static char b64_enc_t[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
							'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
							'u', 'v', 'w', 'x', 'y', 'z', 'a', 'b', 'c', 'd',
							'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
							'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
							'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
							'8', '9', '+', '/' };

static char b64_dec_t[] = {
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	62, 0,	0,	0,	63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
	61, 0,	0,	0,	0,	0,	0,	0,	0,	1,	2,	3,	4,	5,	6,	7,	8,	9,	10,
	11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,	0,	0,	0,
	0,	0,	26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51, 0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,	0
};

static status_val to_b64(struct p_entry *e)
{
	long byte_raw_len = BITOBY(e->raw_len);
	static int mod_t[] = { 0, 2, 1 };
	size_t out_len = 4 * ((byte_raw_len + 2) / 3);

	char *res = malloc(out_len);
	if (!res) {
		return STATUS_OMEM;
	}

	e->conv_data.string = res;

	for (int i = 0, j = 0; i < byte_raw_len;) {
		u_int b1 = i < byte_raw_len ? e->raw_data[i++] : 0;
		u_int b2 = i < byte_raw_len ? e->raw_data[i++] : 0;
		u_int b3 = i < byte_raw_len ? e->raw_data[i++] : 0;

		u_int b123 = (b1 << 16) + (b2 << 8) + b3;

		res[j++] = b64_enc_t[(b123 >> 18) & 0x3F];
		res[j++] = b64_enc_t[(b123 >> 12) & 0x3F];
		res[j++] = b64_enc_t[(b123 >> 6) & 0x3F];
		res[j++] = b64_enc_t[(b123)&0x3F];
	}

	for (int i = 0; i < mod_t[byte_raw_len % 3]; i++) {
		res[byte_raw_len - 1 - i] = '=';
	}

	return STATUS_OK;
}

static status_val b64_to_bin(struct p_entry *e)
{
	long byte_raw_len = BITOBY(e->raw_len);

	if (byte_raw_len % 4) {
		return STATUS_BAD_INPUT;
	}

	int out_len = byte_raw_len / 4 * 3;

	if (e->raw_data[byte_raw_len - 1] == '=') {
		out_len--;
	}

	if (e->raw_data[byte_raw_len - 2] == '=') {
		out_len--;
	}

	u_char *res = malloc(out_len);
	if (!res) {
		return STATUS_OMEM;
	}

	e->conv_data.blob.arr = res;
	e->conv_data.blob.len = out_len;

	for (int i = 0, j = 0; i < byte_raw_len;) {
		u_int s1 =
			e->raw_data[i] == '=' ? 0 & i++ : b64_dec_t[e->raw_data[i++]];
		u_int s2 =
			e->raw_data[i] == '=' ? 0 & i++ : b64_dec_t[e->raw_data[i++]];
		u_int s3 =
			e->raw_data[i] == '=' ? 0 & i++ : b64_dec_t[e->raw_data[i++]];
		u_int s4 =
			e->raw_data[i] == '=' ? 0 & i++ : b64_dec_t[e->raw_data[i++]];

		u_int s1234 = (s1 << 18) + (s2 << 12) + (s3 << 6) + s4;

		if (j < out_len) {
			res[j++] = (s1234 >> 2 * 8) & 0xFF;
		}

		if (j < out_len) {
			res[j++] = (s1234 >> 1 * 8) & 0xFF;
		}

		if (j < out_len) {
			res[j++] = (s1234 >> 0 * 8) & 0xFF;
		}
	}

	return STATUS_OK;
}

converter converter_mat[_EWF_COUNT][_ERF_COUNT] = {
	[EWF_HEX_STR][ERF_UINT_LE] = to_hex,
	[EWF_HEX_STR][ERF_UINT_BE] = to_hex,
	[EWF_HEX_STR][ERF_STR] = to_hex,
	[EWF_HEX_STR][ERF_BIN] = to_hex,
	[EWF_HEX_STR][ERF_B64_STR] = to_hex,
	[EWF_HEXDUMP][ERF_UINT_LE] = to_hexdump,
	[EWF_HEXDUMP][ERF_UINT_BE] = to_hexdump,
	[EWF_HEXDUMP][ERF_STR] = to_hexdump,
	[EWF_HEXDUMP][ERF_BIN] = to_hexdump,
	[EWF_HEXDUMP][ERF_B64_STR] = to_hexdump,
	[EWF_UINT][ERF_UINT_LE] = uintle_to_uint,
	[EWF_UINT][ERF_UINT_BE] = uintbe_to_uint,
	[EWF_STR][ERF_UINT_LE] = uintle_to_string,
	[EWF_STR][ERF_UINT_BE] = uintbe_to_string,
	[EWF_STR][ERF_STR] = str_to_str,
	[EWF_RAW][ERF_UINT_LE] = to_raw,
	[EWF_RAW][ERF_UINT_BE] = to_raw,
	[EWF_RAW][ERF_STR] = to_raw,
	[EWF_RAW][ERF_BIN] = to_raw,
	[EWF_RAW][ERF_B64_STR] = to_raw,
	[EWF_HEX_DT][ERF_UINT_LE] = to_dotted_hex,
	[EWF_HEX_DT][ERF_UINT_BE] = to_dotted_hex,
	[EWF_HEX_DT][ERF_STR] = to_dotted_hex,
	[EWF_HEX_DT][ERF_BIN] = to_dotted_hex,
	[EWF_HEX_DT][ERF_B64_STR] = to_dotted_hex,
	[EWF_DEC_DT][ERF_UINT_LE] = to_dotted_byte,
	[EWF_DEC_DT][ERF_UINT_BE] = to_dotted_byte,
	[EWF_DEC_DT][ERF_STR] = to_dotted_byte,
	[EWF_DEC_DT][ERF_BIN] = to_dotted_byte,
	[EWF_DEC_DT][ERF_B64_STR] = to_dotted_byte,
	[EWF_B64_STR][ERF_UINT_LE] = to_b64,
	[EWF_B64_STR][ERF_UINT_BE] = to_b64,
	[EWF_B64_STR][ERF_STR] = to_b64,
	[EWF_B64_STR][ERF_BIN] = to_b64,
	[EWF_B64_STR][ERF_B64_STR] = to_b64,
	[EWF_DECODED][ERF_B64_STR] = b64_to_bin,
};

