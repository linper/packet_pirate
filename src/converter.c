/**
 * @file converter.c
 * @brief Implementation of interface of converter between read and write formats
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "../include/converter.h"

/**
 * @brief Conversion fron unsigned little enian int to unsigned int
 * @param[in] *data		Pointer to data to convert
 * @param[in] u_len		Length of data
 * @param[out] *res		Pointer to result buffer
 * @return STATUS_OK if successful
 */
status_val ule_to_uint(u_char *data, u_int u_len, u_long *res)
{
	if (u_len > sizeof(u_long)) {
		LOGF(L_DEBUG, STATUS_BAD_INPUT, "Too long integer:%ld", u_len);
		return STATUS_BAD_INPUT;
	}

	*res = 0;
	memcpy(res, data, u_len);

	return STATUS_OK;
}

/**
 * @brief Conversion fron unsigned big enian int to unsigned int
 * @param[in] *data		Pointer to data to convert
 * @param[in] u_len		Length of data
 * @param[out] *res		Pointer to result buffer
 * @return STATUS_OK if successful
 */
status_val ube_to_uint(u_char *data, u_int u_len, u_long *res)
{
	if (u_len > sizeof(u_long)) {
		LOGF(L_DEBUG, STATUS_BAD_INPUT, "Too long integer:%ld", u_len);
		return 1;
	}

	u_char *resb = (u_char *)res;
	*res = 0;

	for (u_int i = 0; i < u_len; i++) {
		resb[u_len - (i + 1)] = data[i];
	}

	return STATUS_OK;
}

static status_val uintle_to_uint(struct p_entry *e)
{
	status_val status;
	if ((status = ule_to_uint(e->raw_data, BITOBY(e->raw_len),
							  &e->conv_data.ulong))) {
		LOG(L_DEBUG, status);
	}

	return status;
}

static status_val uintbe_to_uint(struct p_entry *e)
{
	status_val status;
	if ((status = ube_to_uint(e->raw_data, BITOBY(e->raw_len),
							  &e->conv_data.ulong))) {
		LOG(L_DEBUG, status);
	}

	return status;
}

static status_val uintbe_to_string(struct p_entry *e)
{
	status_val status;
	u_long res = 0;
	if ((status = ube_to_uint(e->raw_data, BITOBY(e->raw_len), &res))) {
		LOG(L_DEBUG, status);
		return status;
	}

	asprintf(&e->conv_data.string, "%lu", res);

	return STATUS_OK;
}

static status_val uintle_to_string(struct p_entry *e)
{
	status_val status;
	u_long res = 0;
	if ((status = ule_to_uint(e->raw_data, BITOBY(e->raw_len), &res))) {
		LOG(L_DEBUG, status);
		return status;
	}

	asprintf(&e->conv_data.string, "%lu", res);

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
	u_char is_str = e->wfc == EWFC_STR ? 1 : 0;

	for (int i = 0; i < BITOBY(e->raw_len) - is_str; i++) {
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

static char b64_enc_t[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
							'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
							'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
							'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
							'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
							'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
							'8', '9', '+', '/' };

static u_char b64_dec_t[] = {
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
	char *out;
	u_char *in = e->raw_data;
	size_t i, j, v, olen, len = BITOBY(e->raw_len);

	if (!in || !BITOBY(len)) {
		return STATUS_ERROR;
	}

	olen = len;
	if (len & 0b11) {
		olen += 3 - (len % 3);
	}

	olen = olen / 3 * 4;

	out = malloc(olen + 1);
	if (!out) {
		return STATUS_OMEM;
	}

	out[olen] = '\0';

	for (i = 0, j = 0; i < len; i += 3, j += 4) {
		v = in[i];
		v = i + 1 < len ? v << 8 | in[i + 1] : v << 8;
		v = i + 2 < len ? v << 8 | in[i + 2] : v << 8;

		out[j] = b64_enc_t[(v >> 18) & 0x3f];
		out[j + 1] = b64_enc_t[(v >> 12) & 0x3f];
		if (i + 1 < len) {
			out[j + 2] = b64_enc_t[(v >> 6) & 0x3f];
		} else {
			out[j + 2] = '=';
		}
		if (i + 2 < len) {
			out[j + 3] = b64_enc_t[v & 0x3f];
		} else {
			out[j + 3] = '=';
		}
	}

	e->conv_data.string = out;
	return STATUS_OK;
}

static status_val b64_to_bin(struct p_entry *e)
{
	size_t i, j, v;
	u_char *in = e->raw_data;
	size_t len = strlen((char*)in);

	if (in == NULL || (len & 0b11)) {
		return STATUS_BAD_INPUT;
	}
	
	size_t outlen = len / 4 * 3;

	for (i = len; i-- > 0;) {
		if (in[i] == '=') {
			outlen--;
		} else {
			break;
		}
	}

	u_char *out = malloc(outlen + 1);

	if (!out) {
		return STATUS_OMEM;
	}

	for (i = 0; i < len; i++) {
		if (!b64_dec_t[in[i]] && in[i] != 'A' && in[i] != '=') {
			return STATUS_BAD_INPUT;
		}
	}

	for (i = 0, j = 0; i < len; i += 4, j += 3) {
		v = b64_dec_t[in[i]];
		v = (v << 6) | b64_dec_t[in[i + 1]];
		v = in[i + 2] == '=' ? v << 6 : (v << 6) | b64_dec_t[in[i + 2]];
		v = in[i + 3] == '=' ? v << 6 : (v << 6) | b64_dec_t[in[i + 3]];

		out[j] = (v >> 16) & 0xff;
		if (in[i + 2] != '=')
			out[j + 1] = (v >> 8) & 0xff;
		if (in[i + 3] != '=')
			out[j + 2] = v & 0xff;
	}

	e->conv_data.blob.arr = out;
	e->conv_data.blob.len = outlen;

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
	[EWF_STR][ERF_B64_STR] = str_to_str,
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

