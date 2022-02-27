#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "../../include/converter.h"

void t_ule_to_u(void **state)
{
	(void)state;

	u_char raw[] = { '\x12', '\x00' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "";
	u_long ures = 18;

	enum ewf_comp wfc = EWFC_INT;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_UINT][ERF_UINT_LE](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_ube_to_u(void **state)
{
	(void)state;

	u_char raw[] = { '\x00', '\x12' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "";
	u_long ures = 18;

	enum ewf_comp wfc = EWFC_INT;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_UINT][ERF_UINT_BE](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_to_hex(void **state)
{
	(void)state;

	u_char raw[] = { '\x11', '\x67' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "0x11 0x67";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_STR;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_HEX_STR][ERF_BIN](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_to_hexdump(void **state)
{
	(void)state;

	u_char raw[] = { '\x11', '\x67' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "11 67";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_STR;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_HEXDUMP][ERF_BIN](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_to_dhex(void **state)
{
	(void)state;

	u_char raw[] = { '\x11', '\x67' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "11.67";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_STR;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_HEX_DT][ERF_BIN](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_to_dbyte(void **state)
{
	(void)state;

	u_char raw[] = { '\x11', '\x67' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "17.103";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_STR;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_DEC_DT][ERF_BIN](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_str_to_str(void **state)
{
	(void)state;

	u_char raw[] = { '\x32', '\x36', '\x00' };
	/*u_char *raw = (u_char*)"26";*/

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "26";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_STR;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWFC_STR][ERF_STR](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_to_raw(void **state)
{
	(void)state;

	u_char raw[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_BLOB;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_RAW][ERF_BIN](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_to_b64(void **state)
{
	(void)state;

	u_char raw[] = { 'a', 'b', 'c', 'd' };

	u_char bres[] = { '\x01', '\x23', '\x34', '\x56', '\x70' };
	char *sres = "YWJjZA==";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_STR;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_B64_STR][ERF_BIN](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

void t_b64_to_bin(void **state)
{
	(void)state;

	u_char raw[] = { 'Y', 'W', 'J', 'j', 'Z', 'A', '=', '=' };

	u_char bres[] = { 'a', 'b', 'c', 'd' };
	char *sres = "";
	u_long ures = 17;

	enum ewf_comp wfc = EWFC_BLOB;

	struct p_entry pe = {
		.raw_data = raw,
		.raw_len = BYTOBI(sizeof raw),
		.wfc = wfc,
	};

	int status = (int)converter_mat[EWF_DECODED][ERF_B64_STR](&pe);

	assert_int_equal(0, status);

	switch (wfc) {
	case EWFC_BLOB:
		assert_memory_equal(pe.conv_data.blob.arr, bres, sizeof bres);
		assert_int_equal(pe.conv_data.blob.len, sizeof bres);
		break;

	case EWFC_STR:
		assert_string_equal(pe.conv_data.string, sres);
		break;

	case EWFC_INT:
		assert_int_equal(pe.conv_data.ulong, ures);
		break;

	default:
		return;
	}
}

int main(void)
{
	const struct CMUnitTest simple_tests[] = {
		cmocka_unit_test(t_ule_to_u),	cmocka_unit_test(t_ube_to_u),
		cmocka_unit_test(t_to_hex),		cmocka_unit_test(t_to_hexdump),
		cmocka_unit_test(t_to_dhex),	cmocka_unit_test(t_to_dbyte),
		cmocka_unit_test(t_str_to_str), cmocka_unit_test(t_to_raw),
		cmocka_unit_test(t_to_b64),		cmocka_unit_test(t_b64_to_bin),
	};

	int simple_fails = cmocka_run_group_tests(simple_tests, NULL, NULL);

	return simple_fails;
}

