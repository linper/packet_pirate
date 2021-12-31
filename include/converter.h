#ifndef CONVERTER_H
#define CONVERTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "utils.h"
#include "filter.h"

enum uint_len {
	L8,
	L16,
	L32,
	L64,
};

//format for every conferter function
typedef status_val (*converter)(struct p_entry *);

status_val bytes_to_uint(u_char *data, unsigned u_len, unsigned long *res);

//Converter matrix between types
//Entry positions must match rw_comp_mat from filter.c
//lines - write
//columns - read
extern converter converter_mat[_EWF_COUNT][_ERF_COUNT];

#endif
