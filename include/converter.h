#ifndef CONVERTER_H
#define CONVERTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils.h"
#include "filter.h"

//format for every conferter function
typedef status_val(*converter)(struct p_entry*);

//Converter matrix between types
//Entry positions must match rw_comp_mat from filter.c
//lines - write
//columns - read
extern converter converter_mat[_EWF_COUNT][_ERF_COUNT];



#endif
