#ifndef CONVERTER_H
#define CONVERTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils.h"
#include "filter.h"


typedef (status_val)(conv*)() converter;

//Converter matrix between types
//Entry positionns must match rw_comp_mat from filter.c
//lines - write
//columns - read
extern unsigned char rw_comp_mat[_EWF_COUNT][_ERF_COUNT];



#endif
