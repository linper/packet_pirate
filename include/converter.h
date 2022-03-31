/**
 * @file converter.h
 * @brief Description of interface of converter between read and write formats
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef CONVERTER_H
#define CONVERTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "utils.h"
#include "filter.h"
#include "stash.h"

/** @brief Format for every converter function */
typedef status_val (*converter)(struct stash *, struct p_entry *);

/**
 * @brief Matrix of converter functions. Must Match rw_comp_mat
 * lines - Write format
 * columns - Read format
 * @see rw_comp_mat
 */
extern converter converter_mat[_EWF_COUNT][_ERF_COUNT];

#endif
