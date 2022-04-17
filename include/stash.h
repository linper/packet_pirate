/**
 * @file stash.h
 * @brief Description of data structure, that stores all data in heap in one continiuos data block instead of many fragmented places
 * @author Linas Perkauskas
 * @date 2022-03-30
 */

#ifndef STASH_H
#define STASH_H

#include <stddef.h>
#include <stdlib.h>
#include "utils.h"
#include <sys/types.h>

#define STASH_DEFAULT_SIZE 1024

#ifdef DEVEL_STASH_DEBUG
#define STASH_GAP 8
#else
#define STASH_GAP 2
#endif //DEVEL_STASH_DEBUG

/**
 * @brief Implementation of 'stash'
 */
struct stash_block {
	/**Next block*/
	struct stash_block *next;
	/**Used bytes*/
	size_t used;
	/**Maximum capacity of internal array*/
	size_t cap;
	/**Internal array to store data*/
	u_char *arr;
};

/**
 * @brief structure to stash debugging
 */
struct stash_dbg {
	/**Next structure*/
	struct stash_dbg *next;
	/**Pointer to first byte of the gap*/
	u_char *gap;
	/**Source code line where preceeding data was 'allocated'*/
	int line;
	/**Function name where preceeding data was 'allocated'*/
	const char *func;
};

/**
 * @brief Implementation of 'stash'
 */
struct stash {
	/**Was this stash been used*/
	bool in_use;
	/**Maximum total capacity of all stash blocks*/
	size_t total_cap;
	/**How many blocks shash have*/
	size_t block_count;
	/**First stash block*/
	struct stash_block *first;
	/**Last stash block*/
	struct stash_block *last;
#ifdef DEVEL_STASH_DEBUG
	/**First `stash_dbg` struct*/
	struct stash_dbg *dbg;
	/**Data to be written into gaps between 'allocated' data for debugging*/
	u_char gap_content[STASH_GAP];
#endif
};

/**
 * @brief Creates stash struct
 * @return Pointer to created stash struct if successful, NULL otherwise  
 */
struct stash *stash_new();

/**
 * @brief Allocates memory in stash
 * @param[in] *st 		Stash pointer to append item to
 * @param[in] *size 	Size of item to be appended
 * @param[in] *func 	Current function name e.g. __FUNCTION__
 * @param[in] *line 	Current line e.g. __LINE__
 * @return pointer to 'allocated' data or NULL if unsuccessfull
 */
void *stash_alloc(struct stash *st, size_t size, const char *func, int line);

/**
 * @brief Cleares all stash data and sets it as not in_use
 * @param[in, out] *st	Pointer to stash to clear
 * @return status_val enum whether clearing succeded
 */
status_val stash_clear(struct stash *st);

/**
 * @brief Frees stash
 * @param[in] *st 	Pointer to stash to free
 * @return Void
 */
void stash_free(struct stash *st);

/**
 * @brief Allocates memory in stash
 * @param[in] *st 		Stash pointer to debug
 * @param[in] *func 	Current function name e.g. __FUNCTION__
 * @param[in] *line 	Current line e.g. __LINE__
 * @return pointer to 'allocated' data or NULL if unsuccessfull
 */
void stash_debug(struct stash *st, const char *func, int line);

#ifdef DEVEL_STASH_DEBUG
#define STASH_ALLOC(st, size) stash_alloc(st, size, __FUNCTION__, __LINE__)
#define STASH_DEBUG(st) stash_debug(st, __FUNCTION__, __LINE__)
#else
#define STASH_ALLOC(st, size) stash_alloc(st, size, NULL, 0)
#define STASH_DEBUG(st) stash_debug(st, NULL, 0)
#endif //DEVEL_STASH_DEBUG

#endif
