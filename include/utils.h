/**
 * @file utils.h
 * @brief Definitions of various utilities. This should be included in
 * every other source file. It is also intended to be used by end user
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef H_UTILS
#define H_UTILS

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>

/**@brief Initial capacity multiplier of filter hashmaps*/
#define FH_CAP_MULTIPLIER 2

/** @brief Creates long integer value with specified bit as 1*/
#define BIT(b) (1 << b)

/** @brief Creates long integer value with specified number of last bits as 1*/
#define BITS(b) ~(~(0u) << b)

/**
 * @brief Ceil number of bits to byte
 * @return value in bytes
 */
#define BITOBY(b) (b ? ((b - 1) / 8 + 1) : 0)

/** @brief Number of bytes to number of bits*/
#define BYTOBI(b) (8 * b) /*bytes to bits*/

/** @brief Gets reminder of bits if value ware converted to bytes*/
#define BIREM(b) (b & 7) /*remaining bits*/

/**
 * @brief Floor number of bits to byte
 * @return value in bytes
 */
#define BYWHO(b) (b >> 3)

//#define container_of(ptr, type, member) (type *)((char *)(ptr) - (char *) &((type *)0)->member)

/**
 * @brief Macro for filter initiallization. This must exist in each filter.
 * It registers each filter before main() is called. 
 */
#define INIT_FILTER(filter)                                                    \
	void __attribute__((constructor)) init_##filter()                          \
	{                                                                          \
		glist_push(pc.f_reg, &filter);                                         \
	}

//** @brief enum of error statuses */
typedef enum {
	STATUS_OK = 0, ///<		OK, no error
	STATUS_ERROR, ///< 		Unknown error
	STATUS_OMEM, ///< 		Out of memory
	STATUS_NOT_FOUND, ///< 	Something's missing
	STATUS_FULL, ///< 		Buffer is full
	STATUS_BAD_INPUT, ///< 	Invalid value was passed
	STATUS_DB, ///< 		Database/dump error
} status_val;

//** @brief enum of logging levels */
typedef enum {
	L_QUIET, ///< 	Using this in LOG*() is pointless
	L_CRIT, ///< 	Irecoverable error
	L_ERR, ///<		Standard error
	L_WARN, ///< 	Abnormal state. warning
	L_NOTICE, ///< 	Low importance messages
	L_INFO, ///< 	Informational messages
	L_DEBUG, ///< 	Debugging messages
	_L_COUNT, ///< 	Should not be used in LOG*()
} verb;

/**@brief Definition of program context struct*/
struct prog_ctx {
	u_long last_dump; ///< 				UTC of last dump timestamp
	size_t next_pid; ///< 				Id that will be assigned to next packet
	u_long pp_hash; ///<  				Hash value of compiled filters
	pcap_t *handle; ///< 				Pcap context
	verb verbosity; ///< 				Program verbosity, this is verb enum
	char *bpf; ///<						Built or given bfp filter query
	const char *sample; ///< 			File to read instead of live capture
	char *dev; ///<						Interface to sniff
	struct bpf_program bpf_prog; ///< 	Compiled BPF program
	struct ef_tree *ef_root; ///< 		Root of extended filter tree
	struct fhmap *f_entries; ///< 		Hashmap of all filter entries
	struct glist *single_cap_pkt; ///< 	List of filtered packets in single capture
	struct glist *f_reg; ///< 			List of registered filters
	struct glist *tree_mods; ///< 		List of to modify filter tree
};

/**@brief Struct to modify filter tree after compilation*/
struct tree_mod {
	bool mod; ///< 			Modification type. True - prune; False - include;
	const char *tag; ///< 	Filter tag to prine/include
};

/** @brief Global variable for program context*/
extern struct prog_ctx pc;

/** @brief Gets Length of array in static context*/
#define ARR_LEN(arr) sizeof arr / sizeof(arr[0])

/**
 * @brief Computes hash value of whole extended filter tree.
 * @return Hash value
 */
u_long get_global_hash();

/**
 * @brief Logs messages
 * @param lvl 		Verbosity level
 * @param status 	Error status 
 * @param file 		File from witch this function was called - __FILE__
 * @param line 		Line number from witch this function was called - __LINE__
 * @param format 	Format string for folowing parameters
 * @param ... 		__VA_ARGS__ as parameters to format
 * @return Void
 */
void log_msg(verb lvl, status_val status, const char *file, int line,
			 const char *format, ...);

/**
 * @brief Prints specified amount of bytes as hex to stdout. Intended to 
 * be used for debugging purposes.
 * @param[in] *str 	Pointer to first data byte
 * @param[in] len 	Number of bytes to print
 */
#define PRINT_HEX(str, len)                                                    \
	for (size_t i = 0; i < (size_t)len; ++i)                                   \
		printf("0x%02x ", str[i]);                                             \
	printf("\n")

/**
 * @brief Logging macro with formattable custom message 
 * @param[in] lvl 		Verbosity level
 * @param[in] status 	Error type
 * @param[in] fmt 		printf() style format string
 * @param[in] ... 		printf() style variable length argument list
 */
#define LOGF(lvl, status, fmt, ...)                                            \
	if (lvl != L_QUIET && lvl <= pc.verbosity)                                 \
	log_msg(lvl, status, __FUNCTION__, __LINE__, fmt, __VA_ARGS__)

/**
 * @brief Logging macro with constant custom message 
 * @param[in] lvl 		Verbosity level
 * @param[in] status 	Error type
 * @param[in] msg 		Message to be displayed
 */
#define LOGM(lvl, status, msg)                                                 \
	if (lvl != L_QUIET && lvl <= pc.verbosity)                                 \
	log_msg(lvl, status, __FUNCTION__, __LINE__, msg)

/**
 * @brief Logging macro with default message 
 * @param[in] lvl 		Verbosity level
 * @param[in] status 	Error type
 */
#define LOG(lvl, status)                                                       \
	if (lvl != L_QUIET && lvl <= pc.verbosity)                                 \
	log_msg(lvl, status, __FUNCTION__, __LINE__, NULL)

#endif
