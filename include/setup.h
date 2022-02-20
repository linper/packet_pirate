/**
 * @file setup.h
 * @brief Interface to set up program and simmilar things
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef H_SETUP
#define H_SETUP

#include <argp.h>

#include "utils.h"

/**
 * @brief Corresponding struct to bpf filter related command line arrguments
 */
struct filter_args {
	const char *proto; ///> 	Protocol
	const char *shost; ///> 	Source host
	const char *dhost; ///> 	Destination host
	const char *sport; ///> 	Source port
	const char *dport; ///> 	Destination port
	const char *snet; ///> 		Source network
	const char *dnet; ///> 		Destination network
	const char *bpf; ///> 		BPF query/uncompiled program
	const char *sample; ///> 	File to analize instead of live capture
	const char *interface; ///> Interface/device to sniff		
};

/**
 * @brief Corresponding struct all command line arrguments
 */
struct prog_args {
	verb verbosity; ///< 				Program vervosity
	bool bpf_enabled; ///< 				Did we supplied BPF
	struct filter_args filter; ///< 	Filter arguments struct
};

/**
 * @brief Sets up proram context from command line arguments
 * @param[in] argc 		Number of command line arguments
 * @param[in] *argv 	Argument list
 * @return Status whether setting up succeded
 */
status_val setup(int argc, char **argv);

#endif
