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
 * @brief Sets up proram context from command line arguments
 * @param[in] argc 		Number of command line arguments
 * @param[in] *argv 	Argument list
 * @return Status whether setting up succeded
 */
status_val setup(int argc, char **argv);

#endif
