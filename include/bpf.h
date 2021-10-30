#ifndef H_BPF
#define H_BPF

#include "utils.h"
#include "params.h"

/**
 * @brief Builds bfp filter query from given command line arguments
 * @param pa Struct that holds given command line arguments
 * @return STATUS_OK if succeded
 */
status_val build_bpf(struct prog_args *pa);

#endif
