
#include "../include/setup.h"



struct prog_ctx pc;

status_val setup_prog_ctx(struct prog_args *pa)
{
    pc.verbosity = pa->verbosity;
    return STATUS_OK;
}
