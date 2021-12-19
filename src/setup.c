
#include "../include/setup.h"

struct prog_ctx pc;

status_val setup_prog_ctx(struct prog_args *pa)
{
	pc.next_puid = 0;
	pc.verbosity = pa->verbosity;
	return STATUS_OK;
}
