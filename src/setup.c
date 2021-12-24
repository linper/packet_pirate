
#include "../include/params.h"
#include "../include/setup.h"

struct prog_ctx pc = { 0 };

status_val setup_prog_ctx(struct prog_args *pa)
{
	pc.next_pid = 0;
	pc.verbosity = pa->verbosity;
	return STATUS_OK;
}
