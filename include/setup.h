#ifndef H_SETUP
#define H_SETUP

#include <argp.h>

#include "utils.h"

struct filter_args { //struct ot hold all command line parameters
	const char *proto;
	const char *shost;
	const char *dhost;
	const char *sport;
	const char *dport;
	const char *snet;
	const char *dnet;
	const char *bpf;
	const char *sample;
	const char *interface;
};

struct prog_args {
	verb verbosity;
	bool bpf_enabled;
	struct filter_args filter;
};

status_val setup(int argc, char **argv);

#endif
