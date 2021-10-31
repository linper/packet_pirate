#ifndef H_PARAMS
#define H_PARAMS

#include <argp.h>

#include "utils.h"


struct filter_args { 	//struct ot hold all command line parameters
    const char *proto;
    const char *shost;
    const char *dhost;
    const char *sport;
    const char *dport;
    const char *snet;
    const char *dnet;
    const char *bpf;
};

struct prog_args {
    verb verbosity;
    bool bpf_enabled;
    struct filter_args filter;
};

status_val parse_params (int argc, char **argv, struct prog_args *args);

#endif
