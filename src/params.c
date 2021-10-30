#include "../include/params.h"

const char *argp_program_version =
    "packet pirate 1.0";
const char *argp_program_bug_address =
    "<none@none.none>";

/* Program documentation. */
static char doc[] =
    "Yet another packet sniffer";

/* A description of the arguments we accept. */
static char args_doc[] = "ARG1 ARG2";

/* The options we understand. */
static struct argp_option options[] = {
    {"proto",       'r', "proto", 	 	 	0, 	"Protocol to capture packets of. Can be one of ether, fddi, tr, wlan, ip, ip6, arp, rarp, decnet, tcp and udp", 0 },
    {"shost",       'h', "shost", 	 	 	0, 	"Filter for the IPv4/v6 when source field of the packet is <shost>", 0 },
    {"dhost",       'H', "dhost", 	 	 	0, 	"Filter for the IPv4/v6 when destination field of the packet is <dhost>", 0 },
    {"sport",       'p', "sport", 	 	 	0, 	"Filter for the ip/tcp, ip/udp, ip6/tcp or ip6/udp when source port value of <sport>", 0 },
    {"dport",       'P', "dport", 	 	 	0, 	"Filter for the ip/tcp, ip/udp, ip6/tcp or ip6/udp when destination port value of <dport>", 0 },
    {"snet",        'n', "snet", 	 	 	0, 	"Filter for the IPv4/v6 when source network address is <snet>", 0 },
    {"dnet",        'N', "dnet", 	 	 	0, 	"Filter for the IPv4/v6 when destination network address is <dnet>", 0 },
    {"bpf",         'b', "bpf", 	 	 	0, 	"BPF program, with full support. If given, overrides all filters above", 0 },
    {"verbose",     'v', "verbose", 	 	0, 	"Produce verbose output", 0 },
    { 0 }
};

/* Used by main to communicate with parse_opt. */


/* Parse a single option. */
static error_t parse_p (int key, char *arg, struct argp_state *state)
{
    struct prog_args *args = state->input;

    switch (key) {
    case 'q':
        args->verbosity = VERB_QUIET;
        break;
    case 'v':
        args->verbosity = VERB_VERBOSE;
        break;
    case 'h':
        args->filter.shost = arg;
        break;
    case 'H':
        args->filter.dhost = arg;
        break;
    case 'p':
        args->filter.sport = arg;
        break;
    case 'P':
        args->filter.dport = arg;
        break;
    case 'n':
        args->filter.snet = arg;
        break;
    case 'N':
        args->filter.dnet = arg;
        break;
    case 'r':
        args->filter.proto = arg;
        break;
    case 'b':
        args->filter.bpf = arg;
        args->bpf_enabled = true;
        break;

    case ARGP_KEY_ARG:
    case ARGP_KEY_END:
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_p, args_doc, doc };

status_val parse_params (int argc, char *argv[], struct prog_args *args)
{
    argp_parse (&argp, argc, argv, 0, 0, args);
    return STATUS_OK;
}
