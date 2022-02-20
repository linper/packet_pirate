/**
 * @file setup.c
 * @brief Interface implementation to set up program and simmilar things
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include "../include/setup.h"
#include <string.h>

/** @brief Corresponding struct all command line arrguments */
#define NEMPTY_STR(s) s &&strcmp(s, "")

/** @brief Global program context definition */
struct prog_ctx pc = { 0 };

/**********************
*  CMD LINE PARAMS  *
**********************/

/** @brief Program name to be desplayed in help message */
const char *argp_program_version = "Packet Pirate 1.0";

/** @brief Contacts to be desplayed in help message */
const char *argp_program_bug_address = "<none@none.none>";

/** @brief Program documentation to be desplayed in help message */
static char doc[] = "Yet another packet sniffer";

/** @brief A description of the arguments we accept to be desplayed in help message */
static char args_doc[] = "ARG1 ARG2";

/** @brief The options we understand  to be desplayed in help message */
static struct argp_option options[] = {
	{ "proto", 'r', "proto", 0,
	  "Protocol to capture packets of. Can be one of ether, fddi, tr, wlan, ip, ip6, arp, rarp, decnet, tcp and udp",
	  0 },
	{ "shost", 'h', "shost", 0,
	  "Filter for the IPv4/v6 when source field of the packet is <shost>", 0 },
	{ "dhost", 'H', "dhost", 0,
	  "Filter for the IPv4/v6 when destination field of the packet is <dhost>",
	  0 },
	{ "sport", 'p', "sport", 0,
	  "Filter for the ip/tcp, ip/udp, ip6/tcp or ip6/udp when source port value of <sport>",
	  0 },
	{ "dport", 'P', "dport", 0,
	  "Filter for the ip/tcp, ip/udp, ip6/tcp or ip6/udp when destination port value of <dport>",
	  0 },
	{ "snet", 'n', "snet", 0,
	  "Filter for the IPv4/v6 when source network address is <snet>", 0 },
	{ "dnet", 'N', "dnet", 0,
	  "Filter for the IPv4/v6 when destination network address is <dnet>", 0 },
	{ "bpf", 'b', "bpf", 0,
	  "BPF program, with full support. If given, overrides all filters above",
	  0 },
	{ "sample", 's', "sample", 0, "Sample .pcap file for offline analysis", 0 },
	{ "interface", 'i', "interface", 0, "Interface to sniff", 0 },
	{ "verbose", 'v', "verbose", 0, "Set verbosity [0-6]", 0 },
	{ 0 }
};

/**
 * @brief Parse a single option
 */
static error_t parse_p(int key, char *arg, struct argp_state *state)
{
	struct prog_args *args = state->input;

	switch (key) {
	case 'v':
		args->verbosity = atoi(arg) >= _L_COUNT ? _L_COUNT - 1 : atoi(arg);
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
	case 'i':
		args->filter.interface = arg;
		break;
	case 's':
		args->filter.sample = arg;
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

/** @brief Our argp parser */
static struct argp argp = { .options = options,
							.parser = parse_p,
							.args_doc = args_doc,
							.doc = doc };

/**
 * @brief Parses command line parameters
 * @params[in] argc 		Number of arguments
 * @params[in] *argv[] 		List of arguments
 * @params[out] *args 		Program arguments struct to return results
 * @return Void
 */
static void parse_params(int argc, char *argv[], struct prog_args *args)
{
	args->verbosity = L_WARN; //setting default verbosity
	argp_parse(&argp, argc, argv, 0, 0, args);
}

/**********************
*  BPF  *
**********************/

/**
 * @brief Builds BPF port string
 * @params[out] *dst 	Pointer to destination buffer
 * @params[out] *src 	Pointer to source string
 * @params[in] *prefix 	"src" or "dst"
 * @return Void
 */
static inline void build_port_string(char *dst, const char *src, char *prefix)
{
	sprintf(dst, "%s %s %s ", prefix, strstr(src, "-") ? "portrange" : "port",
			src);
}

//TODO study bfp syntax and correct errors if they exist
/**
 * @brief Builds BPF compatable string
 * @params[in, out] *pa Program argument struct to work with
 * @return Status whether succeded
 */
static status_val build_bpf(struct prog_args *pa)
{
	status_val status = STATUS_ERROR;

	//+<some value> is for aditional "src/dst host/net" and similar
	char dst_net[DEVEL_NET_LEN + 9] = { 0 };
	char src_net[DEVEL_NET_LEN + 9] = { 0 };
	char dst_ports[DEVEL_PORT_LEN + 14] = { 0 };
	char src_ports[DEVEL_PORT_LEN + 14] = { 0 };

	if (pa->bpf_enabled) {
		if (NEMPTY_STR(pa->filter.bpf) &&
			strlen(pa->filter.bpf) >= DEVEL_BPF_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Bpf is too long");
			goto end;
		} else if (!(pc.bpf = strdup(pa->filter.bpf))) {
			status = STATUS_OMEM;
			LOG(L_CRIT, status);
			goto end;
		}
		status = STATUS_OK;
		goto end;
	}

	if (NEMPTY_STR(pa->filter.dhost) && NEMPTY_STR(pa->filter.dnet)) {
		status = STATUS_BAD_INPUT;
		LOGM(L_CRIT, status, "Dhost and dnet can't exist in unison");
		goto end;
	} else if (NEMPTY_STR(pa->filter.dhost)) {
		if (strlen(pa->filter.dhost) >= DEVEL_NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Dhost is too long");
			goto end;
		}
		sprintf(dst_net, "dst host %s ", pa->filter.dhost);
	} else if (NEMPTY_STR(pa->filter.dnet)) {
		if (strlen(pa->filter.dnet) >= DEVEL_NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Dnet is too long");
			goto end;
		}
		sprintf(dst_net, "dst net %s ", pa->filter.dnet);
	}

	if (NEMPTY_STR(pa->filter.shost) && NEMPTY_STR(pa->filter.snet)) {
		status = STATUS_BAD_INPUT;
		LOGM(L_CRIT, status, "Shost and snet can't exist in unison");
		goto end;
	} else if (NEMPTY_STR(pa->filter.shost)) {
		if (strlen(pa->filter.dnet) >= DEVEL_NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Shost is too long");
			goto end;
		}
		sprintf(src_net, "src host %s ", pa->filter.shost);
	} else if (NEMPTY_STR(pa->filter.snet)) {
		if (strlen(pa->filter.snet) >= DEVEL_NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Snet is too long");
			goto end;
		}
		sprintf(src_net, "src net %s ", pa->filter.snet);
	}

	if (NEMPTY_STR(pa->filter.dport)) {
		if (strlen(pa->filter.dport) >= DEVEL_PORT_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Dport is too long");
			goto end;
		}
		build_port_string(dst_ports, pa->filter.dport, "dst");
	}

	if (NEMPTY_STR(pa->filter.sport)) {
		if (strlen(pa->filter.sport) >= DEVEL_PORT_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Sport is too long");
			goto end;
		}
		build_port_string(src_ports, pa->filter.sport, "src");
	}

	const char *conj =
		((src_net[0] && dst_net[0]) || (src_ports[0] && dst_ports[0])) ?
			" && " :
			  "";

	if (!(pc.bpf = calloc(sizeof(char), DEVEL_BPF_LEN))) {
		status = STATUS_OMEM;
		LOG(L_CRIT, status);
		goto end;
	}

	snprintf(pc.bpf, DEVEL_BPF_LEN - 1, "%s %s%s%s%s%s", pa->filter.proto,
			 src_net, src_ports, conj, dst_net, dst_ports);
	status = STATUS_OK;

end:
	return status;
}

/**********************
*  DEFAULTS *
**********************/

/**
 * @brief Initializes default program argument struct from defines passed by compiler
 * @params[out] *pa Program argument struct to fill up
 * @return Void
 */
static void defaults_init(struct prog_args *pa)
{
#ifdef DEF_USE_BPF
	pa->bpf_enabled = true;
	pa->filter.bpf = DEF_BPF;
#else
	pa->bpf_enabled = false;
	pa->filter.dhost = DEF_DHOST;
	pa->filter.dnet = DEF_DNET;
	pa->filter.dport = DEF_DPORT;
	pa->filter.shost = DEF_SHOST;
	pa->filter.snet = DEF_SNET;
	pa->filter.sport = DEF_SPORT;
	pa->filter.proto = DEF_PROTO;
#endif

#ifdef VERB_QUIET
	pa->verbosity = 0;
#endif
#ifdef VERB_CRIT
	pa->verbosity = 1;
#endif
#ifdef VERB_ERR
	pa->verbosity = 2;
#endif
#ifdef VERB_WARN
	pa->verbosity = 3;
#endif
#ifdef VERB_NOTICE
	pa->verbosity = 4;
#endif
#ifdef VERB_INFO
	pa->verbosity = 5;
#endif
#ifdef VERB_DEBUG
	pa->verbosity = 6;
#endif

#ifndef DEF_AUTO_IF
	pa->filter.interface = DEF_IF;
#endif
}

/**********************
*  SETUP  *
**********************/

/**
 * @brief Sets up program context from program argument struct
 * @params[in] *pa Program argument struct to work with
 * @return Status whether succeded
 */
static status_val setup_prog_ctx(struct prog_args *pa)
{
	pc.next_pid = 0;
	pc.verbosity = pa->verbosity;
	pc.sample = pa->filter.sample;
	if (pa->filter.interface) {
		pc.dev = strdup(pa->filter.interface);
	}

	return STATUS_OK;
}

status_val setup(int argc, char **argv)
{
	struct prog_args pr_args = { 0 };

	defaults_init(&pr_args);

	parse_params(argc, argv, &pr_args); //geting command line parameters

	status_val status = setup_prog_ctx(&pr_args); //setting up program context
	if (status) {
		LOG(L_CRIT, status);
		return status;
	}

	if (!pr_args.bpf_enabled) {
		status = build_bpf(&pr_args);
		if (status) {
			LOG(L_CRIT, status);
			return status;
		}
	} else {
		pc.bpf = strdup(pr_args.filter.bpf);
	}

	return status;
}

