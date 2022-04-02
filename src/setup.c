/**
 * @file setup.c
 * @brief Interface implementation to set up program and simmilar things
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <string.h>
#include "../include/setup.h"
#include "../include/glist.h"

/** @brief Corresponding struct all command line arrguments */
#define NEMPTY_STR(s) s &&strcmp(s, "")

/** @brief Global program context definition */
struct prog_ctx pc = { 0 };

/**********************
*  CMD LINE PARAMS  *
**********************/

/** @brief Program name to be desplayed in help message */
const char *argp_program_version = "Packet Pirate 1.0";

/* @brief Contacts to be desplayed in help message */
/*const char *argp_program_bug_address = "<none@none.none>";*/

/** @brief Program documentation to be desplayed in help message */
static char doc[] = "Powered by 'Packet Pirate' sniffing framework in C";

/** @brief A description of the arguments we accept to be desplayed in help message */
/*static char args_doc[] = "ARG1 ARG2";*/
static char args_doc[] = {0};

/** @brief The options we understand  to be desplayed in help message */
static struct argp_option options[] = {
	{ "prune", 'p', "filter", 0,
	  "Allows modifications of filter tree. Filter tree branch to prune. Works with 'grow' parameter. Can use multiple times",
	  0 },
	{ "grow", 'g', "filter", 0,
	  "Allows modifications of filter tree. Filter tree node to grow branch to. Works with 'prune' parameter. Can use multiple times",
	  0 },
	{ "bpf", 'b', "query", 0,
	  "Fully supported BPF query for first stage filter",
	  0 },
	{ "sample", 's', "file", 0, "Sample .pcap file for offline analysis", 0 },
	{ "device", 'd', "device", 0, "Interface/device to sniff", 0 },
	{ "verbose", 'v', "verbosity", 0, "Set verbosity [0-6]", 0 },
	{ 0 }
};

/**
 * @brief Parse a single option
 */
static error_t parse_p(int key, char *arg, struct argp_state *state)
{
	struct prog_ctx *prc = state->input;
	struct tree_mod *tm = NULL;
	status_val status;

	switch (key) {
	case 'v':
		prc->verbosity = atoi(arg) >= _L_COUNT ? _L_COUNT - 1 : atoi(arg);
		break;
	case 'p':
		tm = malloc(sizeof(struct tree_mod));
		if (!tm) {
			return 1;
		}

		tm->mod = true;
		tm->tag = arg;
		status = glist_push(prc->tree_mods, tm);
		if (status) {
			LOG(L_ERR, status);
			return 1;
		}
		break;
	case 'g':
		tm = malloc(sizeof(struct tree_mod));
		if (!tm) {
			return 1;
		}

		tm->mod = false;
		tm->tag = arg;
		status = glist_push(prc->tree_mods, tm);
		if (status) {
			LOG(L_ERR, status);
			return 1;
		}
		break;
	case 'd':
		prc->dev = arg;
		break;
	case 's':
		prc->sample = arg;
		break;
	case 'b':
		prc->bpf = arg;
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
static void parse_params(int argc, char *argv[], struct prog_ctx *args)
{
	args->verbosity = L_WARN; //setting default verbosity
	argp_parse(&argp, argc, argv, 0, 0, args);
}

/**********************
*  DEFAULTS *
**********************/

/**
 * @brief Initializes default program argument struct from defines passed by compiler
 * @params[out] *pa Program argument struct to fill up
 * @return Void
 */
static void defaults_init(struct prog_ctx *prc)
{
	prc->bpf = DEF_BPF;

#ifdef VERB_QUIET
	prc->verbosity = L_QUIET;
#endif
#ifdef VERB_CRIT
	prc->verbosity = L_CRIT;
#endif
#ifdef VERB_ERR
	prc->verbosity = L_ERR;
#endif
#ifdef VERB_WARN
	prc->verbosity = L_WARN;
#endif
#ifdef VERB_NOTICE
	prc->verbosity = L_NOTICE;
#endif
#ifdef VERB_INFO
	prc->verbosity = L_INFO;
#endif
#ifdef VERB_DEBUG
	prc->verbosity = L_DEBUG;
#endif

#ifndef DEF_AUTO_IF
	prc->dev = strdup(DEF_IF);
#endif
}

/**********************
*  SETUP  *
**********************/

status_val setup(int argc, char **argv)
{
	pc.tree_mods = glist_new(8);
	if (!pc.tree_mods) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	defaults_init(&pc);

	parse_params(argc, argv, &pc); //geting command line parameters

	return STATUS_OK;
}

