#ifndef H_UTILS
#define H_UTILS

#include <stdbool.h>
//#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define BUF_SIZE 512
#define ERRBUF_SIZE 256

typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;


#define BPF_PR_LEN 1024
#define NET_LEN 256
#define PORT_LEN 12

typedef enum {
    STATUS_OK = 0,
    STATUS_ERROR,
    STATUS_OMEM,
    STATUS_NOT_FOUND,
    STATUS_FULL,
    STATUS_BAD_INPUT,
    STATUS_COUNT,
} status_val;

typedef enum {
    VERB_DEFAULT,
    VERB_VERBOSE,
    VERB_QUIET,
} prog_verb;

struct prog_ctx { 		//struct for program context
    prog_verb verbosity; 	//program verbosity
    char *bpf; 			//built or given bfp filter query
};

extern struct prog_ctx pc; 	//program context instance


#define ARR_LEN(arr) sizeof arr / sizeof(arr[0])

/**
 * @brief Logs messages
 * @param status Message status 
 * @param file File from witch this function was called - __FILE__
 * @param line Line number from witch this function was called - __LINE__
 * @param format Format string for folowing parameters
 * @param ... __VA_ARGS__ as parameters to format
 * @return Void
 */
void log_msg(status_val status, const char *file, int line, const char *format, ...);

#endif
