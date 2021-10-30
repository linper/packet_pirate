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

struct prog_ctx {
    prog_verb verbosity;
    char *bpf;
};

extern struct prog_ctx pc;


#define ARR_LEN(arr) sizeof arr / sizeof(arr[0])

void log_msg(status_val status, const char *file, int line, const char *format, ...);

#endif
