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
    L_QUIET, 	//using this in LOG*() is pointless
    L_CRIT, 	//irecoverable state
    L_ERR, 	//may be recoverable state
    L_WARN, 	//recoverable abnormal state
    L_NOTICE, 	//low importance messages
    L_INFO, 	//informational messages
    L_DEBUG, 	//debugging messages
    _L_COUNT, 	//should not me used in LOG*()
} verb;

struct prog_ctx { 		//struct for program context
    verb verbosity; 		//program verbosity
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
void log_msg(verb lvl, status_val status, const char *file, int line, const char *format, ...);

//different message logging macros
#define LOGF(lvl, status, fmt, ...) if (lvl != L_QUIET && lvl <= pc.verbosity) log_msg(lvl, status, __FILE__, __LINE__, fmt, __VA_ARGS__)
#define LOGM(lvl, status, msg) if (lvl != L_QUIET && lvl <= pc.verbosity) log_msg(lvl, status, __FILE__, __LINE__, msg)
#define LOG(lvl, status) if (lvl != L_QUIET && lvl <= pc.verbosity) log_msg(lvl, status, __FILE__, __LINE__, NULL)

#endif
