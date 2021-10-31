
#include <stdarg.h>
#include <stdio.h>

#include "../include/utils.h"


const char *prog_verb_str[] = {
    [L_CRIT] = "CRITICAL",
    [L_ERR] = "ERROR",
    [L_WARN] = "WARNING",
    [L_NOTICE] = "NOTICE",
    [L_INFO] = "INFO",
    [L_DEBUG] = "DEBUG",
};

static struct { 	//structure to describe messages
    bool err; 		//is this an error
    const char *desc; 	//message type description
    const char *msg; 	//default message
} msg_map[] = {
    [STATUS_OK] 	= {.err = false, 	.desc = "OK", 		.msg = NULL},
    [STATUS_ERROR] 	= {.err = true, 	.desc = "ERROR",  	.msg = "Error occured"},
    [STATUS_OMEM] 	= {.err = true, 	.desc = "OMEM", 	.msg = "Out of memory"},
    [STATUS_NOT_FOUND] 	= {.err = true, 	.desc = "NOT FOUND", 	.msg = "Value not found"},
    [STATUS_FULL] 	= {.err = true, 	.desc = "FULL",  	.msg = "Container is full"},
    [STATUS_BAD_INPUT] 	= {.err = true, 	.desc = "BAD INPUT", 	.msg = "Invalid input value"},
};

void log_msg(verb lvl, status_val status, const char *file, int line, const char *format, ...)
{
    char loc[strlen(file) + strlen(prog_verb_str[lvl] + strlen(msg_map[status].desc) + 8)];
    char msg[256] = {0};

    sprintf(loc, "%s:[%d]:%s:%s", file, line, prog_verb_str[lvl], msg_map[status].desc);

    if (format) {
	va_list vl;
	va_start(vl, format);
	vsprintf(msg, format, vl);
	va_end(vl);
    } else if (msg_map[status].msg) {
	sprintf(msg, "%s", msg_map[status].msg);
    }
    
    fprintf(msg_map[status].err ? stderr : stdout, "%s: %s\n", loc, msg);

    return;
}
