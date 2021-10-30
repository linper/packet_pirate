
#include <stdarg.h>
#include <stdio.h>

#include "../include/utils.h"

static struct { 	//structure to describe messages
    status_val val; 	//message status to compare too
    bool err; 		//is this an error
    const char *msg; 	//default message
} msg_map[] = {
    {.val = STATUS_OK, 		.err = false,   .msg = NULL},
    {.val = STATUS_ERROR, 	.err = true,    .msg = "Error occured"},
    {.val = STATUS_OMEM,    	.err = true,    .msg = "Out of memory"},
    {.val = STATUS_NOT_FOUND,   .err = true,    .msg = "Value not found"},
    {.val = STATUS_FULL,    	.err = true,    .msg = "Container is full"},
    {.val = STATUS_BAD_INPUT,   .err = true,    .msg = "Invalid input value"},
    {.val = STATUS_COUNT},

};

void log_msg(status_val status, const char *file, int line, const char *format, ...)
{
    va_list vl;

    for (size_t i = 0; msg_map[i].val < STATUS_COUNT; i++) {
        if (msg_map[i].val == status) {
            switch (pc.verbosity) {
            case VERB_QUIET:
                return;
            case VERB_VERBOSE:
            case VERB_DEFAULT:
                if (status != STATUS_OK) {
                    if (format) {
			char ext_format[strlen(format) + 128];
#ifdef DEBUG
			    
			    sprintf(ext_format, "%s:[%d]: %s\n", file, line, format);
#else
			    sprintf(ext_format, "%s\n", format);
#endif //DEBUG
                        va_start(vl, format);
                        vfprintf(msg_map[i].err ? stderr : stdout, ext_format, vl);
                        va_end(vl);
                    } else if (msg_map[i].msg) {
#ifdef DEBUG
			    
			    fprintf(msg_map[i].err ? stderr : stdout, "%s:[%d]: %s\n", file, line, msg_map[i].msg);
#else
			    fprintf(msg_map[i].err ? stderr : stdout, "%s\n", msg_map[i].msg);
#endif //DEBUG
                    }
                }
                break;
            }
        }
    }
    return;
}
