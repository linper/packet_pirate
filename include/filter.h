#ifndef H_FILTER
#define H_FILTER

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


#define TAG_LEN 16


enum entry_type {
    ET_DATA,
    ET_OFFSET,
    ET_BITFIELD,
    ET_FLAG,
};

enum entry_len_tp {
    ELT_TAG,
    ELT_OFF,
    ELT_PAC_OFF,
    ELT_PAC_OFF_TAG,
    ELT_FLAG,
};

enum entry_read_format {
    ERF_NONE,
    ERF_UINT,
    ERF_UINT_BE,
    ERF_STR,
    _ERF_COUNT,
};

enum entry_write_format {
    EWF_NONE,
    EWF_UINT,
    EWF_UINT_BE,
    EWF_STR,
    EWF_HEX_STR,
    EWF_B64_STR,
    _EWF_COUNT,
};

//compatability matrix between read and write formats
//lines - write
//columns - read
extern unsigned char rw_comp_mat[_EWF_COUNT][_ERF_COUNT];

enum entry_flags {
    EF_NONE 	= 0,
    EF_PLD 	= 1 << 1,
    EF_OPT 	= 1 << 2,
};

struct entry_len {
    union {
        struct { 		//length given directly
            long length;
        } e_len_val; 
        struct { 		//length from current packet begining
            long length;
        } e_pact_off; 
        struct { 		//length as other entry's data
            char tag[TAG_LEN];
        } e_len_tag;
        struct { 		//length as other entry's data from current packet begining
            char tag[TAG_LEN];
        } e_pac_off_tag;
        struct { 		//number of bits with offset from entry with given tag
            char tag[TAG_LEN];
            long offset;
            long nbits;
        } e_len_bits;
    } data;
    enum entry_len_tp type; 	//used to identify length calculation method
};

//length from current packet begining
#define E_PAC_OFF(_length)   	   \
    {                    	   \
	.data = {           	   \
	    .e_pac_off = {         \
		.length = _length  \
	    }              	   \
	},                  	   \
	.type = ELT_PAC_OFF        \
    }

//length given directly
#define E_LEN(_length)      	   \
    {                    	   \
	.data = {           	   \
	    .e_len_val = { 	   \
		.length = _length  \
	    }              	   \
	},                  	   \
	.type = ELT_OFF  	   \
    }
    
//length as other entry's data
#define E_LEN_OF(_tag)      \
    {                       \
	.data = {           \
	    .e_len_tag = {  \
		.tag = _tag \
	    }               \
	},                  \
        .type = ELT_TAG     \
    }

//length as other entry's data from current packet begining
#define E_PAC_OFF_OF(_tag)      \
    {                           \
	.data = {               \
	    .e_pac_off_tag = {  \
		.tag = _tag,    \
	    }                   \
	},                      \
	.type = ELT_PAC_OFF_TAG \
    }
    
//number of bits with offset from entry with given tag
#define E_BITS(_tag, _offset, _nbits)   \
    {                                   \
	.data = {                       \
	    .e_len_bits = {             \
		.tag = _tag,            \
		.offset = _offset,      \
		.nbits = _nbits,        \
	    }                           \
	},                              \
        .type = ELT_FLAG                \
    }


struct entry { 					//packet field/entry
    char tag[TAG_LEN]; 				//globaly unique entry id
    enum entry_type type; 			//entry type
    struct entry_len len; 			//struct to define entry length
    enum entry_flags flags; 			//optional flags
    enum entry_read_format read_form; 		//data format (on wire)
    enum entry_write_format write_form; 	//data dump format
};

#define FILTER_LEN(arr) sizeof arr / sizeof(struct entry) //gets defined filter length

struct filter {
    char parent_tag[TAG_LEN]; //tag for parent(lower level) packet 
    char packet_tag[TAG_LEN]; //tag for current packet 
    void(*pre_filter)();      //function to call before filter is applied
    void(*post_filter)();     //function to call after filter is applied(for filtered packets)
    bool(*validate)();        //packet validation function, can be used for low level filtering
    struct entry *entries;    //array of packet field entries
    size_t n_entries;         //length of entries 
};

#endif
