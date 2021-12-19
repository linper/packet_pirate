#ifndef H_FILTER
#define H_FILTER

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/types.h>

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
	ERF_UINT_LE,
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
	EF_NONE = 0,
	EF_PLD = 1 << 1,
	EF_OPT = 1 << 2,
};

struct entry_len {
	union {
		struct { //length given directly
			unsigned length;
		} e_len_val;
		struct { //length as other entry's data
			char tag[TAG_LEN];
		} e_len_tag;
		struct { //length from current packet begining
			unsigned length;
			char tag[TAG_LEN];
		} e_pact_off;
		struct { //length as other entry's data from current packet begining
			char tag[TAG_LEN];
		} e_pac_off_tag;
		struct { //number of bits with offset from entry with given tag
			char tag[TAG_LEN];
			unsigned offset;
			unsigned nbits;
		} e_len_bits;
	} data;
	enum entry_len_tp type; //used to identify length calculation method
};

//length of current entry given directly
#define E_LEN(_length)														 \
	{																		  \
		.data = { .e_len_val = { .length = _length } }, .type = ELT_OFF		\
	}

//length of current entry's as other entry's data
#define E_LEN_OF(_tag)														 \
	{																		  \
		.data = { .e_len_tag = { .tag = _tag } }, .type = ELT_TAG			  \
	}

//_length - total length from given packet's begining to current's end
#define E_PAC_OFF(_tag, _length)											   \
	{																		  \
		.data = {		   	   \
		.e_pac_off = {		 \
		.tag = _tag, 	   \
		.length = _length, \
	},				  	   \
	.type = ELT_PAC_OFF		\
	}

//current packet end is calculated from given packet's begining with offset of its data
#define E_PAC_OFF_OF(_tag)													 \
	{																		  \
		.data = {			   \
		.e_pac_off_tag = {  \
		.tag = _tag,	\
		}				   \
	},					  \
	.type = ELT_PAC_OFF_TAG													   \
	}

//number of bits with offset from entry with given tag
#define E_BITS(_tag, _offset, _nbits)										  \
	{																		  \
		.data = {					   \
		.e_len_bits = {			 \
		.tag = _tag,			\
		.offset = _offset,	  \
		.nbits = _nbits,		\
		}						   \
	},							  \
		.type = ELT_FLAG													 \
	}

struct f_entry { //packet field/entry
	char tag[TAG_LEN]; //globaly unique entry id
	enum entry_type type; //entry type
	struct entry_len len; //struct to define entry length
	enum entry_flags flags; //optional flags
	enum entry_read_format read_form; //data format (on wire)
	enum entry_write_format write_form; //data dump format
};

#define FILTER_LEN(arr)														\
	sizeof arr / sizeof(struct f_entry) //gets defined filter length

struct filter {
	char parent_tag[TAG_LEN]; //tag for parent(lower level) packet
	char packet_tag[TAG_LEN]; //tag for current packet
	void (*pre_filter)(
		u_char *, const struct pcap_pkthdr *,
		const u_char *); //function to call before filter is applied
	void (
		*post_filter)(); //function to call after filter is applied(for filtered packets)
	bool (
		*validate)(); //packet validation function, can be used for low level filtering
	struct f_entry *entries; //array of packet field entries
	unsigned n_entries; //length of entries
};

struct p_entry { //struct to store individual packet entry data
	const char *tag; //tag for parent(lower level) packet
	bool in_bits; //is length represented in bits
	unsigned raw_len; //length of received entry
	unsigned conv_len; //length of entry in write format
	u_char *raw_data; //pointer to allocated buffer with entry data
	u_char *
		conv_data; //pointe to allocated buffer wiith entry data in write format
};

struct packet { //struct to store received and filtered packet data
	unsigned id; //UID for received packet
	//enum p_status sta tus;
	const char *parent_tag; //tag for parent(lower level) packet
	const char *packet_tag; //tag for current packet
	unsigned e_len; //count of entry fields
	struct p_entry *entries; //array of entries
};

#endif
