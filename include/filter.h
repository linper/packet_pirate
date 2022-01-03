#ifndef H_FILTER
#define H_FILTER

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/types.h>

#define TAG_LEN 16

enum entry_type {
	ET_DATAFIELD,
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
	ERF_UINT_LE, //TODO in order to use as offset packet must me marked by this or one below
	ERF_UINT_BE,
	ERF_STR,
	ERF_BIN,
	_ERF_COUNT,
};

enum entry_write_format {
	EWF_NONE,
	EWF_RAW,
	EWF_UINT,
	EWF_STR,
	EWF_HEX_STR,
	EWF_B64_STR,
	_EWF_COUNT,
};

enum ewf_comp {
	EWFC_NONE,
	EWFC_INT,
	EWFC_REAL, //currently unused
	EWFC_STR,
	EWFC_BLOB,
};

enum erf_comp {
	ERFC_INT,
	ERFC_REAL, //currently unused
	ERFC_STR,
	ERFC_BLOB,
};

//compatability matrix between read and write formats
//lines - write
//columns - read
extern u_char rw_comp_mat[_EWF_COUNT][_ERF_COUNT];
//array that determines compatability between entry
//write format and actual database supported types
extern enum ewf_comp wfc_arr[_EWF_COUNT];
//similar to above, but for data "on wire"
extern enum erf_comp rfc_arr[_ERF_COUNT];

enum entry_flags {
	EF_NONE = 0,
	EF_32BITW = 1 << 1,
	EF_PLD = 1 << 2,
	EF_OPT = 1 << 3,
};

struct entry_len {
	union {
		struct { //length given directly
			u_int length;
		} e_len_val;
		struct { //length as other entry's data
			char tag[TAG_LEN];
		} e_len_tag;
		struct { //length from current packet begining
			u_int length;
			char tag[TAG_LEN];
		} e_pac_off;
		struct { //length as other entry's data from current packet begining
			char start_tag[TAG_LEN];
			char offset_tag[TAG_LEN];
		} e_pac_off_tag;
		struct { //number of bits with offset from entry with given tag
			char tag[TAG_LEN];
			u_int offset;
			u_int nbits;
		} e_len_bits;
	} data;
	enum entry_len_tp type; //used to identify length calculation method
};

//length of current entry given directly
#define E_LEN(_length)                                                         \
	{                                                                          \
		.data = { .e_len_val = { .length = _length } }, .type = ELT_OFF        \
	}

//length of current entry's as other entry's data
#define E_LEN_OF(_tag)                                                         \
	{                                                                          \
		.data = { .e_len_tag = { .tag = _tag } }, .type = ELT_TAG              \
	}

//_length - total length from given packet's begining to current's end
#define E_PAC_OFF(_tag, _length)                                               \
	{                                                                          \
		.data = {															\
		.e_pac_off = { 														\
		.tag = _tag, 														\
		.length = _length, 													\
	},				  	   													\
	.type = ELT_PAC_OFF														\
	}

//current packet end is calculated from given "start" packet's begining with offset of "offset" packet's its data
#define E_PAC_OFF_OF(_start_tag, _offset_tag)                                  \
	{                                                                          \
		.data = {															\
		.e_pac_off_tag = { 													\
		.start_tag = _start_tag,											\
		.offset_tag = _offset_tag,											\
		}																	\
	},																		\
	.type = ELT_PAC_OFF_TAG                                              \
	}

//number of bits with offset from entry with given tag
#define E_BITS(_tag, _offset, _nbits)                                          \
	{                                                                          \
		.data = {															\
		.e_len_bits = {														\
		.tag = _tag,														\
		.offset = _offset,													\
		.nbits = _nbits,													\
		}																	\
	},																		\
		.type = ELT_FLAG                                              \
	}

struct f_entry { //packet field/entry
	char tag[TAG_LEN]; //globaly unique entry id
	enum entry_type type; //entry type
	struct entry_len len; //struct to define entry length
	enum entry_flags flags; //optional flags
	enum entry_read_format read_form; //data format (on wire)
	enum entry_write_format write_form; //data dump format
};

#define FILTER_LEN(arr)                                                        \
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
	u_int n_entries; //length of entries
};

struct p_entry { //struct to store individual packet entry data
	const char *tag; //tag for parent(lower level) packet
	long raw_len; //length of received entry
	u_char *raw_data; //pointer to allocated buffer with entry data
	long glob_bit_off; //global offset from root packet's begining in bits
	union {
		u_long ulong; //integer complient data to write
		double real; //floating point complient value to write
		u_char *string; //printable string value to write
		struct {
			u_char *arr; //binnary data itself
			u_long len; //length of binnary data
		} blob; //any binnary data to write
	} conv_data; //union of with entry data in write format
	enum ewf_comp
		wfc; //write datatype compatability. Also gives info which data is stored in "conv_data" union
	enum erf_comp rfc; //read datatype compatability
};

struct packet { //struct to store received and filtered packet data
	u_int id; //UID for received packet
	const char *parent_tag; //tag for parent(lower level) packet
	const char *packet_tag; //tag for current packet
	long e_len; //count of entry fields
	struct p_entry *entries; //array of entries
	long glob_bit_off; //global offset from root packet's begining in bits
};

#endif
