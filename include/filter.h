/**
 * @file filter.h
 * @brief Main header file for end user to use. It contains 
 * definitions and declarations of most of macros, enums 
 * and structures used in user defined filters
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef H_FILTER
#define H_FILTER

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pcap.h>
#include <sys/types.h>

/** 
 * @brief Macro to get filtered packet entry
 * @params *node 	Extended filter tree node to start search upwards
 * @param *packet 	Current packet to include in search 
 * @param *tag 		Filter entry's tag to sarch for associated entry
 * @return Pointer to found filtered packet entry
 */
#define PENTRY(node, packet, tag)                                              \
	&packet->entries[fe_idx(node->flt->filter, tag)]

/** 
 * @brief Hints program to expect certain packet after this one
 * @params *_node 	Current extended filter tree node to set hint for
 * @param *_hint  	Tag of expected packet 
 */
#define HINT(_node, _hint) _node->flt->hint = _hint

/** 
 * @brief Types of entry length descriptions
 * @see entry_len
 */
enum entry_len_tp {
	ELT_TAG, ///< 			Length is value of another entry
	ELT_OFF, ///< 			Length is provided directly
	ELT_PAC_OFF, ///<		Length from another packet's beginning
	ELT_PAC_OFF_TAG, ///< 	Length of one entry's value from another packet's beginning
	ELT_UNKN, ///< 			Length is unknown
};

/** @brief Data format on wire(raw) */
enum entry_read_format {
	ERF_UINT_LE, ///< 	Unsigned little endian integer
	ERF_UINT_BE, ///< 	Unsigned big endian integer
	ERF_STR, ///< 		Printable string
	ERF_BIN, ///< 		Raw or unprintable binary data
	ERF_B64_STR, ///< 	Base64 endoded data
	_ERF_COUNT,
};

/** @brief Data format for validation and dumping */
enum entry_write_format {
	EWF_RAW, ///< 		Unchanged data
	EWF_DECODED, ///< 	Decoded data e.g from base64
	EWF_UINT, ///< 		Unsigned integer
	EWF_STR, ///< 		Printable string
	EWF_HEX_STR, ///< 	0x00 0x01 0x02 ... 0xff
	EWF_HEXDUMP, ///< 	00 01 02 ... ff
	EWF_HEX_DT, ///< 	00.01.02 ... .ff i.e. MAC address format
	EWF_DEC_DT, ///< 	0.1.2. ... .255  i.e. IP address format
	EWF_B64_STR, ///< 	Base64 endoded string
	_EWF_COUNT,
};

/** @brief Primitive write types for dumping */
enum ewf_comp {
	EWFC_NONE, ///< 	Empty, do not dum
	EWFC_INT, ///< 		Integer
	EWFC_REAL, ///< 	Real/float
	EWFC_STR, ///< 		String
	EWFC_BLOB, ///< 	Blob/binary data
};

/** @brief Misc flags for filter entry */
enum entry_flags {
	EF_NONE = 0, ///< 		Does not mean anything
	EF_DUB = 1 << 1, ///< 	Doesn't increase global read offset when parsing
	EF_NOWRT = 1 << 2, ///< Does not dump this field
	EF_PLD = 1 << 3, ///< 	Payload field
	EF_PLD_REG = EF_DUB | EF_NOWRT | EF_PLD, ///< Regular payload field
	EF_OPT = 1 << 4, ///< 	Optional field
};

/** @brief Validation/third statge result */
typedef enum {
	VLD_DROP_ALL, ///< 	Drops all filtered packets in current capture
	VLD_DROP, ///< 		Drops curent packet and potential children packets
	VLD_PASS, ///< 		Vlidation was passed
} vld_status;

/**
 * @brief Compatability matrix between read and write formats.
 * Must match converter_mat
 * lines - Write format
 * columns - Read format
 * @see converter_mat
 */
extern u_char rw_comp_mat[_EWF_COUNT][_ERF_COUNT];

/**
 * @brief Array that determines compatability between entry
 * write format and actual database supported types
 */
extern enum ewf_comp wfc_arr[_EWF_COUNT];

/**
 * @brief Struct to desccribe how entry's length has to be calculated
 * @see entry_len_tp
 */
struct entry_len {
	union {
		struct {
			u_int length;
		} e_len_val; ///< 		Length given directly
		struct {
			char tag[DEVEL_TAG_LEN];
		} e_len_tag; ///< 		Length as other entry's data
		struct {
			u_int length;
			char tag[DEVEL_TAG_LEN];
		} e_pac_off; ///< 		Length from current packet begining
		struct {
			char start_tag[DEVEL_TAG_LEN];
			char offset_tag[DEVEL_TAG_LEN];
		} e_pac_off_tag; ///< 	Length as other entry's data from current packet begining
	} data;
	enum entry_len_tp type; ///< Used to identify length calculation method
};

/**
 * @brief Length of current entry given directly
 * @param[in] _length Length or entry
 * @see ELT_OFF
 */
#define E_LEN(_length)                                                         \
	{                                                                          \
		.data = { .e_len_val = { .length = _length } }, .type = ELT_OFF        \
	}

/**
 * @brief Length of current entry's as other entry's data
 * @param[in] *_tag Target entry's tag
 * @see ELT_OFF
 */
#define E_LEN_OF(_tag)                                                         \
	{                                                                          \
		.data = { .e_len_tag = { .tag = _tag } }, .type = ELT_TAG              \
	}

/**
 * @brief Length is calculated from given packet's begining to current's end
 * @param[in] *_tag Target entry's tag
 * @param[in] _length Length from target entry's beginning
 * @see ELT_PAC_OFF
 */
#define E_PAC_OFF(_tag, _length)                                               \
	{                                                                          \
		.data = {															\
		.e_pac_off = { 														\
		.tag = _tag, 														\
		.length = _length, 													\
	},				  	   													\
	.type = ELT_PAC_OFF														\
	}

/**
 * @brief Current packet end is calculated from given "start" packet's 
 * begining with offset of "offset" packet's data value
 * @param[in] *_start_tag Tag to start offset from
 * @param[in] *_offset_tag Offset entry's tag
 * @see
 */
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

/**
 * @brief Length is unknown
 * @see ELT_UNKN
 */
#define E_UNKN                                                                 \
	{                                                                          \
		.type = ELT_UNKN                                                       \
	}

/**
 * @brief Staticly user definable filter's entry.
 * It is used to describe and cut out data.
 */
struct f_entry {
	char tag[DEVEL_TAG_LEN]; ///< 				Globaly unique filters entry's id
	struct entry_len len; ///< 					Struct to define entry length
	u_int len_mul; ///< 						Calculated lenth multiplier
	enum entry_flags flags; ///< 				Optional flags
	enum entry_read_format read_form; ///< 		Data format (on wire)
	enum entry_write_format write_form; ///< 	Data dump format
};

/** @brief Gets Length of filter in static context*/
#define FILTER_LEN(arr) sizeof arr / sizeof(struct f_entry)

/**
 * @brief Staticly user definable filter. It contains filter entries and
 * callback functions to be called at certain time in capture.
 */
struct filter {
	/** Tag for parent(lower level) packet */
	char parent_tag[DEVEL_TAG_LEN];
	/** Tag for current packet */
	char packet_tag[DEVEL_TAG_LEN];
	/** Function to be called when filter tree is built
	 * may be used to create user object or whatever */
	void (*init_filter)();
	/** Function to be called when progrem ins intermination process
	 * may be used to free user object or whatever */
	void (*exit_filter)();
	/** Function to be called before filter is applied */
	void (*itc_capture)(u_char *, const struct pcap_pkthdr *, const u_char *);
	/** Function to be called after filter is applied(for filtered packets) */
	void (*itc_dump)();
	/** Packet validation function, can be used for low level filtering */
	vld_status (*validate)();
	/** Array of packet field entries */
	struct f_entry *entries;
	/** Length of entries */
	u_int n_entries;
	/** Pointer to user data/object. If `usr` has dynamicly allocated 
	 * conponents, they should not depend on other filters' `usr` 
	 * data as `init_filter` and `exit_filter`. Calling sequence 
	 * is undefined */
	void *usr;
};

/** @brief Struct to store individual filtered packet entry's data */
struct p_entry {
	const char *tag; ///< 		Tag for parent(lower level) packet
	long raw_len; ///< 			Length of received entry
	u_char *raw_data; ///< 		Pointer to allocated buffer with entry data
	long glob_bit_off; //< 		Global offset from root packet's begining in bits
	union {
		u_long ulong; ///< 		Integer complient data to write
		double real; ///< 		Floating point complient value to write
		char *string; ///< 		Printable string value to write
		struct {
			u_char *arr; ///< 	Binary data itself
			u_long len; ///< 	Length of binnary data
		} blob; ///< 			Any binary data to write
	} conv_data; ///< 			Union of with entry data in write format
	/** Write datatype compatability. Also gives 
	 * info which data is stored in "conv_data" union */
	enum ewf_comp wfc;
};

/** @brief Filtered packet's data */
struct packet { ///< 				Struct to store received and filtered packet data
	u_int id; ///< 					UID for received packet
	const char *parent_tag; ///< 	Tag for parent(lower level) packet
	const char *packet_tag; ///< 	Tag for current packet
	long e_len; ///< 				Count of entry fields
	struct p_entry *entries; ///< 	Array of entries
	long glob_bit_off; ///< 		Global offset from root packet's begining in bits
};

/**
 * @brief Cretes new extended filter with filter
 * @param[in] *f 	Filter to query
 * @param[in] *tag 	Filter entry's tag
 * @return Index of filter entry, -1 otherwise
 */
int fe_idx(struct filter *f, const char *tag);

#endif
