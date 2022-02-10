#ifndef H_REPORT
#define H_REPORT

#include "utils.h"

struct report {
	ulong received; //total amount of packets recived form pcap
	ulong skiped; //packets skiped because parent wasn't parsed
	ulong unconverted; //packets that filter to convert between formats
	ulong unsplit; //invalidated by 2-nd stage filter
	ulong invalid; //invalidated by 3-rd stage filter
	ulong truncated; //truncated do to too small SNAPLEN
	ulong parsed; //packets passed 3-rd stage filter
};

/**
 * @brief displays capture session report
 */
void report_all();

#endif
