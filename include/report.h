/**
 * @file report.h
 * @brief Description of capture statgistics interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef H_REPORT
#define H_REPORT

#include "utils.h"

/**
 * @brief Struct to store capture statistics
 */
struct report {
	ulong received; ///< 		Total amount of packets recived form pcap
	ulong skiped; ///< 			Packets skiped because parent wasn't parsed
	ulong unconverted; ///< 	Packets that filter to convert between formats
	ulong unsplit; ///< 		Invalidated by 2-nd stage filter
	ulong invalid; ///< 		Invalidated by 3-rd stage filter
	ulong truncated; ///< 		Truncated do to too small SNAPLEN
	ulong parsed; ///< 			Packets passed 3-rd stage filter
};

/**
 * @brief Displays capture session report
 * @return Void
 */
void report_all();

#endif
