
#include <pcap/pcap.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <pcap.h>

#include "../include/glist.h"
#include "../include/filter.h"
#include "../include/fhmap.h"
#include "../include/ext_filter.h"
#include "../include/ef_tree.h"
#include "../include/converter.h"
#include "../include/pkt_list.h"
#include "../include/packet.h"

/**
 * @brief Copies bits from src to packets raw_data field
 * @param e destination packet struct to copy data to
 * @param src data source
 * @param bit_off bit offset to start read from
 * @param n_bits number of bits to copy
 */
static void copy_bits(struct p_entry *e, const u_char *src, unsigned bit_off,
					  unsigned n_bits)
{
	unsigned wb_off = BYTOBI(BITOBY(e->raw_len)) - n_bits;
	u_char r_byte, r_bit, w_byte, w_bit, bit_num;
	u_char dt_bit;

	for (unsigned i = 0; i < n_bits; i++) {
		r_byte = (bit_off + i) >> 3;
		bit_num = 7 - ((bit_off + i) & BITS(3));
		r_bit = BIT(bit_num);
		w_byte = (wb_off + i) >> 3;
		bit_num = 7 - ((wb_off + i) & BITS(3));
		w_bit = BIT(bit_num);

		//checking if read bit is 1 or 0
		dt_bit = !!(src[r_byte] & r_bit);

		if (dt_bit) {
			//if read bit is 1, then oring write bit with dest.
			e->raw_data[w_byte] |= w_bit;
		}
	}
	//TODO optinization needed
}

/**
 * @brief Finds length of packet's entry struct
 * @param pkt_list generic list that contains already parsed packets from data
 * @param fe filter entry to derive packet's entry form
 * @param e pointer to packet entry's to return
 * @param read_off pointer pointed to current read position in 'data'
 * @return status wether packet entry's length ware parsed succesfully
 */
static status_val get_entry_length(struct glist *pkt_list, struct f_entry *fe,
								   struct packet *p, struct p_entry *e,
								   u_int *read_off)
{
	status_val status;
	struct p_entry *pe;
	struct f_entry *ref_fe;
	u_long len = 0;

	switch (fe->len.type) { //switching by entry length extraction method
	case ELT_TAG:
		if (!(pe = get_packet_entry_by_tag2(pkt_list, p, fe->tag)) ||
			pe->wfc != EWFC_INT) {
			LOG(L_ERR, STATUS_BAD_INPUT);
			return STATUS_BAD_INPUT;
		}

		e->raw_len = pe->conv_data.ulong * fe->len_mul;
		break;

	case ELT_OFF:
		e->raw_len = fe->len.data.e_len_val.length * fe->len_mul;
		break;

	case ELT_PAC_OFF: //TODO never tested
		len = fe->len.data.e_pac_off.length * fe->len_mul;

		//getting previous parssed entry with start position info
		if (!(pe = get_packet_entry_by_tag2(pkt_list, p,
											fe->len.data.e_pac_off.tag))) {
			LOG(L_ERR, STATUS_BAD_INPUT);
			return STATUS_BAD_INPUT;
		}

		if (*read_off > (long)len + pe->glob_bit_off) {
			LOGM(L_NOTICE, STATUS_BAD_INPUT, "Packet is longer than expected");
			return STATUS_BAD_INPUT;
		}

		e->raw_len = (long)len + pe->glob_bit_off - *read_off;

		break;

	case ELT_PAC_OFF_TAG:
		//getting previous parsed entry with offset info and retreiving its data as uint
		if (!(pe = get_packet_entry_by_tag2(
				  pkt_list, p, fe->len.data.e_pac_off_tag.offset_tag)) ||
			pe->wfc != EWFC_INT) {
			LOG(L_ERR, STATUS_BAD_INPUT);
			return STATUS_BAD_INPUT;
		}

		len = pe->conv_data.ulong * fe->len_mul;

		//getting previous parssed entry with start position info
		if (!(pe = get_packet_entry_by_tag2(
				  pkt_list, p, fe->len.data.e_pac_off_tag.start_tag))) {
			LOG(L_ERR, STATUS_BAD_INPUT);
			return STATUS_BAD_INPUT;
		}

		//retreiving offset filter entry
		if ((status =
				 fhmap_get(pc.f_entries, fe->len.data.e_pac_off_tag.offset_tag,
						   &ref_fe))) {
			LOGM(L_NOTICE, STATUS_BAD_INPUT, "Packet is longer than expected");
			return STATUS_BAD_INPUT;
		}

		if (*read_off > (long)len + pe->glob_bit_off) {
			LOGM(L_NOTICE, STATUS_BAD_INPUT, "Packet is longer than expected");
			return STATUS_BAD_INPUT;
		}

		e->raw_len = (long)len + pe->glob_bit_off - *read_off;
		break;

	default:
		LOGF(L_ERR, STATUS_BAD_INPUT, "Bad length type:%d for entry:%s\n",
			 fe->len.type, fe->tag);
		return STATUS_BAD_INPUT;
		break;
	}

	return STATUS_OK;
}

/**
 * @brief Builds packet entry struct based on filter entry and fills it
 * with supplied data. 
 * @param node extended filter node associated with current filter
 * @param pkt_list generic list that contains already parsed packets from data
 * @param fe filter entry to derive packet's entry form
 * @param e pointer to packet entry's to return
 * @param data captured packet data
 * @param header capture header/metadata
 * @param read_off pointer pointed to current read position in 'data'
 * @return status wether packet entry were parsed succesfully
 */
static status_val derive_entry(struct ef_tree *node, struct glist *pkt_list,
							   struct packet *p, struct f_entry *fe,
							   struct p_entry *e, const u_char *data,
							   const struct pcap_pkthdr *header,
							   u_int *read_off)
{
	status_val status;

	e->tag = fe->tag;

	//If field length is unknown it can not be parsed at this abstraction level
	if (fe->len.type == ELT_UNKN) {
		return STATUS_OK;
	}

	//getting data length of current entry
	if (get_entry_length(pkt_list, fe, p, e, read_off)) {
		LOG(L_ERR, STATUS_ERROR);
		return STATUS_ERROR;
	}

	// for regular payload field
	if ((fe->flags & EF_PLD_REG) == EF_PLD_REG) {
		u_int read = *read_off + e->raw_len;
		//captured packet is not long enough
		if (BITOBY(read) > header->caplen) {
			if (BITOBY(read) <= header->len) {
				LOGF(
					L_DEBUG, STATUS_BAD_INPUT,
					"Faild to split %s %s, packet is longer - %d (%d bits) than SNAPLEN(%d)\n",
					p->packet_tag, fe->tag, BITOBY(read), read, DEF_SNAPLEN);
				node->flt->rep.truncated++;
				return STATUS_OK;
			}

			LOGF(
				L_NOTICE, STATUS_BAD_INPUT,
				"Faild to split %s %s, too long - %d (%d bits), then possible(%d) probably bad filter\n",
				p->packet_tag, fe->tag, BITOBY(read), read, header->len);
			return STATUS_BAD_INPUT;
		}

		return STATUS_OK;
	}

	e->raw_data = calloc(BITOBY(e->raw_len) + 1, sizeof(u_char));
	if (!e->raw_data) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	u_int read = *read_off + e->raw_len;
	if (BITOBY(read) > header->caplen) { //captured packet is not long enough
		if (BITOBY(read) <= header->len) {
			LOGF(
				L_DEBUG, STATUS_BAD_INPUT,
				"Faild to split %s %s, packet is longer - %d (%d bits) than SNAPLEN(%d)\n",
				p->packet_tag, fe->tag, BITOBY(read), read, DEF_SNAPLEN);
			node->flt->rep.truncated++;
			free(e->raw_data);
			return STATUS_OK;
		}

		LOGF(
			L_NOTICE, STATUS_BAD_INPUT,
			"Faild to split %s %s, too long - %d (%d bits), then possible(%d) probably bad filter\n",
			p->packet_tag, fe->tag, BITOBY(read), read, header->len);
		free(e->raw_data);
		return STATUS_BAD_INPUT;
	}

	//extracting entry data
	copy_bits(e, ((u_char *)data) + BYWHO(*read_off), BIREM(*read_off),
			  e->raw_len);

	e->glob_bit_off = *read_off;

	if (!(fe->flags & EF_DUB)) {
		*read_off += e->raw_len; //showing that data was succesfully read
	}

	if (fe->flags & EF_NOWRT) {
		e->wfc = EWFC_NONE;
	} else {
		e->wfc = wfc_arr[fe->write_form];
	}

	e->rfc = rfc_arr[fe->read_form];

	if (rw_comp_mat[fe->write_form][fe->read_form] &&
		converter_mat[fe->write_form][fe->read_form]) {
		//converting to write format
		status = converter_mat[fe->write_form][fe->read_form](e);
		if (status) {
			LOGM(L_ERR, status,
				 "Conversion from read to write format failed\n");
			node->flt->rep.unconverted++;
			return status;
		}
	}

	if (pc.verbosity >= L_DEBUG && !(fe->flags & EF_PLD)) {
		LOGF(L_DEBUG, STATUS_OK, "entry:%s", e->tag);
		PRINT_HEX(e->raw_data, BITOBY(e->raw_len));
	}

	return STATUS_OK;
}

status_val derive_packet(struct glist *pkt_list, struct ef_tree *node,
						 const u_char *data, const struct pcap_pkthdr *header,
						 u_int *read_off, struct packet **pkt_ptr)
{
	status_val status;
	struct filter *nf = node->flt->filter;

	node->flt->rep.received++;

	struct packet *p = calloc(1, sizeof(struct packet));
	if (!p) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	*pkt_ptr = p;

	//assigning packet its ID, will be used for primary and foreign keys in data dump stage
	//all parent and children packets will have same pid
	p->id = pc.next_pid;
	p->glob_bit_off = *read_off;

	//adding tags to indicate position in hierarchy
	p->packet_tag = nf->packet_tag;
	p->parent_tag = nf->parent_tag;

	p->entries = calloc(nf->n_entries, sizeof(struct p_entry));
	if (!p->entries) {
		LOG(L_CRIT, STATUS_OMEM);
		free(p);
		return STATUS_OMEM;
	}

	for (u_int i = 0; i < nf->n_entries; i++) {
		if (BITOBY(*read_off) <= header->caplen) {
			//cutting and parsing entry
			status = derive_entry(node, pkt_list, p, &nf->entries[i],
								  &p->entries[i], data, header, read_off);
			if (status) {
				LOGF(L_NOTICE, status, "Packet:%s(%d) failed to split\n",
					 nf->entries[i].tag, p->id);
				packet_free(p);
				return status;
			}

			p->e_len++;
		} else if (nf->entries[i].flags & EF_OPT) {
			//faking empty optional entry

			p->e_len++;
		} else if (!(nf->entries[i].flags & EF_NOWRT)) {
			//error if we still have required unparsed fields
			LOGF(L_NOTICE, STATUS_ERROR, "Unparsed required field:%s\n",
				 nf->entries[i].tag);
			return STATUS_ERROR;
		}
	}

	return STATUS_OK;
}

void packet_free(struct packet *p)
{
	if (p) {
		struct p_entry *pe;
		for (u_int i = 0; i < p->e_len; i++) {
			pe = &p->entries[i];
			//if raw_data and converted data (string/blob) is the same memory addres.
			//this may be done to save memory.
			if (pe->raw_data && pe->wfc == EWFC_STR &&
				pe->raw_data == (u_char *)pe->conv_data.string) {
				free(pe->raw_data);
			} else if (pe->raw_data && pe->wfc == EWFC_BLOB &&
					   pe->raw_data == pe->conv_data.blob.arr) {
				free(pe->raw_data);
			} else { // no shenanigans
				if (pe->raw_data) {
					free(pe->raw_data);
				}

				if (pe->wfc == EWFC_STR && pe->conv_data.string) {
					free(pe->conv_data.string);
				}

				if (pe->wfc == EWFC_BLOB && pe->conv_data.blob.arr) {
					free(pe->conv_data.blob.arr);
				}
			}
		}

		free(p->entries);
		free(p);
	}
}
