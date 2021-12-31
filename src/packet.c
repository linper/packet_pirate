
#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#include "../include/glist.h"
#include "../include/filter.h"
#include "../include/fhmap.h"
#include "../include/ext_filter.h"
#include "../include/ef_tree.h"
#include "../include/converter.h"
#include "../include/packet.h"

static u_int get_off_multiplier(struct f_entry *fe)
{
	if (fe->flags & EF_32BITW) {
		return 4;
	} else {
		return 1;
	}
}

static struct p_entry *packet_get_entry(struct glist *pkt_list,
										struct packet *pac, const char *tag)
{
	void *e;
	struct packet *p;

	p = pac;
	for (unsigned i = 0; i < p->e_len; i++) {
		if (!strcmp(p->entries[i].tag, tag)) {
			return &p->entries[i];
		}
	}

	//searching in already parsed packets
	glist_foreach (e, pkt_list) {
		p = (struct packet *)e;
		for (unsigned i = 0; i < p->e_len; i++) {
			if (!strcmp(p->entries[i].tag, tag)) {
				return &p->entries[i];
			}
		}
	}

	return NULL;
}

static void copy_bits(struct p_entry *e, u_char *src, unsigned bit_off,
					  unsigned n_bits)
{
	unsigned wb_off = 8 * e->raw_len - n_bits;
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
}

static status_val get_entry_length(struct glist *pkt_list, struct f_entry *fe,
								   struct packet *p, struct p_entry *e,
								   u_int *read_off)
{
	status_val status;
	struct p_entry *pe;
	struct f_entry *ref_fe;
	u_long len = 0;
	u_int mul = 1;

	switch (fe->len.type) { //switching by entry length extraction method
	case ELT_TAG:
		if (!(pe = packet_get_entry(pkt_list, p, fe->tag)) ||
			bytes_to_uint(pe->raw_data, pe->raw_len,
						  (unsigned long *)&e->raw_len) ||
			pe->rfc != ERFC_INT) {
			LOG(L_ERR, STATUS_BAD_INPUT);
			return STATUS_BAD_INPUT;
		}

		break;

	case ELT_OFF:
		e->raw_len = fe->len.data.e_len_val.length;
		break;

	case ELT_PAC_OFF: //TODO never tested
		len = fe->len.data.e_pac_off.length;

		//getting previous parssed entry with start position info
		if (!(pe = packet_get_entry(pkt_list, p, fe->len.data.e_pac_off.tag))) {
			LOG(L_ERR, STATUS_BAD_INPUT);
			return STATUS_BAD_INPUT;
		}

		if (*read_off > (long)len + pe->glob_bit_off / 8) {
			LOGM(L_NOTICE, STATUS_BAD_INPUT, "Packet is longer than expected");
			return STATUS_BAD_INPUT;
		}

		e->raw_len = (long)len + pe->glob_bit_off / 8 - *read_off;

		break;

	case ELT_PAC_OFF_TAG:
		//getting previous parsed entry with offset info and retreiving its data as uint
		if (!(pe = packet_get_entry(pkt_list, p,
									fe->len.data.e_pac_off_tag.offset_tag)) ||
			bytes_to_uint(pe->raw_data, pe->raw_len, &len) ||
			pe->rfc != ERFC_INT) {
			LOG(L_ERR, STATUS_BAD_INPUT);
			return STATUS_BAD_INPUT;
		}

		//getting previous parssed entry with start position info
		if (!(pe = packet_get_entry(pkt_list, p,
									fe->len.data.e_pac_off_tag.start_tag))) {
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

		//retreiving length nultiplier from offset filter entry
		mul = get_off_multiplier(ref_fe);

		if (*read_off > mul * (long)len + pe->glob_bit_off / 8) {
			LOGM(L_NOTICE, STATUS_BAD_INPUT, "Packet is longer than expected");
			return STATUS_BAD_INPUT;
		}

		e->raw_len = mul * (long)len + pe->glob_bit_off / 8 - *read_off;
		break;

	case ELT_FLAG: //this is basicaly pointless
		e->raw_len = (fe->len.data.e_len_bits.nbits - 1) / 8 + 1;
		break;

	default:
		LOGF(L_ERR, STATUS_BAD_INPUT, "Bad length type:%d for entry:%s\n",
			 fe->len.type, fe->tag);
		return STATUS_BAD_INPUT;
		break;
	}

	return STATUS_OK;
}

static status_val derive_entry(struct glist *pkt_list, struct packet *p,
							   struct f_entry *fe, struct p_entry *e,
							   const u_char *data, u_int len, u_int *read_off)
{
	status_val status;
	struct p_entry *ref_entry;

	e->tag = fe->tag;
	//getting data length of current entry
	if (get_entry_length(pkt_list, fe, p, e, read_off)) {
		LOG(L_ERR, STATUS_ERROR);
		return STATUS_ERROR;
	}

	switch (fe->type) { //switching by entry data format category
	case ET_DATAFIELD:
	case ET_BITFIELD:
		e->raw_data = calloc(e->raw_len + 1, sizeof(u_char));
		if (!e->raw_data) {
			LOG(L_CRIT, STATUS_OMEM);
			return STATUS_OMEM;
		}

		if (*read_off + e->raw_len > len) { //captured packet is not long enough
			LOGF(L_NOTICE, STATUS_BAD_INPUT,
				 "Packet:%d, faild to split as %s\n", p->id, p->packet_tag);
			free(e->raw_data);
			return STATUS_BAD_INPUT;
		}

		//extracting entry data
		memcpy(e->raw_data, data + (*read_off), e->raw_len);
		e->glob_bit_off = *read_off * 8;
		*read_off += e->raw_len; //showing that data was succesfully read
		e->wfc = wfc_arr[fe->write_form];
		e->rfc = rfc_arr[fe->read_form];
		break;
	case ET_FLAG:
		ref_entry = packet_get_entry(pkt_list, p, fe->len.data.e_len_bits.tag);
		if (!ref_entry) {
			LOGF(L_CRIT, STATUS_NOT_FOUND,
				 "Filter entry with tag: \"%s\" not found.",
				 fe->len.data.e_len_bits.tag);
			return STATUS_NOT_FOUND;
		}

		e->raw_data = calloc(e->raw_len + 1, sizeof(u_char));
		if (!e->raw_data) {
			LOG(L_CRIT, STATUS_OMEM);
			return STATUS_OMEM;
		}

		copy_bits(e, ref_entry->raw_data, fe->len.data.e_len_bits.offset,
				  fe->len.data.e_len_bits.nbits);

		e->glob_bit_off = *read_off * 8 + fe->len.data.e_len_bits.offset;
		e->wfc = wfc_arr[fe->write_form];
		e->rfc = rfc_arr[fe->read_form];

		break;
	default:
		LOGF(L_ERR, STATUS_BAD_INPUT, "Bad type:%d for entry:%s\n", fe->type,
			 fe->tag);
		return STATUS_BAD_INPUT;
		break;
	}

	if (rw_comp_mat[fe->write_form][fe->read_form] &&
		converter_mat[fe->write_form][fe->read_form]) {
		//converting to write format
		status = converter_mat[fe->write_form][fe->read_form](e);
		if (status) {
			LOGM(L_ERR, status,
				 "Conversion from read to write format failed\n");
			return status;
		}
		LOGF(L_DEBUG, STATUS_OK, "entry:%s", e->tag);
		/*PRINT_HEX(e->raw_data, e->raw_len);*/
	}

	return STATUS_OK;
}

status_val derive_packet(struct glist *pkt_list, struct ef_tree *node,
						 const u_char *data, u_int len, u_int *read_off)
{
	status_val status;
	struct filter *nf = node->flt->filter;

	struct packet *p = calloc(1, sizeof(struct packet));
	if (!p) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	//assigning packet its ID, will be used for primary and foreign keys in data dump stage
	//all parent and children packets will have same pid
	p->id = pc.next_pid;
	p->glob_bit_off = *read_off * 8;
	p->entries = calloc(nf->n_entries, sizeof(struct p_entry));
	if (!p->entries) {
		LOG(L_CRIT, STATUS_OMEM);
		free(p);
		return STATUS_OMEM;
	}

	for (u_int i = 0; i < nf->n_entries; i++) {
		//cutting and parsing entry
		status = derive_entry(pkt_list, p, &nf->entries[i], &p->entries[i],
							  data, len, read_off);
		if (status) {
			LOGF(L_ERR, status, "Packet:%d failed to split\n", p->id);
			packet_free(p);
			return status;
		}
		p->e_len++;
	}

	//adding tags to indicate position in hierarchy
	p->packet_tag = nf->packet_tag;
	p->parent_tag = nf->parent_tag;

	status = glist_push(pkt_list, p); //appending packet to packet list;
	if (status) {
		LOG(L_ERR, status);
		packet_free(p);
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
				pe->raw_data == pe->conv_data.string) {
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
