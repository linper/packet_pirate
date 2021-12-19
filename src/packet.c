
#include "../include/packet.h"
#include <stddef.h>
#include <string.h>

static status_val packet_get_entry(struct packet *p, const char *tag,
								   struct p_entry **e)
{
	for (unsigned i = 0; i < p->e_len; i++) {
		if (!strcmp(p->entries[i].tag, tag)) {
			*e = &p->entries[i];
			return STATUS_OK;
		}
	}

	return STATUS_NOT_FOUND;
}

static status_val get_entry_length(struct glist *pkt_list, struct ef_tree *node,
								   struct f_entry *fe,
								   struct p_entry *e) //TODO finish
{
	void *p;
	struct p_entry *pe;
	switch (fe->len.type) { //switching by entry length extraction method
	case ELT_TAG:
		glist_foreach(p, pkt_list)
		{
			if (!packet_get_entry((struct packet *)p, fe->tag, &pe) &&
				bytes_to_uint(pe->raw_data, pe->raw_len,
							  (unsigned long *)&e->raw_len)) {
				LOG(L_ERR, STATUS_BAD_INPUT);
				return STATUS_BAD_INPUT;
			}
		}
		break;

	case ELT_OFF:
		e->raw_len = fe->len.data.e_len_val.length;
		break;

	case ELT_PAC_OFF:
		LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n"); //TODO
		break;

	case ELT_PAC_OFF_TAG:
		LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n"); //TODO
		break;

	case ELT_FLAG:
		e->in_bits = true;
		LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n"); //TODO
		break;

	default:
		LOGF(L_ERR, STATUS_BAD_INPUT, "Bad length type:%d for entry:%s\n",
			 fe->len.type, fe->tag);
		return STATUS_BAD_INPUT;
		break;
	}

	return STATUS_OK;
}

static status_val derive_entry(struct glist *pkt_list, struct ef_tree *node,
							   struct packet *p, struct f_entry *fe,
							   struct p_entry *e, const u_char *data,
							   unsigned len, unsigned *read_off) //TODO finish
{
	status_val status;

	e->tag = fe->tag;
	//getting data length of current entry
	if (get_entry_length(pkt_list, node, fe, e)) {
		free(e);
		LOG(L_ERR, STATUS_ERROR);
		return STATUS_ERROR;
	}

	switch (fe->type) { //switching by entry data format category
	case ET_DATA:
		e->raw_data = calloc(e->raw_len + 1, sizeof(u_char));
		if (!e->raw_data) {
			free(e);
			LOG(L_CRIT, STATUS_OMEM);
			return STATUS_OMEM;
		}

		if (*read_off + e->raw_len > len) { //captured packet is not long enough
			LOGF(L_NOTICE, STATUS_BAD_INPUT,
				 "Packet:%d, faild to split as %s\n", p->id, p->packet_tag);
			free(e);
		}

		//extracting entry data
		memcpy(e->raw_data, data + (*read_off), e->raw_len);
		*read_off += e->raw_len; //showing that data was succesfully read
		/*PRINT_HEX(data, e->raw_len);*/
		break;
	case ET_OFFSET:
		LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n"); //TODO
		return STATUS_NOT_FOUND;

		break;
	case ET_BITFIELD:
		LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n"); //TODO
		return STATUS_NOT_FOUND;

		break;
	case ET_FLAG:
		LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n"); //TODO
		return STATUS_NOT_FOUND;

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
		LOGF(L_DEBUG, STATUS_OK, "entry:%s data: %s\n", e->tag, e->conv_data);
	}

	return STATUS_OK;
}

status_val derive_packet(struct glist *pkt_list, struct ef_tree *node,
						 const u_char *data, unsigned len, unsigned *read_off)
{
	status_val status;

	struct packet *p = calloc(1, sizeof(struct packet));
	if (!p) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	p->id =
		pc.next_puid++; //assigning packet its UID, will be used for primary and foreign keys in data dump stage

	p->entries = calloc(node->flt->filter->n_entries, sizeof(struct p_entry));
	if (!p->entries) {
		LOG(L_CRIT, STATUS_OMEM);
		free(p);
		return STATUS_OMEM;
	}

	for (unsigned i = 0; i < node->flt->filter->n_entries; i++) {
		//cutting and parsing entry
		status = derive_entry(pkt_list, node, p, &node->flt->filter->entries[i],
							  &p->entries[i], data, len, read_off);
		if (status) {
			LOGF(L_ERR, status, "Packet:%d failed to split\n", p->id);
			packet_free(p);
			return status;
		}
	}

	//adding tags to indicate position in hierarchy
	p->packet_tag = node->flt->filter->packet_tag;
	p->parent_tag = node->flt->filter->parent_tag;

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
		for (unsigned i = 0; p->e_len; i++) {
			free(p->entries[i].raw_data);
			free(p->entries[i].conv_data);
		}
		free(p->entries);
		free(p);
	}
}
