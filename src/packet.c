
#include "../include/packet.h"
#include <stddef.h>
#include <string.h>


static status_val get_entry_length(struct ef_tree *node, struct f_entry *fe, struct p_entry *e) //TODO finish 
{
    switch (fe->len.type) {  //switching by entry length extraction method
    case ELT_TAG:
	LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n");	
	break;

    case ELT_OFF:
	e->raw_len = fe->len.data.e_len_val.length;
	break;
	
    case ELT_PAC_OFF:
	LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n");	
	break;
	
    case ELT_PAC_OFF_TAG:
	LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n");	
	break;

    case ELT_FLAG:
	e->in_bits = true;
	LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n");	
	break;

    default:
	LOGF(L_ERR, STATUS_BAD_INPUT, "Bad length type:%d for entry:%s\n", fe->len.type, fe->tag);	
	return STATUS_BAD_INPUT;
	break;
    }

    return STATUS_OK;
}

static status_val derive_entry(struct ef_tree *node, struct packet *p, struct f_entry *fe, struct p_entry *e, const u_char *data, size_t len, size_t *read_off) //TODO finish
{
    status_val status;

    e->tag = fe->tag;
    if (get_entry_length(node, fe, e)) { //getting data length of current entry
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
	    LOGF(L_NOTICE, STATUS_BAD_INPUT, "Packet:%d, faild to split as %s\n", p->id, p->packet_tag);
	    free(e);
	}
	
	memcpy(e->raw_data, data+(*read_off), e->raw_len); //extracting entry data
	*read_off += e->raw_len; //showing that data was succesfully read
	/*PRINT_HEX(data, e->raw_len);*/
	break;
    case ET_OFFSET:
	LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n");	
	return STATUS_NOT_FOUND;

	break;
    case ET_BITFIELD:
	LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n");	
	return STATUS_NOT_FOUND;

	break;
    case ET_FLAG:
	LOGM(L_ERR, STATUS_BAD_INPUT, "Not implemented\n");	
	return STATUS_NOT_FOUND;

	break;
    default:
	LOGF(L_ERR, STATUS_BAD_INPUT, "Bad type:%d for entry:%s\n", fe->type, fe->tag);	
	return STATUS_BAD_INPUT;
	break;
    }    

    if (rw_comp_mat[fe->write_form][fe->read_form] && converter_mat[fe->write_form][fe->read_form]) {
	status = converter_mat[fe->write_form][fe->read_form](e); //converting to write format
	if (status) {
	    LOGM(L_ERR, status, "Conversion from read to write format failed\n");
	    return status;
	}
	LOGF(L_DEBUG, STATUS_OK,"entry:%s data: %s\n", e->tag, e->conv_data);
    } 

    return STATUS_OK;
}

status_val derive_packet(struct packet **p_ptr, struct ef_tree *node, const u_char *data, size_t len, size_t *read_off)
{
    status_val status;
    
    struct packet *p = calloc(1, sizeof(struct packet));
    if (!p) {
	LOG(L_CRIT, STATUS_OMEM);
	return STATUS_OMEM;
    }

    p->id = pc.next_puid++; //assigning packet its UID, will be used for primary and foreign keys in data dump stage
    
    p->entries = calloc(node->flt->filter->n_entries, sizeof(struct p_entry));
    if (!p->entries) {
	LOG(L_CRIT, STATUS_OMEM);
	free(p);
	return STATUS_OMEM;
    }

    for (size_t i = 0; i < node->flt->filter->n_entries; i++) {
	//cutting and parsing entry
	status = derive_entry(node, p, &node->flt->filter->entries[i], &p->entries[i], data, len, read_off);
	if (status) {
	   LOGF(L_ERR, status, "Packet:%d failed to split\n", p->id);
	   packet_free(p);
	   return status;
	}
    }
    
    //adding tags to indicate position in hierarchy
    p->packet_tag = node->flt->filter->packet_tag; 
    p->parent_tag = node->flt->filter->parent_tag;
    p->status = P_SPLIT;//TODO is this needed

    *p_ptr = p;

    return STATUS_OK;
}


void packet_free(struct packet *p)
{
    if (p) {
	for (size_t i = 0; p->e_len; i++) {
	    free(p->entries[i].raw_data);
	    free(p->entries[i].conv_data);
	}
	free(p->entries);
	free(p);
    }
}
