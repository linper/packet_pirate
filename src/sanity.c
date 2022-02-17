
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <ctype.h>

#include "../include/filter.h"
#include "../include/converter.h"
#include "../include/fhmap.h"
#include "../include/glist.h"
#include "../include/sanity.h"

static status_val check_filter_entry(struct filter *f, struct f_entry *fe)
{
	status_val status = STATUS_OK;

	if (fe->tag[TAG_LEN - 1]) {
		LOGF(L_CRIT, STATUS_ERROR,
			 "Filter has entry with tag:%s that is too long. Max:%d", fe->tag,
			 TAG_LEN - 1);
		status = STATUS_ERROR;
	}

	for (unsigned i = 0; i < strlen(fe->tag); i++) {
		if (!isprint((int)fe->tag[i])) {
			LOGF(L_CRIT, STATUS_ERROR,
				 "Unprintable characters in filter entry' tag:%s", fe->tag);
			status = STATUS_ERROR;
		}
	}

	if (!fe->tag[0]) {
		LOGF(L_CRIT, STATUS_ERROR, "Filter:%s has entry with empty tag",
			 f->packet_tag);
		status = STATUS_ERROR;
	}

	struct f_entry *pfe;

	switch (fe->len.type) {
	case ELT_TAG:
		if (fhmap_get(pc.f_entries, fe->len.data.e_len_tag.tag, &pfe)) {
			LOGF(L_CRIT, STATUS_ERROR, "Filter entry:%s does not exist",
				 fe->len.data.e_len_tag.tag);
			status = STATUS_ERROR;
		}

		if (wfc_arr[pfe->write_form] != EWFC_INT) {
			LOGF(L_CRIT, STATUS_ERROR,
				 "Filter entry's:%s write format is incompatible with INT type",
				 pfe->tag);
			status = STATUS_ERROR;
		}
		break;

	case ELT_PAC_OFF_TAG:
		if (fhmap_get(pc.f_entries, fe->len.data.e_pac_off_tag.offset_tag,
					  &pfe)) {
			LOGF(L_CRIT, STATUS_ERROR, "Filter entry:%s does not exist",
				 fe->len.data.e_pac_off_tag.offset_tag);
			status = STATUS_ERROR;
		}

		if (wfc_arr[pfe->write_form] != EWFC_INT) {
			LOGF(L_CRIT, STATUS_ERROR,
				 "Filter entry's:%s write format is incompatible with INT type",
				 pfe->tag);
			status = STATUS_ERROR;
		}
		break;

	case ELT_UNKN:
		if (!(fe->flags & EF_PLD)) {
			LOGF(L_CRIT, STATUS_ERROR,
				 "Not payload entry:%s is marked as unknown length", fe->tag);
			status = STATUS_ERROR;
		}
		break;

	default:
		break;
	}

	if (fe->len.type == ELT_UNKN && !(fe->flags & EF_PLD)) {
		LOGF(L_CRIT, STATUS_ERROR,
			 "Not payload entry:%s is marked as unknown length", fe->tag);
		status = STATUS_ERROR;
	}

	if ((fe->flags & EF_PLD) && &f->entries[f->n_entries - 1] != fe) {
		LOGF(L_CRIT, STATUS_ERROR, "Payload entry:%s is not last", fe->tag);
		status = STATUS_ERROR;
	}

	return status;
}

static status_val check_filter()
{
	status_val status = STATUS_OK;

	struct filter *f;
	glist_foreach (void *e, pc.f_reg) {
		f = (struct filter *)e;

		if (!f->n_entries) {
			LOGF(L_CRIT, STATUS_ERROR, "Filter:%s has no entries",
				 f->packet_tag);
			status = STATUS_ERROR;
		}

		if (f->packet_tag[TAG_LEN - 1]) {
			LOGF(L_CRIT, STATUS_ERROR,
				 "Filter's packet_tag: %s is too long. Max:%d", f->packet_tag,
				 TAG_LEN - 1);
			status = STATUS_ERROR;
		}

		for (unsigned i = 0; i < strlen(f->packet_tag); i++) {
			if (!isprint((int)f->packet_tag[i])) {
				LOGF(L_CRIT, STATUS_ERROR,
					 "Unprintable characters in filter's packet_tag:%s",
					 f->packet_tag);
				status = STATUS_ERROR;
			}
		}

		if (!f->packet_tag[0]) {
			LOGM(L_CRIT, STATUS_ERROR, "Filter's packet_tag is empty");
			status = STATUS_ERROR;
		}

		if (f->parent_tag[TAG_LEN - 1]) {
			LOGF(L_CRIT, STATUS_ERROR,
				 "Filter's parent_tag is too long. Max:%d", TAG_LEN - 1);
			status = STATUS_ERROR;
		}

		for (unsigned i = 0; i < strlen(f->parent_tag); i++) {
			if (!isprint((int)f->parent_tag[i])) {
				LOGF(L_CRIT, STATUS_ERROR,
					 "Unprintable characters in filter's parent_tag:%s",
					 f->parent_tag);
				status = STATUS_ERROR;
			}
		}

		struct f_entry *fe;
		for (unsigned i = 0; i < f->n_entries; i++) {
			fe = &f->entries[i];

			status |= check_filter_entry(f, fe);
		}
	}

	return status;
}

static status_val check_converters()
{
	status_val status = STATUS_OK;
	for (int i = 0; i < _EWF_COUNT; i++) {
		for (int j = 0; j < _ERF_COUNT; j++) {
			if (!!rw_comp_mat[i][j] != !!converter_mat[i][j]) {
				LOGF(
					L_CRIT, STATUS_ERROR,
					"rw_comp_mat and connverter_mat is incompatible for ln:%d col:%d",
					i + 1, j + 1);
				status = STATUS_ERROR;
			}
		}
	}

	return status;
}

status_val check_sanity()
{
	status_val status = STATUS_OK;
	status |= check_converters();
	status |= check_filter();

	if (status) {
		LOGM(L_CRIT, STATUS_ERROR, "Sanity checks failed");
	}

	return status;
}

