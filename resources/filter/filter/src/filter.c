#include "../include/>>>FILTER_DB<<<.h"

static struct f_entry >>>FILTER_DB<<<_packet[] = {
	/*ethernet packet example*/
/*  TAG 			ENTRY TYPE	LENG TH 	FLAGS 	READ FORMAT 	WRITE FORMAT */
	/*{"dhost", 	ET_DATAFIELD, 	E_LEN(6), 	0, 		ERF_STR, 		EWF_HEX_STR},*/
	/*{"shost", 	ET_DATAFIELD,	E_LEN(6), 	0, 		ERF_STR, 		EWF_HEX_STR},*/
	/*{"type", 		ET_DATAFIELD,	E_LEN(2), 	0, 		ERF_UINT_LE, 	EWF_HEX_STR},*/
}; 

struct my_struct {
	char text[32];
} mystruct = {
	.text = "Hello world!",
};

static void itc_capture_>>>FILER_DB<<<(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	(void)args;
	(void)header;
	(void)packet;

	LOGF(L_NOTICE, STATUS_OK, "Intercepted packet filtering for %s\n", >>>FILTER_DB<<<_packet->tag);
	return;
}

static void itc_dump_>>>FILTER_DB<<<() {
	LOGF(L_NOTICE, STATUS_OK, "Next packet index will be %d\n", pc.next_pid);
	return;
}

static void init_>>>FILTER_DB<<<() {
	LOGF(L_NOTICE, STATUS_OK, "%s\n", ((struct my_struct*)>>>FILTER_DB<<<_filter.usr)->text);
	strcpy(((struct my_struct*)>>>FILTER_DB<<<_filter.usr)->text, "Goodbye cruel world!");
	return;
}

static void exit_>>>FILTER_DB<<<() {
	LOGF(L_NOTICE, STATUS_OK, "%s\n", ((struct my_struct*)>>>FILTER_DB<<<_filter.usr)->text);
	return;
}

static vld_status validate_>>>FILTER_DB<<<(struct packet *p, struct ef_tree *node)
{
	return VLD_PASS;
}

struct filter >>>FILTER_DB<<<_filter = {
	.parent_tag = >>>PARENT_BUF_DB<<<,
	.packet_tag = ">>>FILTER_DB<<<",
	.init_filter = init_>>>FILTER_DB<<<,
	.exit_filter = exit_>>>FILTER_DB<<<,
	.itc_capture = itc_capture_>>>FILTER_DB<<<,
	.itc_dump = itc_dump_>>>FILTER_DB<<<,
	.validate = validate_>>>FILTER_DB<<<,
	.entries = >>>FILTER_DB<<<_packet,
	.n_entries = FILTER_LEN(>>>FILTER_DB<<<_packet),
	.usr = &mystruct,
};
	


