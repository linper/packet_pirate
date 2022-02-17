#include "../include/>>>FILTER_NAME<<<.h"

static struct f_entry >>>FILTER_NAME<<<_packet[] = {
	/*ethernet packet example*/
/*  TAG 			LENGTH 		MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	/*{"eth_dhost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},*/
	/*{"eth_shost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},*/
	/*{"eth_type", 	E_LEN(2), 	8,	0, 			ERF_UINT_LE, 	EWF_UINT},*/
	/*{"eth_pld", 	E_UNKN, 	8,	EF_PLD_REG, ERF_BIN,		EWF_RAW},*/
}; 

struct my_struct {
	char text[32];
} mystruct = {
	.text = "Hello world!",
};

static void itc_capture_>>>FILTER_NAME<<<(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	(void)args;
	(void)header;
	(void)packet;

	LOGF(L_NOTICE, STATUS_OK, "Intercepted packet filtering for %s\n", >>>FILTER_NAME<<<_packet->tag);
	return;
}

static void itc_dump_>>>FILTER_NAME<<<() {
	LOGF(L_NOTICE, STATUS_OK, "Next packet index will be %d\n", pc.next_pid);
	return;
}

static void init_>>>FILTER_NAME<<<() {
	LOGF(L_NOTICE, STATUS_OK, "%s\n", ((struct my_struct*)>>>FILTER_NAME<<<_filter.usr)->text);
	strcpy(((struct my_struct*)>>>FILTER_NAME<<<_filter.usr)->text, "Goodbye cruel world!");
	return;
}

static void exit_>>>FILTER_NAME<<<() {
	LOGF(L_NOTICE, STATUS_OK, "%s\n", ((struct my_struct*)>>>FILTER_NAME<<<_filter.usr)->text);
	return;
}

static vld_status validate_>>>FILTER_NAME<<<(struct packet *p, struct ef_tree *node)
{
	(void)p;
	(void)node;

	return VLD_PASS;
}

struct filter >>>FILTER_NAME<<<_filter = {
	.parent_tag = >>>PARENT_BUF_NAME<<<,
	.packet_tag = ">>>FILTER_NAME<<<",
	.init_filter = init_>>>FILTER_NAME<<<,
	.exit_filter = exit_>>>FILTER_NAME<<<,
	.itc_capture = itc_capture_>>>FILTER_NAME<<<,
	.itc_dump = itc_dump_>>>FILTER_NAME<<<,
	.validate = validate_>>>FILTER_NAME<<<,
	.entries = >>>FILTER_NAME<<<_packet,
	.n_entries = FILTER_LEN(>>>FILTER_NAME<<<_packet),
	.usr = &mystruct,
};

INIT_FILTER(>>>FILTER_NAME<<<_filter)

