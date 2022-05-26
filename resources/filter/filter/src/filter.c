#include <stdlib.h>

#include "../../../../include/utils.h"
#include "../../../../include/glist.h"
#include "../../../../include/ef_tree.h"
#include "../../../../include/ext_filter.h"
#include "../../../../include/filter.h"

static struct filter filter;

static struct f_entry filter_arr[] = {
	/*ethernet packet example*/
/*  TAG 			LENGTH 		MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	/*{"eth_dhost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},*/
	/*{"eth_shost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},*/
	/*{"eth_type", 	E_LEN(2), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},*/
	/*{"eth_pld", 	E_UNKN, 	8,	EF_PLD_REG, ERF_BIN,		EWF_RAW},*/
}; 

struct my_struct {
	char text[32];
} mystruct = {
	.text = "Hello world!",
};

static void itc_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	(void)args;
	(void)header;
	(void)packet;

	LOGF(L_NOTICE, STATUS_OK, "Intercepted packet filtering for %s\n", filter.packet_tag);
	return;
}

static void itc_dump() {
	LOGF(L_NOTICE, STATUS_OK, "Next packet index will be %d\n", pc.next_pid);
	return;
}

static void filter_init() {
	LOGF(L_NOTICE, STATUS_OK, "%s\n", ((struct my_struct*)filter.usr)->text);
	strcpy(((struct my_struct*)filter.usr)->text, "Goodbye cruel world!");
	return;
}

static void filter_exit() {
	LOGF(L_NOTICE, STATUS_OK, "%s\n", ((struct my_struct*)filter.usr)->text);
	return;
}

static vld_status validate(struct packet *p, struct ef_tree *node)
{
	(void)p;
	(void)node;

	return VLD_PASS;
}

static struct filter filter = {
	.parent_tag = >>>PARENT_BUF_NAME<<<,
	.packet_tag = ">>>FILTER_NAME<<<",
	.init_filter = filter_init,
	.exit_filter = filter_exit,
	.itc_capture = itc_capture,
	.itc_dump = itc_dump,
	.validate = validate,
	.entries = filter_arr,
	.n_entries = FILTER_LEN(filter_arr),
	.usr = &mystruct,
};

INIT_FILTER(filter)

