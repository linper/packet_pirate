#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "../include/glist.h"
#include "../include/filter.h"
#include "../include/fhmap.h"
#include "../include/f_reg.h"
#include "../include/ext_filter.h"
#include "../include/packet.h"
#include "../include/ef_tree.h"
#include "../include/dump/dump.h"
#include "../include/core.h"

#define FH_GLOB_INIT_CAP 256

static status_val build_ef_tree()
{
	status_val ret = STATUS_BAD_INPUT;
	struct ext_filter *ef = NULL;
	if (!(pc.ef_root = ef_tree_base())) {
		LOG(L_CRIT, STATUS_OMEM);
		return STATUS_OMEM;
	}

	bool found = true;
	while (found) { //till all filters reachable from root are added
		found = false;

		for (struct filter **f = filter_arr; *f; f++) {
			//checking if parent filter is in the tree and curent is not
			if (ef_tree_contains_by_tag(
					pc.ef_root, (*f)->packet_tag) && /*does not contain filter*/
				(!*(*f)->parent_tag || /*is link layer filter*/
				 !ef_tree_contains_by_tag(
					 pc.ef_root,
					 (*f)->parent_tag))) { /*contains parent filter*/
				//now we know that current filter can be added to tree
				//createing new extended filter
				if (!(ef = ext_filter_new(*f))) {
					ret = STATUS_OMEM;
					LOG(L_CRIT, ret);
					goto err;
				}

				//adding new filter to filter tree
				if ((ret = ef_tree_put(pc.ef_root, ef))) {
					LOG(L_CRIT, ret);
					ext_filter_free(ef);
					goto err;
				}
				found = true;
			}
		}
	}

	return STATUS_OK;
err:
	ef_tree_free(pc.ef_root);
	return ret;
}

static status_val filter_rec(struct ef_tree *node, const u_char *data,
							 u_char *args, const struct pcap_pkthdr *header,
							 unsigned read_off)
{
	status_val status;
	const unsigned base_read_off = read_off;

	if (node->lvl) { //skiping root root node
		//trying to split data to packet fields
		status =
			derive_packet(pc.single_cap_pkt, node, data, header, &read_off);
		if (status) {
			read_off = base_read_off; //reverting read offset
			LOGF(L_DEBUG, STATUS_NOT_FOUND, "Packet dropped for %s\n",
				 node->flt->filter->packet_tag);
			return STATUS_NOT_FOUND; //if this filter fails, then all children filter must fail
		}

		//TODO call validation callback here
	}

	if (node->chld) { //desending down into first child filter if it exists
		//persist filtering on failure
		filter_rec(node->chld, data, args, header, read_off);
	}

	if (node->next) { // going to sibling filter
		//persist filtering on failure
		filter_rec(node->next, data, args, header, base_read_off);
	}

	return STATUS_OK;
}

status_val core_init()
{
	status_val status;

	pc.cap_pkts = glist_new(2 * DUMP_BATCH, GLIST_NO_SHRINK);
	if (!pc.cap_pkts) {
		LOG(L_CRIT, STATUS_OMEM);
		status = STATUS_OMEM;
		goto cp_err;
	}

	glist_set_free_cb(pc.cap_pkts, (void (*)(void *))packet_free);

	pc.single_cap_pkt = glist_new(64, GLIST_ST_DEFAULT);
	if (!pc.single_cap_pkt) {
		LOG(L_CRIT, STATUS_OMEM);
		status = STATUS_OMEM;
		goto scp_err;
	}

	pc.f_entries = fhmap_new(FH_GLOB_INIT_CAP * FH_CAP_MULTIPLIER);
	if (!pc.f_entries) {
		LOG(L_CRIT, STATUS_OMEM);
		status = STATUS_OMEM;
		goto fhmap_err;
	}

	status = build_ef_tree();
	if (status) {
		LOG(L_CRIT, status);
		goto tree_err;
	}

	status = dctx.open();
	if (status) {
		LOG(L_CRIT, status);
		goto dump_build_err;
	}

	status = dctx.build(pc.ef_root);
	if (status) {
		LOG(L_CRIT, status);
		goto dump_build_err;
	}

	return status;

dump_build_err:
	dctx.close();
	ef_tree_free(pc.ef_root);
tree_err:
	fhmap_shallow_free(pc.f_entries);
fhmap_err:
	glist_free(pc.single_cap_pkt);
scp_err:
	glist_free(pc.cap_pkts);
cp_err:
	return status;
}

void core_filter(u_char *args, const struct pcap_pkthdr *header,
				 const u_char *packet)
{
	//clearing old single packet capture list
	glist_clear_shallow(pc.single_cap_pkt);
	filter_rec(pc.ef_root, packet, args, header, 0);

	//copying elements ot main captured packet list
	if (glist_copy_to(pc.single_cap_pkt, pc.cap_pkts)) {
		LOG(L_ERR, STATUS_OMEM);
	}

	u_long now = time(NULL);
	if (glist_count(pc.cap_pkts) >= DUMP_BATCH ||
		now - pc.last_dump >= DUMP_INTERVAL) {
		dctx.dump(pc.cap_pkts);
		glist_clear(pc.cap_pkts);
		pc.last_dump = now;
	}

	pc.next_pid++;
}

void core_destroy()
{
	if (pc.handle) {
		pcap_freecode(&pc.bpf_prog);
		pcap_close(pc.handle);
	}

	//syncing db before freeing everyting else
	dctx.close();
	//do not need to free containing elements; just unlinking
	glist_free_shallow(pc.single_cap_pkt);
	glist_free(pc.cap_pkts);
	ef_tree_free(pc.ef_root);
	fhmap_shallow_free(pc.f_entries);
	free(pc.bpf);
}

