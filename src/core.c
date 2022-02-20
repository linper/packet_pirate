/**
 * @file core.c
 * @brief Implementation of core "Packet Pirate's" interface.
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "../include/glist.h"
#include "../include/filter.h"
#include "../include/fhmap.h"
#include "../include/ext_filter.h"
#include "../include/packet.h"
#include "../include/ef_tree.h"
#include "../include/dump/dump.h"
#include "../include/sanity.h"
#include "../include/core.h"

#define FH_GLOB_INIT_CAP 256

/**
* @brief Builds whole extended filter tree
* @return Status whethet buldidn was successfull
 */
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
		struct filter *f;
		glist_foreach (void *e, pc.f_reg) {
			f = (struct filter *)e;
			//checking if parent filter is in the tree and curent is not
			if (ef_tree_contains_by_tag(
					pc.ef_root, f->packet_tag) && /*does not contain filter*/
				(!*f->parent_tag || /*is link layer filter*/
				 !ef_tree_contains_by_tag(
					 pc.ef_root, f->parent_tag))) { /*contains parent filter*/
				//now we know that current filter can be added to tree
				//createing new extended filter
				if (!(ef = ext_filter_new(f))) {
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

				//calling filter initialization hooks for each filter
				if (f->init_filter) {
					f->init_filter();
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

/**
 * @brief Callback to modify invalid packets' statistics
 */
inline static void invalidate(struct ef_tree *node, void *usr)
{
	(void)usr;
	node->flt->rep.invalid++;
}

/**
 * @brief Callback to clear hint
 */
inline static void clear_hint(struct ef_tree *node, void *usr)
{
	(void)usr;
	node->flt->hint = NULL;
}

/**
 * @brief Callback to skip filter
 */
inline static void skip(struct ef_tree *node, void *usr)
{
	(void)usr;
	node->flt->rep.skiped++;
}

/**
 * @brief Function to each filter to work with captured data
 * @param[in] *node 	Extended filter tree node to derive packet form
 * @param[in] *data 	Captured packet data
 * @param[in] *args 	Arguments supplied to pcap's capture callback
 * @param[in] *header 	Timestamp, packet length and captured packet length
 * @param[in] read_off 	Current read position in `data`
 * @return Status whether packet entry were parsed succesfully
 */
static vld_status filter_rec(struct ef_tree *node, const u_char *data,
							 u_char *args, const struct pcap_pkthdr *header,
							 unsigned read_off)
{
	status_val status;
	vld_status vlds;
	const unsigned base_read_off = read_off;

	if (node->lvl) { //skiping root root node
		if (node->par->flt && node->par->flt->hint &&
			strcmp(node->par->flt->hint, node->flt->filter->packet_tag)) {
			//this is not hinted filter
			goto sibling;
		}

		struct packet *p = NULL;

		//calling capture intercept hook for every filter
		if (node->flt->filter->itc_capture) {
			node->flt->filter->itc_capture(args, header, data);
		}

		//trying to split data to packet fields
		status =
			derive_packet(pc.single_cap_pkt, node, data, header, &read_off, &p);
		if (status) {
			read_off = base_read_off; //reverting read offset
			LOGF(L_DEBUG, STATUS_NOT_FOUND, "Packet dropped for %s\n",
				 node->flt->filter->packet_tag);
			node->flt->rep.unsplit++;
			ef_tree_foreach(node, true, skip, NULL);
			vlds = VLD_DROP;
			//if this filter fails, then all children filter must fail.
			//But nesesserely siblings
			goto sibling;
		}

		if (node->flt->filter->validate) {
			vlds = node->flt->filter->validate(p, node);
			switch (vlds) {
			case VLD_DROP:
				LOGF(L_DEBUG, STATUS_OK,
					 "Packet for %s failed validation, dropping...\n",
					 p->packet_tag);
				node->flt->rep.invalid++;
				packet_free(p);
				goto sibling;

			case VLD_DROP_ALL:
				LOGF(L_DEBUG, STATUS_OK,
					 "Packet for %s failed validation, dropping all...\n",
					 p->packet_tag);
				ef_tree_foreach_continue(node, invalidate, NULL);
				node->flt->rep.invalid++;
				packet_free(p);
				return VLD_DROP_ALL;

			case VLD_PASS:
				//appending packet to packet list
				status = glist_push(pc.single_cap_pkt, p);
				if (status) {
					LOG(L_ERR, status);
					packet_free(p);
				} else {
					node->flt->rep.parsed++;
				}
				break;
			}
			//pass throug if validation callbach does not exist
		} else {
			status = glist_push(pc.single_cap_pkt, p);
			if (status) {
				LOG(L_ERR, status);
				packet_free(p);
			} else {
				node->flt->rep.parsed++;
			}
		}
	}

	if (node->chld) { //desending down into first child filter if it exists
		//persist filtering on failure, unless drop all is returned
		vlds = filter_rec(node->chld, data, args, header, read_off);
		if (vlds == VLD_DROP_ALL) {
			return VLD_DROP_ALL;
		}
	}

sibling:
	if (node->next) { // going to sibling filter
		//persist filtering on failure, unless drop all is returned
		vlds = filter_rec(node->next, data, args, header, base_read_off);
		if (vlds == VLD_DROP_ALL) {
			return VLD_DROP_ALL;
		}
	}

	return VLD_PASS;
}

status_val core_init()
{
	status_val status;

	pc.cap_pkts = glist_new(2 * DUMP_BATCH);
	if (!pc.cap_pkts) {
		LOG(L_CRIT, STATUS_OMEM);
		status = STATUS_OMEM;
		goto cp_err;
	}

	glist_set_free_cb(pc.cap_pkts, (void (*)(void *))packet_free);

	pc.single_cap_pkt = glist_new(64);
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

#ifdef DEVEL_SANITY
	status = check_sanity();
	if (status) {
		LOG(L_CRIT, status);
		goto dump_build_err;
	}
#endif

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

	vld_status vlds = filter_rec(pc.ef_root, packet, args, header, 0);
	if (vlds == VLD_DROP_ALL) {
		//no packets from this capture should be saved
		glist_clear(pc.single_cap_pkt);
		goto end;

		//copying elements ot main captured packet list
	} else if (glist_copy_to(pc.single_cap_pkt, pc.cap_pkts)) {
		LOG(L_ERR, STATUS_OMEM);
		goto end;
	}

	u_long now = time(NULL);
	if (glist_count(pc.cap_pkts) >= DUMP_BATCH ||
		now - pc.last_dump >= DUMP_INTERVAL) {
		//calling dunp interception hooks for each filter
		glist_foreach (void *e, pc.f_reg) {
			if (((struct filter *)e)->itc_dump) {
				((struct filter *)e)->itc_dump();
			}
		}

		dctx.dump(pc.cap_pkts);
		glist_clear(pc.cap_pkts);
		pc.last_dump = now;
	}

end:
	pc.next_pid++;
	ef_tree_foreach(pc.ef_root, true, clear_hint, NULL);
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
	free(pc.dev);
}

