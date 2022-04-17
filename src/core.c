/** @file core.c
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
#include "../include/dump.h"
#ifdef DEVEL_SANITY
#include "../include/sanity.h"
#endif
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
 * @brief Callback to clear stash
 */
inline static void clear_stash(struct ef_tree *node, void *usr)
{
	(void)usr;
	if (node->flt->stash->in_use) {
		stash_clear(node->flt->stash);
	}
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
 * @brief Callback to enable filter
 */
inline static void enable_filter(struct ef_tree *node, void *usr)
{
	(void)usr;
	if (node && node->flt) {
		node->flt->active = true;
	}
}

/**
 * @brief Callback to disable filter
 */
inline static void disable_filter(struct ef_tree *node, void *usr)
{
	(void)usr;
	if (node && node->flt) {
		node->flt->active = false;
	}
}

/**
 * @brief Function to modify extended filter tree after compilation
 * @return Status whether modifications went succesfully
 */
static status_val modify_ef_tree()
{
	status_val status = STATUS_OK;
	struct tree_mod *tm = NULL;
	struct ef_tree *node = NULL;

	glist_foreach (void *e, pc.tree_mods) {
		tm = (struct tree_mod *)e;

		status = ef_tree_get_node(pc.ef_root, tm->tag, &node);
		if (status) {
			LOGF(L_ERR, status, "Failed to find filter:%s", tm->tag);
			goto end;
		}

		if (tm->mod) { //pruning
			ef_tree_foreach(node, false, disable_filter, NULL);
		} else { //growing
			ef_tree_root_to_leaf_foreach(pc.ef_root, node, enable_filter, NULL);
		}
	}

end:
	return status;
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
							 unsigned read_off, struct packet *last)
{
	status_val status;
	vld_status vlds = VLD_DROP;
	const unsigned base_read_off = read_off;
	struct packet *p = NULL;

	if (node->lvl) { //skiping root root node
		if ((node->par->flt && node->par->flt->hint &&
			 strcmp(node->par->flt->hint, node->flt->filter->packet_tag)) ||
			!node->flt->active) {
			//this is not hinted filter
			goto sibling;
		}

		//calling capture intercept hook for every filter
		if (node->flt->filter->itc_capture) {
			node->flt->filter->itc_capture(args, header, data);
		}

		//preparing basic packet for later
		status = prepare_packet(&p, node->flt, last);
		if (status) {
			LOG(L_CRIT, status);
			return VLD_DROP_ALL;
		}

		//trying to split data to packet fields
		status = derive_packet(p, data, header, &read_off);
		if (status) {
			read_off = base_read_off; //reverting read offset
			LOGF(L_DEBUG, STATUS_NOT_FOUND, "Packet dropped for %s\n",
				 node->flt->filter->packet_tag);
			node->flt->rep.unsplit++;
			ef_tree_foreach(node, true, skip, NULL);
			vlds = VLD_DROP;
			//if this filter fails, then all children filter must fail.
			//But not nesesserely siblings
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
				goto sibling;

			case VLD_DROP_ALL:
				LOGF(L_DEBUG, STATUS_OK,
					 "Packet for %s failed validation, dropping all...\n",
					 p->packet_tag);
				ef_tree_foreach_continue(node, invalidate, NULL);
				node->flt->rep.invalid++;
				return VLD_DROP_ALL;

			case VLD_PASS:
				//appending packet to packet list
				status = glist_push(pc.single_cap_pkt, p);
				if (status) {
					LOG(L_ERR, status);
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
			} else {
				node->flt->rep.parsed++;
			}
		}
	}

	//desending down into first child filter if it exists
	if (node->chld) {
		vlds = filter_rec(node->chld, data, args, header, read_off, p);
		if (vlds == VLD_DROP_ALL) {
			return VLD_DROP_ALL;
		}
	}

sibling:
	// going to sibling filter
	if (node->next) {
		//persist filtering on failure, unless drop all is returned
		vlds = filter_rec(node->next, data, args, header, base_read_off, last);
		if (vlds == VLD_DROP_ALL) {
			return VLD_DROP_ALL;
		}
	}

	return vlds;
}

status_val core_init()
{
	status_val status;

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

	status = modify_ef_tree();
	if (status) {
		LOG(L_CRIT, status);
		goto mod_tree_err;
	}

#ifdef DEVEL_SANITY
	status = check_sanity();
	if (status) {
		LOG(L_CRIT, status);
		goto mod_tree_err;
	}
#endif

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
mod_tree_err:
	glist_free(pc.tree_mods);
tree_err:
	fhmap_shallow_free(pc.f_entries);
fhmap_err:
	glist_free(pc.single_cap_pkt);
scp_err:
	return status;
}

void core_filter(u_char *args, const struct pcap_pkthdr *header,
				 const u_char *packet)
{
	//clearing old single packet capture list
	glist_clear_shallow(pc.single_cap_pkt);

	vld_status vlds = filter_rec(pc.ef_root, packet, args, header, 0, NULL);
	if (vlds == VLD_DROP_ALL) {
		//no packets from this capture should be saved
		glist_clear_shallow(pc.single_cap_pkt);
		goto end;
	}

	glist_foreach (void *e, pc.f_reg) {
		if (((struct filter *)e)->itc_dump) {
			((struct filter *)e)->itc_dump();
		}
	}

	dctx.dump(pc.single_cap_pkt);

end:
	pc.next_pid++;
	glist_clear_shallow(pc.single_cap_pkt);
	ef_tree_foreach(pc.ef_root, true, clear_hint, NULL);
	ef_tree_foreach(pc.ef_root, true, clear_stash, NULL);
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
	glist_free(pc.tree_mods);
	ef_tree_free(pc.ef_root);
	fhmap_shallow_free(pc.f_entries);
	free(pc.dev);
}

