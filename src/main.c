/**
 * @file main.c
 * @brief Entry and exit point of whole program
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <pcap/pcap.h>

#include "../include/setup.h"
#include "../include/report.h"
#include "../include/core.h"
#include "../include/glist.h"

static volatile bool in_cap = false;

/**
 * @brief Signal handler to gracefully terminate program
 */
void sig_exit(int signo)
{
	(void)signo;
	if (in_cap) {
		pcap_breakloop(pc.handle);
	} else {
		core_destroy();
		exit(0);
	}
}

/**
 * @brief Selects device/interface to sniff
 * @return Status whethet device was successfuly selected
 */
static status_val get_dev()
{
	status_val status = STATUS_NOT_FOUND;

	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	pcap_if_t *devs = NULL;
	pcap_if_t *d;

	if (pcap_findalldevs(&devs, errbuf)) {
		LOGF(L_CRIT, STATUS_ERROR, "Failed to get all interfaces: %s", errbuf);
		return status;
	}
	/*goto end;*/
	bool dev_compat = false;
	if (pc.dev) {
		//checking if supplied interface is valid
		d = devs;

		while (d->next) {
			if (!strcmp(pc.dev, d->name)) {
				LOGF(L_INFO, STATUS_OK, "Using interface: %s%s%s", d->name,
					 d->description ? "\ndescription:" : "",
					 d->description ? d->description : "");
				dev_compat = true;
				status = STATUS_OK;
			}

			d = d->next;
		}

		if (!dev_compat) {
			LOGF(L_WARN, STATUS_NOT_FOUND, "Interface:%s was not found",
				 pc.dev);
			//so data in previously allocated memory was invalid
			free(pc.dev);
			pc.dev = NULL;

#ifndef DEF_AUTO_IF
			LOGM(L_CRIT, STATUS_NOT_FOUND,
				 "No way to get valid interface. Exiting...");
			goto end;
#endif
		}
	}

	//checking if interface can be auto selected
#ifdef DEF_AUTO_IF
	if (!dev_compat) {
		LOGM(L_INFO, STATUS_OK, "Trying to autoselect interface");
		d = devs;

		while (d->next) {
#ifndef DEF_IF_LO
			if (d->flags & PCAP_IF_LOOPBACK) {
				d = d->next;
				continue;
			}
#endif
#ifndef DEF_IF_WI
			if (d->flags & PCAP_IF_WIRELESS) {
				d = d->next;
				continue;
			}
#endif
#ifdef DEF_IF_OUP
			if (!(d->flags & PCAP_IF_UP)) {
				d = d->next;
				continue;
			}
#endif
#ifdef DEF_IF_ORN
			if (!(d->flags & PCAP_IF_RUNNING)) {
				d = d->next;
				continue;
			}
#endif
			dev_compat = true;
			LOGF(L_INFO, STATUS_OK, "Using interface: %s%s%s", d->name,
				 d->description ? "\ndescription:" : "",
				 d->description ? d->description : "");
			pc.dev = strdup(d->name);
			status = STATUS_OK;
			goto end;
		}

		LOGM(L_CRIT, STATUS_NOT_FOUND,
			 "No way to get valid interface. Exiting...");
	}
#endif

end:
	pcap_freealldevs(devs);
	return status;
}

/**
 * @brief Main entry point of a program
 */
int main(int argc, char *argv[])
{
	status_val status;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	bpf_u_int32 mask;
	bpf_u_int32 net;

	signal(SIGINT, sig_exit);
	signal(SIGTERM, sig_exit);

	status = setup(argc, argv);
	if (status) {
		LOGM(L_CRIT, status, "Failed to setup program");
		goto error;
	}

	status = get_dev();
	if (status) {
		LOGM(L_CRIT, status, "Failed to get interface");
		goto error;
	}

	if (!pc.sample) {
		if (pcap_lookupnet(pc.dev, &net, &mask, errbuf) == -1) {
			LOGF(L_ERR, STATUS_ERROR, "Could not get netmask for device: %s",
				 pc.dev);
			net = 0;
			mask = 0;
		}

		if (!(pc.handle =
				  pcap_open_live(pc.dev, DEF_SNAPLEN, 1, 1000, errbuf))) {
			LOGF(L_CRIT, STATUS_ERROR, "Could not open device %s: %s", pc.dev,
				 errbuf);
			goto error;
		}

		//TODO add compatability mechanism between filters and datalink headers
		if (pcap_datalink(pc.handle) != DLT_EN10MB) {
			LOGF(L_CRIT, STATUS_ERROR,
				 "Required ethernet headers for device %s are not supported",
				 pc.dev);
			goto error;
		}
	} else {
		if (!(pc.handle = pcap_open_offline(pc.sample, errbuf))) {
			LOGF(L_CRIT, STATUS_ERROR, "Could not open sample%s: %s", pc.sample,
				 errbuf);
			goto error;
		}
	}

	if (pcap_compile(pc.handle, &pc.bpf_prog, pc.bpf, 0, net) == -1) {
		LOGF(L_CRIT, STATUS_ERROR, "Could not parse filter %s: %s", pc.bpf,
			 pcap_geterr(pc.handle));
		goto error;
	}

	if (pcap_setfilter(pc.handle, &pc.bpf_prog) == -1) {
		LOGF(L_CRIT, STATUS_ERROR, "Could not install filter %s: %s", pc.bpf,
			 pcap_geterr(pc.handle));
		goto error;
	}

	status = core_init();
	if (status) {
		LOG(L_CRIT, status);
		if (pc.handle) {
			pcap_freecode(&pc.bpf_prog);
			pcap_close(pc.handle);
		}

		free(pc.bpf);
		goto error;
	}

	in_cap = true; //lets say scheduling can not occur right after this
	pcap_loop(pc.handle, -1, core_filter, NULL);

	if (pc.verbosity > L_QUIET) {
		report_all();
	}

	core_destroy();

	return 0;
error:
	return 1;
}

/**
 * @brief Real entry point of a program.
 * Creates generic list to sore user defined filters
 */
void __attribute__((constructor)) init()
{
	pc.f_reg = glist_new(16);
}

/**
 * @brief Real exit point of a program.
 * Frees generic list of user defined filters
 */
void __attribute__((destructor)) deinit()
{
	glist_free_shallow(pc.f_reg);
}

