#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <pcap/pcap.h>

#include "../include/setup.h"
#include "../include/report.h"
#include "../include/core.h"

static volatile bool in_cap = false;

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

int main(int argc, char *argv[])
{
	/*pcap_t *handle;*/
	status_val status;
	/*char *dev = "wlp3s0";*/
	/*char *dev = "eno1";*/
	char errbuf[ERRBUF_SIZE] = { 0 };
	bpf_u_int32 mask;
	bpf_u_int32 net;

	signal(SIGINT, sig_exit);
	signal(SIGTERM, sig_exit);

	//TODO find default dev
	/*if (!(dev = pcap_lookupdev( errbuf))) {*/
	if (!pc.dev) {
		pc.dev = "eno1"; //for now
		/*fprintf(stderr, "Could not get default device: %s/n", errbuf);*/
		/*goto error;*/
	}

	status = setup(argc, argv);
	if (status) {
		LOGM(L_CRIT, status, "Fatiled to setup program");
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

	//	if (pcap_datalink(pc.handle) != DLT_EN10MB) {
	//		LOGF(L_CRIT, STATUS_ERROR, "Required ethernet headers for device %s are not supported", pc.dev);
	//		goto error;
	//	}

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
