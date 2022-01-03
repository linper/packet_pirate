#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <pcap/pcap.h>

#include "../include/params.h"
#include "../include/setup.h"
#include "../include/bpf.h"
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
	struct prog_args pr_args = { 0 };

	signal(SIGINT, sig_exit);
	signal(SIGTERM, sig_exit);

	parse_params(argc, argv, &pr_args); //geting command line parameters

	status_val status = setup_prog_ctx(&pr_args); //setting up program context
	if (status) {
		LOG(L_CRIT, status);
		goto error;
	}

	if (!pr_args.bpf_enabled) {
		status = build_bpf(&pr_args);
		if (status) {
			LOG(L_CRIT, status);
			goto error;
		}
	}

	/*pcap_t *handle;*/
	//	char *dev;
	//	char *dev = argv[1];
	char *dev = "eno1";
	char errbuf[ERRBUF_SIZE] = { 0 };
	char filter_exp[BUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;
	/*struct pcap_pkthdr header;*/

	sprintf(filter_exp, "tcp");
	//	sprintf(filter_exp, "port %s", argv[2]);

	//	if (!(dev = pcap_lookupdev( errbuf))) {
	//		fprintf(stderr, "Could not get default device: %s/n", errbuf);
	//		goto error;
	//	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Could not get netmask for device: %s/n", dev);
		net = 0;
		mask = 0;
	}

	if (!(pc.handle = pcap_open_live(dev, BUF_SIZE, 1, 1000, errbuf))) {
		fprintf(stderr, "Could not open device %s: %s/n", dev, errbuf);
		goto error;
	}

	if (pcap_compile(pc.handle, &pc.bpf_prog, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Could not parse filter %s: %s/n", filter_exp,
				pcap_geterr(pc.handle));
		goto error;
	}

	if (pcap_setfilter(pc.handle, &pc.bpf_prog) == -1) {
		fprintf(stderr, "Could not install filter %s: %s/n", filter_exp,
				pcap_geterr(pc.handle));
		goto error;
	}

	//	if (pcap_datalink(pc.handle) != DLT_EN10MB) {
	//		fprintf(stderr, "Required ethernet headers for device %s are not supported/n", dev);
	//		goto error;
	//	}

	//	packet = pcap_next(pc.handle, &header);
	status = core_init();
	if (status) {
		LOG(L_CRIT, status);
		goto error;
	}

	in_cap = true; //lets say scheduling can not occur right after this
	pcap_loop(pc.handle, -1, core_filter, NULL);

	core_destroy();

	return 0;
error:
	return 1;
}
