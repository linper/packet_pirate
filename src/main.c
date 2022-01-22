#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <pcap/pcap.h>

/*#include "../include/params.h"*/
#include "../include/setup.h"
/*#include "../include/bpf.h"*/
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
	char *dev = "wlp3s0";
	/*char *dev = "eno1";*/
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

	signal(SIGINT, sig_exit);
	signal(SIGTERM, sig_exit);

	status = setup(argc, argv);
	if (status) {
		LOGM(L_CRIT, status, "Fatiled to setup program");
		goto error;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		LOGF(L_ERR, STATUS_ERROR, "Could not get netmask for device: %s", dev);
		net = 0;
		mask = 0;
	}

	if (!(pc.handle = pcap_open_live(dev, BUF_SIZE, 1, 1000, errbuf))) {
		LOGF(L_CRIT, STATUS_ERROR, "Could not open device %s: %s", dev, errbuf);
		goto error;
	}

	if (pcap_compile(pc.handle, &pc.bpf_prog, filter_exp, 0, net) == -1) {
		LOGF(L_CRIT, STATUS_ERROR, "Could not parse filter %s: %s", filter_exp,
			 pcap_geterr(pc.handle));
		goto error;
	}

	if (pcap_setfilter(pc.handle, &pc.bpf_prog) == -1) {
		LOGF(L_CRIT, STATUS_ERROR, "Could not install filter %s: %s",
			 filter_exp, pcap_geterr(pc.handle));
		goto error;
	}

	//	if (pcap_datalink(pc.handle) != DLT_EN10MB) {
	//		LOGF(L_CRIT, STATUS_ERROR, "Required ethernet headers for device %s are not supported", dev);
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

	core_destroy();

	return 0;
error:
	return 1;
}
