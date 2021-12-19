
#include <string.h>

#include "../include/bpf.h"

static inline void build_port_string(char *dst, const char *src, char *prefix)
{
	sprintf(dst, "%s %s %s ", prefix, strstr(src, "-") ? "portrange" : "port",
			src);
}

//todo study bfp syntax and correct errors if they exist
status_val build_bpf(struct prog_args *pa)
{
	status_val status = STATUS_ERROR;

	//+<some value> is for aditional "src/dst host/net" and similar
	char dst_net[NET_LEN + 9];
	char src_net[NET_LEN + 9];
	char dst_ports[PORT_LEN + 14];
	char src_ports[PORT_LEN + 14];

	if (pa->bpf_enabled) {
		if (pa->filter.bpf && strlen(pa->filter.bpf) >= BPF_PR_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Bpf is too long");
			goto end;
		} else if (!(pc.bpf = strdup(pa->filter.bpf))) {
			status = STATUS_OMEM;
			LOG(L_CRIT, status);
			goto end;
		}
		status = STATUS_OK;
		goto end;
	}

	if (pa->filter.dhost && pa->filter.dnet) {
		status = STATUS_BAD_INPUT;
		LOGM(L_CRIT, status, "Dhost and dnet can't exist in unison");
		goto end;
	} else if (pa->filter.dhost) {
		if (strlen(pa->filter.dhost) >= NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Dhost is too long");
			goto end;
		}
		sprintf(dst_net, "dst host %s ", pa->filter.dhost);
	} else if (pa->filter.dnet) {
		if (strlen(pa->filter.dnet) >= NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Dnet is too long");
			goto end;
		}
		sprintf(dst_net, "dst net %s ", pa->filter.dnet);
	}

	if (pa->filter.shost && pa->filter.snet) {
		status = STATUS_BAD_INPUT;
		LOGM(L_CRIT, status, "Shost and snet can't exist in unison");
		goto end;
	} else if (pa->filter.shost) {
		if (strlen(pa->filter.dnet) >= NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Shost is too long");
			goto end;
		}
		sprintf(src_net, "src host %s ", pa->filter.shost);
	} else if (pa->filter.snet) {
		if (strlen(pa->filter.snet) >= NET_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Snet is too long");
			goto end;
		}
		sprintf(src_net, "src net %s ", pa->filter.snet);
	}

	if (pa->filter.dport) {
		if (strlen(pa->filter.dport) >= PORT_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Dport is too long");
			goto end;
		}
		build_port_string(dst_ports, pa->filter.dport, "dst");
	}

	if (pa->filter.sport) {
		if (strlen(pa->filter.sport) >= PORT_LEN) {
			status = STATUS_BAD_INPUT;
			LOGM(L_CRIT, status, "Sport is too long");
			goto end;
		}
		build_port_string(src_ports, pa->filter.sport, "src");
	}

	size_t comb_len = strlen(dst_net) + strlen(src_net) + strlen(dst_ports) +
					  strlen(src_ports);

	if (!(pc.bpf = calloc(sizeof(char), comb_len))) {
		status = STATUS_OMEM;
		LOG(L_CRIT, status);
		goto end;
	}

	sprintf(pc.bpf, "%s %s%s%s%s", pa->filter.proto, src_net, src_ports,
			dst_net, dst_ports);
	status = STATUS_OK;

end:
	return status;
}
