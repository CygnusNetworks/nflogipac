#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libnetfilter_log/libnetfilter_log.h>

#define PROCFILEPATH "/proc/net/netfilter/nf_log"
#define PROC_UNBOUND "NONE"
#define PROC_BOUND "nfnetlink_log"

#define ACT_UNBIND (1 << 0)
#define ACT_BIND (1 << 1)

int main(int argc, char **argv) {
	int i, actions;
	uint16_t protocolfamily;
	struct nflog_handle *handle = NULL;
	FILE *procfile;
	char buff[4096];

	for(i=1;i < argc; ++i) {
		if(0 == strcmp(argv[i], "help")) {
			fprintf(stderr, "Usage: %s  [command protocolfamily]*"
					"\n", argv[0]);
			fprintf(stderr, "The command is one out of help, bind, "
					"rebind, status, unbind.\n");
			fprintf(stderr, "Supported protocol families are "
					"AF_INET and AF_INET6.\n");
			return 1;
		} else if(0 == strcmp(argv[i], "bind"))
			actions = ACT_BIND;
		else if(0 == strcmp(argv[i], "rebind"))
			actions = ACT_UNBIND | ACT_BIND;
		else if(0 == strcmp(argv[i], "status"))
			actions = 0;
		else if(0 == strcmp(argv[i], "unbind"))
			actions = ACT_UNBIND;
		else {
			fprintf(stderr, "Unknown action `%s'. Try passing "
					"help.\n", argv[i]);
			return 1;
		}
		if(++i >= argc) {
			fprintf(stderr, "Missing protocol family parameter.\n");
			return 1;
		} else if(0 == strcmp(argv[i], "AF_INET"))
			protocolfamily = AF_INET;
		else if(0 == strcmp(argv[i], "AF_INET6"))
			protocolfamily = AF_INET6;
		else {
			fprintf(stderr, "Unknown protocol family `%s'. Valid "
					"protocol families are AF_INET and "
					"AF_INET6.\n", argv[i]);
			return 1;
		}

		if(actions == 0) {
			procfile = fopen(PROCFILEPATH, "r");
			if(procfile == NULL) {
				fprintf(stderr, "failed to open " PROCFILEPATH
						": %s\n", strerror(errno));
				return 1;
			}
			printf(protocolfamily == AF_INET ? "AF_INET"
					: "AF_INET6");
			/* repurposing actions */
			while(fscanf(procfile, "%d %4095s", &actions, buff)
					== 2) {
				if(actions != protocolfamily)
					continue;

				if(0 == strcmp(buff, PROC_UNBOUND))
					puts(" unbound");
				else if(0 == strcmp(buff, PROC_BOUND))
					puts(" bound");
				else
					puts(" other");
				fclose(procfile);
				procfile = NULL;
				break;
			}
			if(NULL != procfile) {
				puts(" error");
				fclose(procfile);
			}
		} else {
			handle = nflog_open();
			if(NULL == handle) {
				fprintf(stderr, "nflog_open() failed: %s\n",
						strerror(errno));
				return 1;
			}
			if(0 != (actions & ACT_UNBIND))
				if(nflog_unbind_pf(handle, protocolfamily)
						< 0) {
					fprintf(stderr, "nflog_unbind_pf() "
							"failed with protocol "
							"family %d: %s\n",
							protocolfamily,
							strerror(errno));
					/* Cannot handle a close failure
					 * anymore. */
					(void)nflog_close(handle);
					return 1;
				}
			if(0 != (actions & ACT_BIND))
				if(nflog_bind_pf(handle, protocolfamily)
						< 0) {
					fprintf(stderr, "nflog_bind_pf() failed"
						        " with protocol family "
							"%d: %s\n",
							protocolfamily,
							strerror(errno));
					/* Cannot handle a close failure
					 * anymore. */
					(void)nflog_close(handle);
					return 1;
				}
			if(0 > nflog_close(handle)) {
				fprintf(stderr, "nflog_close() failed: %s\n",
						strerror(errno));
				return 1;
			}
		}
	}
	return 0;
}
