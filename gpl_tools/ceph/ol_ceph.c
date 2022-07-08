/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <stdbool.h>
#include <libgen.h>
#include <stdint.h>

#include "ol_cmdline.h"
#include "ol_ceph_receiver.h"
#include "ol_ceph_generator.h"
#include "ol_ceph.h"

/* Send/receive buffer for both generator and receiver. */
static uint8_t buf[1024 * 512];

static bool     print_help = false;
static char    *srv_addr = NULL;
static int      srv_port = OL_CEPH_APP_PORT;
static int      time_to_run = OL_CEPH_GENERATOR_LIM_UNSPEC;
static char    *iface = NULL;

static ol_cmdline_opt opts[] =
{
    {"srv-addr", OL_OPT_STR, &srv_addr,
                 "Address which an application connects to. Omitting the "
                 "option means passive connection opening. "},
    {"srv-port", OL_OPT_INT, &srv_port, "Server port to bind on server and to "
                 "connect on client. If the option is omitted, default port "
                 "(" OL_CEPH_APP_PORT_STR ") is used."},
    {"time-to-run", OL_OPT_INT, &time_to_run,
                    "How long to run generator in seconds. If the option is "
                    "omitted, application runs in receiver mode."},
    {"iface", OL_OPT_STR, &iface, "Name of the interface via which data will "
                                  "flow."},
    {"help", OL_OPT_FLAG, &print_help, "Print help."},
};
#define OPTS_NUM (sizeof(opts) / sizeof(opts[0]))

static void
usage(const char *prog_name)
{
    int i = 0;

    printf("\n");
    printf("Usage: %s [options]\n", prog_name);
    printf("\noptions:\n");

    for (i = 0; i < OPTS_NUM; ++i)
        printf("    --%-20s -- %s\n", opts[i].name, opts[i].usage);

    printf("\nExamples:\n\n");
    printf("  %s --time-to-run 5 --srv_addr 1.2.3.4\n"
           "    Run CEPH generator that connects actively to 1.2.3.4 address "
           "and sends traffic for 5 seconds\n\n", prog_name);
    printf("  %s --time-to-run 5\n"
           "    Run CEPH generator that waits for incoming TCP connections, "
           "and, when connected, sends traffic for 5 seconds\n\n", prog_name);
    printf("  %s --srv_addr 1.2.3.4\n"
           "    Run CEPH receiver that connects actively to 1.2.3.4 "
           "address\n\n", prog_name);
    printf("  %s\n"
           "    Run CEPH receiver that waits for incoming TCP connections\n\n",
           prog_name);
}

int
main(int argc, char **argv)
{
    ol_ceph_state   app = {0};
    int             ret = 0;

    ret = ol_cmdline_getopt(argc, argv, opts, OPTS_NUM);
    if (ret != 0 || print_help)
    {
        usage(basename(argv[0]));
        return ret;
    }

    app.buf = buf;
    app.bufsize = sizeof(buf);

    if (time_to_run != OL_CEPH_GENERATOR_LIM_UNSPEC)
        ret = ol_ceph_generator(&app, srv_addr, srv_port, time_to_run);
    else
        ret = ol_ceph_receiver(&app, srv_addr, srv_port, iface);

    free(srv_addr);
    free(iface);

    return ret;
}
