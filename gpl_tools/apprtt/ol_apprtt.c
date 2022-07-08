/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Application to measure "app-level" RTT.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <stdbool.h>
#include <libgen.h>

#include "ol_cmdline.h"
#include "ol_client.h"
#include "ol_server.h"
#include "ol_apprtt.h"

/** Send/receive buffer for both server and client. */
static char         buf[APP_BUF_SIZE];

static bool         print_help = false;
static char        *srv_addr = NULL;
static int          chunk_size = 0;
static int          time_to_run = OL_CLIENT_LIM_UNSPEC;
static int          bytes_to_send = OL_CLIENT_LIM_UNSPEC;
static bool         data_check = false;

static ol_cmdline_opt opts[] =
{
    /* Client options */
    {"srv-addr", OL_OPT_STR, &srv_addr,
                 "Address which the client connects to"},
    {"time-to-run", OL_OPT_INT, &time_to_run,
                    "How long to run test in seconds"},
    {"bytes-to-send", OL_OPT_INT, &bytes_to_send, "How much bytes to send"},

    /* Generic options */
    {"chunk-size", OL_OPT_INT, &chunk_size,
               "Chunk of data that the server \"acks\""},
    {"data-check", OL_OPT_FLAG, &data_check,
               "The client sends data according to the pattern. The server "
               "checks that the received data matches the pattern."},
    {"help", OL_OPT_FLAG, &print_help, "Print help"},
};
#define OPTS_NUM            (sizeof(opts) / sizeof(opts[0]))
#define SERVER_OPTS_NUM     0
#define CLIENT_OPTS_NUM     3

static void usage(const char *prog_name)
{
    int i = 0;

    printf("\n");
    printf("Usage:\n");
    printf("  %s [options]\n", prog_name);

    printf("\n  Server options:\n");
    for (i = 0; i < SERVER_OPTS_NUM; ++i)
        printf("     --%-20s -- %s\n", opts[i].name, opts[i].usage);

    printf("\n  Client options:\n");
    for (; i < SERVER_OPTS_NUM + CLIENT_OPTS_NUM; ++i)
        printf("     --%-20s -- %s\n", opts[i].name, opts[i].usage);

    printf("\n  Generic options:\n");
    for (; i < OPTS_NUM; ++i)
        printf("     --%-20s -- %s\n", opts[i].name, opts[i].usage);

    printf("\nExamples:\n");
    printf("  %s --srv_addr 1.2.3.4   - run client side app\n", prog_name);
    printf("  %s                      - run server side app\n\n", prog_name);
}

int main(int argc, char **argv)
{
    ol_app_state    app = {0};
    bool            is_client = false;
    int             ret = 0;

    /*
     * Make stdout line-buffered. It is useful when stdout is piped, e.g. when
     * the application is invoked from TE. See bug 11857.
     */
    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
        perror("setvbuf failed");

    ret = ol_cmdline_getopt(argc, argv, opts, OPTS_NUM);
    if (ret != 0)
    {
        usage(basename(argv[0]));
        return ret;
    }

    if (print_help)
    {
        usage(basename(argv[0]));
        return 0;
    }

    if (srv_addr != NULL)
        is_client = true;

    app.buf = buf;
    app.bufsize = sizeof(buf);

    if (is_client)
    {
        ret = ol_rtt_client(&app, srv_addr, time_to_run, bytes_to_send,
                            chunk_size, data_check);
    }
    else
    {
        ret = ol_rtt_server(&app, chunk_size, data_check);
    }

    free(srv_addr);

    return ret;
}
