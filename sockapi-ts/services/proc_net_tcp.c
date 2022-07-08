/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-ftp_put_get FTP PUT and GET commands processing by FTP server
 *
 * @objective Check that FTP server properly receives/sends data
 *            via secondary connection in active and passive modes.
 *
 * @type conformance
 *
 * @param pco_iut   IUT PCO
 * @param pco_tst   Tester PCO
 * @param library   transport library to be used by the FTP server
 *
 * @par Scenario
 * -# Stop FTP server on the @p pco_iut (if it is running).
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Start FTP server on the @p pco_iut in standalone mode.
 * -# If @p get, prepare and put file @p f_iut to pub directory of
 *    the anonymous home on the @p iut.
 * -# For @p pco_ts1 and @p pco_tst2 simultaneously:
 *   -# Connect from @p pco_tstN to FTP port of the @p pco_iut.
 *   -# If @p passive, issue command PASV to the connection.
 *   -# If @p get issue the @c FTP @c GET command for file @p f_iut; otherwise
 *      issue @c FTP @c PUT command for file @p f_tstN on the @p pco_tstN.
 *   -# If @p passive, create the data connection from @p pco_tstN,
 *      otherwise accept the data connection from the FTP server.
 *   -# If @p get, read data and compare them with the content of file
 *      @p f_iut. Check that server closed the connection correctly
 *      (try to read more data and check that @b read() returned 0).
 *   -# If put, send data to the data connection from @p pco_tstN and close
 *      data connection.
 *   -# If put, retrieve the file @p f_tstN from @p pco_tstN and compare
 *      them with sent data.
 * -# Stop FTP server on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Remove all files created during the test on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/proc_net_tcp"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

static char buf[150 * 100];

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int s_l = -1;
    int s_c1 = -1;
    int s_c2 = -1;
    int s_c3 = -1;
    int s_c4 = -1;
    int c_c1 = -1;
    int c_c2 = -1;
    int c_c3 = -1;
    int c_c4 = -1;
    int fd;

    struct sockaddr_in addr;
    unsigned int       addr_len;

    unsigned short port, port1, port2, port3, port4;

    int   size_to_read = 0;
    int   found = 0;
    char *s;
    int   got_bytes;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(buf, 0, sizeof(buf));

    /* Create connections and find ports */
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &c_c1, &s_c1);

    ((struct sockaddr_in *)tst_addr)->sin_port++;
    ((struct sockaddr_in *)iut_addr)->sin_port++;
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &c_c2, &s_c2);

    ((struct sockaddr_in *)tst_addr)->sin_port++;
    ((struct sockaddr_in *)iut_addr)->sin_port++;
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &c_c3, &s_c3);

    ((struct sockaddr_in *)tst_addr)->sin_port++;
    ((struct sockaddr_in *)iut_addr)->sin_port++;
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &c_c4, &s_c4);

    ((struct sockaddr_in *)iut_addr)->sin_port++;
    s_l = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, s_l, iut_addr);
    rpc_listen(pco_iut, s_l, 5);

    addr_len = sizeof(addr);
    rpc_getsockname(pco_iut, s_l, (struct sockaddr *)&addr, &addr_len);
    port = ntohs(addr.sin_port);

    addr_len = sizeof(addr);
    rpc_getsockname(pco_iut, s_c1, (struct sockaddr *)&addr, &addr_len);
    port1 = ntohs(addr.sin_port);

    addr_len = sizeof(addr);
    rpc_getsockname(pco_iut, s_c2, (struct sockaddr *)&addr, &addr_len);
    port2 = ntohs(addr.sin_port);

    addr_len = sizeof(addr);
    rpc_getsockname(pco_iut, s_c3, (struct sockaddr *)&addr, &addr_len);
    port3 = ntohs(addr.sin_port);

    addr_len = sizeof(addr);
    rpc_getsockname(pco_iut, s_c4, (struct sockaddr *)&addr, &addr_len);
    port4 = ntohs(addr.sin_port);

    /* Read and parse /proc/net/tcp to find a place to stop reading */
    fd = rpc_open(pco_iut, "/proc/net/tcp", RPC_O_RDONLY, 0);
    got_bytes = 0;
    rc = rpc_read(pco_iut, fd, buf, sizeof(buf));
    while (rc > 0)
    {
        got_bytes += rc;
        rc = rpc_read(pco_iut, fd, buf + got_bytes, sizeof(buf) - got_bytes);
    }
    if (got_bytes == sizeof(buf))
    {
        TEST_FAIL("File is too long");
    }
    
    RPC_CLOSE(pco_iut, fd);

    for (s = buf; s != NULL; s = strchr(s + 1, '\n'))
    {
        unsigned int tmp_port;

        rc = sscanf(s, "%*d: %*x:%x", &tmp_port);
        if (rc == 1 && (tmp_port == port || 
                        tmp_port == port1 || tmp_port == port2 ||
                        tmp_port == port3 || tmp_port == port4))
        {
            found++;
            RING("got port %d, 0x%x", tmp_port, tmp_port);
            if (found == 2) {
                size_to_read = (s - buf) - 10;
            }
        }
    }
    if (found != 5)
    {
        ERROR("Expected 5 entries, got %d", found);
        TEST_FAIL("%s", buf);
    }
    RING("strlen %d", strlen(buf));
    RING("/proc/net/tcp is correct:\n%s", buf);

    /* Close listen socket and try to catch race condition */
    fd = rpc_open(pco_iut, "/proc/net/tcp", RPC_O_RDONLY, 0);

    got_bytes = 0;
    rc = rpc_read(pco_iut, fd, buf, size_to_read);
    while (got_bytes + rc < size_to_read && rc > 0)
    {
        got_bytes += rc;
        rc = rpc_read(pco_iut, fd, buf + got_bytes, size_to_read - got_bytes);
    }
    RPC_CLOSE(pco_iut, s_l);
    rc = rpc_read(pco_iut, fd, buf + size_to_read, sizeof(buf) - size_to_read);
    while (rc > 0)
    {
        got_bytes += rc;
        rc = rpc_read(pco_iut, fd, buf + got_bytes, sizeof(buf) - got_bytes);
    }

    found = 0;
    for (s = buf; s != NULL; s = strchr(s + 1, '\n'))
    {
        int tmp_port;

        sscanf(s, "%*d: %*x:%x", &tmp_port);
        if (tmp_port == port || tmp_port == port1 || tmp_port == port2 ||
            tmp_port == port3 || tmp_port == port4)
        {
            RING("got port %d, 0x%x", tmp_port, tmp_port);
            found++;
        }
    }
    if (found != 4)
    {
        ERROR("Expected 4 entries, got %d", found);
        TEST_FAIL("%s", buf);
    }
    RING("/proc/net/tcp is correct:\n%s", buf);

    RPC_CLOSE(pco_iut, fd);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, s_l);
    CLEANUP_RPC_CLOSE(pco_iut, s_c1);
    CLEANUP_RPC_CLOSE(pco_iut, s_c2);
    CLEANUP_RPC_CLOSE(pco_iut, s_c3);
    CLEANUP_RPC_CLOSE(pco_iut, s_c4);
    CLEANUP_RPC_CLOSE(pco_iut, c_c1);
    CLEANUP_RPC_CLOSE(pco_iut, c_c2);
    CLEANUP_RPC_CLOSE(pco_iut, c_c3);
    CLEANUP_RPC_CLOSE(pco_iut, c_c4);


    TEST_END;
}

