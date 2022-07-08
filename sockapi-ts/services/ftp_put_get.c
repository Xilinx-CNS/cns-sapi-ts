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
 * @param pco_tst1  Tester PCO
 * @param pco_tst2  Tester PCO
 * @param passive   if @c TRUE, use passive mode
 * @param get       if @c TRUE, the file should be get from the server
 * @param library   transport library to be used by the FTP server
 *
 * @pre Host with @p pco_iut should have two network interfaces.
 *      One should be connected to the host with @p pco_tst1; other - to
 *      the host with @p pco_tst2.
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

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "services/ftp_put_get"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

#define DATA_BULK       128  /**< Size of data to be sent/received */

static char buf[DATA_BULK + 1];
static char pattern[DATA_BULK];

/** Data corresponding to one tester PCO */
struct {
    rcf_rpc_server *clnt;        /**< Tester PCO */

    char fname[RCF_MAX_PATH];    /**< File name on the TA */
    char url[RCF_MAX_PATH];      /**< URL */
    int  s;                      /**< Data connection socket */
    int  s_c;                    /**< Control connection socket */
} tdata[2];

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *tst2_addr;
    te_bool                 passive;
    te_bool                 get;
    const char             *server;

    cfg_handle handle = CFG_HANDLE_INVALID;

    char   *name = NULL;
    char   *localfile = NULL;
    int     enable;
    int     i;

    TEST_START;

    memset(tdata, 0, sizeof(tdata));
    tdata[0].s = tdata[1].s = -1;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    tdata[0].clnt = pco_tst;
    TEST_GET_PCO(pco_tst2);
    tdata[1].clnt = pco_tst2;
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_BOOL_PARAM(get);
    TEST_GET_BOOL_PARAM(passive);
    TEST_GET_STRING_PARAM(server);

    TEST_CHECK_SERVICE(pco_iut->ta, ftpserver);

    /* Disable FTP server */
    CHECK_RC(cfg_find_fmt(&handle, "/agent:%s/ftpserver:", pco_iut->ta));
    CHECK_RC(cfg_get_instance(handle, NULL, &enable));
    if (enable)
        CHECK_RC(cfg_set_instance(handle, CVT_INTEGER, 0));

    /* Specify server to be tested */
    CHECK_RC(cfg_set_instance_fmt(CVT_STRING, server,
                                  "/agent:%s/ftpserver:/server:",
                                  pco_iut->ta));

    SLEEP(5); /* xinetd needs some time to get up. */
    /* Enable FTP server */
    CHECK_RC(cfg_set_instance(handle, CVT_INTEGER, 1));
    SLEEP(5); /* xinetd needs some time to get up. */

    name = tapi_file_generate_name();
    sprintf(tdata[0].fname, RCF_FILE_FTP_PREFIX "pub/%s", name);
    sprintf(tdata[0].url, "ftp://anonymous:null@%s/pub/%s",
            te_sockaddr_get_ipstr(iut_addr), name);

    name = tapi_file_generate_name();
    sprintf(tdata[1].fname, RCF_FILE_FTP_PREFIX "pub/%s", name);
    sprintf(tdata[1].url, "ftp://anonymous:null@%s/pub/%s",
            te_sockaddr_get_ipstr(iut_addr2), name);
    tdata[0].s_c = tdata[1].s_c = -1;

    CHECK_NOT_NULL(localfile = tapi_file_create(DATA_BULK, pattern, TRUE));
    if (get)
    {
        for (i = 0; i < 2; i++)
            CHECK_RC(rcf_ta_put_file(pco_iut->ta, 0, localfile,
                                     tdata[i].fname));
    }

    for (i = 0; i < 2; i++)
        tdata[i].s = rpc_ftp_open(tdata[i].clnt, tdata[i].url, get,
                                  passive, 0, &tdata[i].s_c);

    /* Send data via secondary connection */
    for (i = 0; i < 2; i++)
    {
        int   len;
        FILE *f = NULL;

        if (get)
        {
            len = rpc_recv(tdata[i].clnt, tdata[i].s, buf, sizeof(buf), 0);
            if (len != DATA_BULK)
                TEST_FAIL("Incorrect number of bytes is received: %d "
                          "instead %d", len, DATA_BULK);

            if ((rc = rpc_read(tdata[i].clnt, tdata[i].s, buf,
                               sizeof(buf))) != 0)
            {
                 TEST_FAIL("Unexpected read() result %d after finishing"
                           " of the file receiving", rc);
            }
        }
        else
        {
            RPC_SEND(len, tdata[i].clnt, tdata[i].s, pattern, DATA_BULK, 0);
            RPC_CLOSE(tdata[i].clnt, tdata[i].s);
            SLEEP(1); /* It is better to check ftp server reply... */
            CHECK_RC(rcf_ta_get_file(pco_iut->ta, 0,
                                     tdata[i].fname, localfile));
        }

        /* Compare transferred data */
        if ((f = fopen(localfile, "r")) == NULL)
            TEST_FAIL("Cannot open file %s", localfile);

        len = fread(buf, 1, sizeof(buf), f);
        fclose(f);

        if (!get && len != DATA_BULK)
            TEST_FAIL("Incorrect number of bytes is stored on the server: "
                      "%d instead %d", len, DATA_BULK);

        if (memcmp(buf, pattern, DATA_BULK) != 0)
            TEST_FAIL("Data are corrupted during transfering");
    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < 2; i++)
    {
        if (*tdata[i].fname != 0)
            rcf_ta_del_file(pco_iut->ta, 0, tdata[i].fname);

        CLEANUP_RPC_CLOSE(tdata[i].clnt, tdata[i].s);
        CLEANUP_RPC_FTP_CLOSE(tdata[i].clnt, tdata[i].s_c);
    }

    if (handle != CFG_HANDLE_INVALID)
        cfg_set_instance(handle, CVT_INTEGER, 0);

    if (localfile != NULL)
    {
        unlink(localfile);
        free(localfile);
    }

    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
