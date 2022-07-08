/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-ftp_many FTP PUT/GET in one control connection
 *
 * @objective Check that FTP server properly satisfies PUT and GET
 *            requested simultaneously via one control connection.
 *
 * @param pco_iut   IUT PCO
 * @param pco_tst1  Tester PCO
 * @param pco_tst2  Tester PCO
 * @param passive   if @c TRUE, use passive mode
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
 * -# Prepare and put file @p f1 and @p f2 to pub directory of
 *    the anonymous home on the @p iut.
 * -# For @p pco_ts1 and @p pco_tst2 simultaneously:
 *   -# Connect from @p pco_tstN to FTP port of the @p pco_iut.
 *   -# If @p passive, issue command PASV to the connection.
 *   -# If issue the @c FTP @c GET command for file @p f1.
 *   -# If issue the @c FTP @c GET command for file @p f2.
 *   -# If issue the @c FTP @c PUT command for file @p f1_tstN.
 *   -# If issue the @c FTP @c PUT command for file @p f2_tstN.
 *   -# If @p passive, create four data connections from @p pco_tstN,
 *      otherwise accept four data connection from the FTP server.
 *   -# Read data from data connections for uploading of @p f1 and @p f2.
 *   -# Write data to data connections for downloading @p f1_tstN and
 *      @p f2_tstN (data reading and writing should be mixed).
 *   -# Close data connections for uploading.
 *   -# Check that FTP server closed data connections for downloading
 *      correctly (try to read more data and check that @b read() returned 0).
 *   -# Compare uploaded and downloaded data with corresponding files.
 * -# Stop FTP server on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Remove all files created during the test on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "services/ftp_many"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

#define DATA_BULK       256  /**< Size of data to be sent/received */

static char buf[DATA_BULK + 1];
static char pattern[DATA_BULK];

/** Data corresponding to one tester PCO */
struct {
    rcf_rpc_server *clnt;         /**< Tester PCO */

    char     fname[RCF_MAX_PATH]; /**< TA filename */
    char     url[RCF_MAX_PATH];   /**< URL */
    int     *s_c;                 /**< Control connection socket */
    int      s;                   /**< Data connection socket */
    te_bool  get;                 /**< If true, get the file */
} tdata[4];

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
    const char             *server;

    cfg_handle handle = CFG_HANDLE_INVALID;

    char *localfile = NULL;
    int   enable;
    int   i;
    int   s_c1 = -1, s_c2 = -1;

    TEST_START;

    /* Prepare tester parameters */
    memset(tdata, 0, sizeof(tdata));
    tdata[0].s = tdata[1].s = tdata[2].s = tdata[3].s = -1;
    tdata[0].s_c = tdata[1].s_c = &s_c1;
    tdata[2].s_c = tdata[3].s_c = &s_c2;

    tdata[0].get = tdata[2].get = TRUE;
    tdata[1].get = tdata[3].get = FALSE;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    tdata[0].clnt = tdata[1].clnt = pco_tst;
    TEST_GET_PCO(pco_tst2);
    tdata[2].clnt = tdata[3].clnt = pco_tst2;
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_BOOL_PARAM(passive);
    TEST_GET_STRING_PARAM(server);

    TEST_CHECK_SERVICE(pco_iut->ta, ftpserver);

    if (strcmp(server, "wuftpd") == 0 ||
        strstr(server, "proftpd") != NULL)
    {
        TEST_FAIL("FTP daemon %s cannot re-use control connection",
                  server);
    }

    /* Disable FTP server */
    CHECK_RC(cfg_find_fmt(&handle, "/agent:%s/ftpserver:", pco_iut->ta));
    CHECK_RC(cfg_get_instance(handle, NULL, &enable));
    if (enable)
        CHECK_RC(cfg_set_instance(handle, CVT_INTEGER, 0));

    /* Specify server to be tested */
    CHECK_RC(cfg_set_instance_fmt(CVT_STRING, server,
                                  "/agent:%s/ftpserver:/server:",
                                  pco_iut->ta));

    /* Enable FTP server */
    CHECK_RC(cfg_set_instance(handle, CVT_INTEGER, 1));
    SLEEP(1);

    CHECK_NOT_NULL(localfile = tapi_file_create(DATA_BULK, pattern, TRUE));
    for (i = 0; i < 4; i++)
    {
        char *name = tapi_file_generate_name();

        sprintf(tdata[i].fname, RCF_FILE_FTP_PREFIX "pub/%s", name);
        sprintf(tdata[i].url, "ftp://anonymous:null@%s/pub/%s",
                te_sockaddr_get_ipstr(i < 2 ? iut_addr : iut_addr2), name);

        if (tdata[i].get)
            CHECK_RC(rcf_ta_put_file(pco_iut->ta, 0, localfile,
                                     tdata[i].fname));
    }

    for (i = 0; i < 4; i++)
        tdata[i].s = rpc_ftp_open(tdata[i].clnt, tdata[i].url,
                                  tdata[i].get, passive, 0, tdata[i].s_c);

    /* Send/receive data via secondary connection */
    for (i = 0; i < 4; i++)
    {
        int   len;
        FILE *f = NULL;

        if (tdata[i].get)
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
            SLEEP(1);
            CHECK_RC(rcf_ta_get_file(pco_iut->ta, 0,
                                     tdata[i].fname, localfile));
        }

        /* Compare transferred data */
        if ((f = fopen(localfile, "r")) == NULL)
            TEST_FAIL("Cannot open file %s", localfile);

        len = fread(buf, 1, sizeof(buf), f);
        fclose(f);

        if (!tdata[i].get && len != DATA_BULK)
            TEST_FAIL("Incorrect number of bytes is stored on the server: "
                      "%d instead %d", len, DATA_BULK);

        if (memcmp(pattern, buf, DATA_BULK) != 0)
            TEST_FAIL("Data are corrupted during transfering");
    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < 4; i++)
        CLEANUP_RPC_CLOSE(tdata[i].clnt, tdata[i].s);

    CLEANUP_RPC_FTP_CLOSE(pco_tst, s_c1);
    CLEANUP_RPC_FTP_CLOSE(pco_tst2, s_c2);

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
