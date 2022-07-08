/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ftp_file Enhanced file downloading via FTP
 *
 * @objective Check that FTP server allows downloading of the one file
 *            by several clients from different offsets.
 *
 * @param pco_iut   IUT PCO 
 * @param pco_tst1  Tester PCO
 * @param pco_tst2  Tester PCO
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
 * -# Prepare the file @p f and put it to @p pco_tst.
 * -# For @p pco_ts1 and @p pco_tst2 simultaneously:
 *   -# Create two connections from @p pco_tstN to FTP port of the @p pco_iut.
 *   -# Issue command PASV to the first connection .
 *   -# Issue the @c FTP @c REST command to both connections specifying
 *      unique offset for each command.
 *   -# Issue the @c FTP @c GET command for file @p f to both connection.
 *   -# Accept data connection from the @p pco_iut corresponding to the
 *      first control connection and establish data connection from the
 *      @p pco_tstN to @p pco_iut corresponding to the second control
 *      connection.
 *   -# Receive data from data connections and verify that they are
 *      the same as corresponding data from the corresponding offset in
 *      the file @p f.
 * -# Stop FTP server on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Remove file @p f from the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "services/ftp_file"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

#define DATA_BULK       256  /**< Size of data to be sent/received */

static char fname[RCF_MAX_PATH];
static char buf[DATA_BULK + 1];
static char pattern[DATA_BULK];

/** Data corresponding to one tester PCO */
struct {
    rcf_rpc_server *clnt;        /**< Tester PCO */
    
    char     url[RCF_MAX_PATH];  /**< URL */
    int     *s_c;                /**< Control connection socket */
    int      s;                  /**< Data connection socket */
    int      offset;             /**< File offset */
    te_bool  passive;            /**< Use passive mode */     
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
    const char             *server;

    cfg_handle handle = CFG_HANDLE_INVALID;

    char *localfile = NULL;
    char *name;
    int   enable;
    int   i;
    int   s_c1 = -1, s_c2 = -1, s_c3 = -1, s_c4 = -1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_CHECK_SERVICE(pco_iut->ta, ftpserver);
    
    /* Prepare tester parameters */
    memset(tdata, 0, sizeof(tdata));
    tdata[0].s = tdata[1].s = tdata[2].s = tdata[3].s = -1;
    tdata[0].s_c = tdata[1].s_c = &s_c1;
    tdata[2].s_c = tdata[3].s_c = &s_c2;
    
    tdata[0].offset = 0;
    tdata[1].offset = DATA_BULK / 4;
    tdata[2].offset = DATA_BULK / 2;
    tdata[3].offset = DATA_BULK / 4 * 3;
    
    tdata[1].passive = tdata[3].passive = TRUE;
    tdata[0].passive = tdata[2].passive = FALSE;

    tdata[0].clnt = tdata[1].clnt = pco_tst;
    TEST_GET_PCO(pco_tst2);
    tdata[2].clnt = tdata[3].clnt = pco_tst2;
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_STRING_PARAM(server);

    /* It seems, that these daemons cannot re-use control connectoin */
    if (strcmp(server, "wuftpd") == 0 ||
        strstr(server, "proftpd") != NULL)
    {
        tdata[1].s_c = &s_c3;
        tdata[3].s_c = &s_c4;
    }

    /* Prepare pattern */
    te_fill_buf(pattern, DATA_BULK);

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
    
    name = tapi_file_generate_name();
    sprintf(fname, RCF_FILE_FTP_PREFIX "pub/%s", name);
    sprintf(tdata[0].url, "ftp://anonymous:null@%s/pub/%s", 
            te_sockaddr_get_ipstr(iut_addr), name);
    strcpy(tdata[1].url, tdata[0].url);

    sprintf(tdata[2].url, "ftp://anonymous:null@%s/pub/%s", 
            te_sockaddr_get_ipstr(iut_addr2), name);
    strcpy(tdata[3].url, tdata[2].url);

    CHECK_NOT_NULL(localfile = tapi_file_create(DATA_BULK, pattern, TRUE));
    CHECK_RC(rcf_ta_put_file(pco_iut->ta, 0, localfile, fname));
        
    for (i = 0; i < 4; i++)
        tdata[i].s = rpc_ftp_open(tdata[i].clnt,
                                  tdata[i].url, TRUE, tdata[i].passive, 
                                  tdata[i].offset, tdata[i].s_c);

    /* Send data via secondary connection */
    for (i = 0; i < 4; i++)
    {
        int len;
        
        len = rpc_recv(tdata[i].clnt, tdata[i].s, buf, sizeof(buf), 0);
        if (len != DATA_BULK - tdata[i].offset)
            TEST_FAIL("Incorrect number of bytes is received: %d "
                      "instead %d", len, DATA_BULK - tdata[i].offset);
                      
        if ((rc = rpc_read(tdata[i].clnt, tdata[i].s, buf, 
                           sizeof(buf))) != 0)
        {
             TEST_FAIL("Unexpected read() result %d after finishing"
                       " of the file receiving", rc);
        }

        /* Compare transferred data */
        if (memcmp(pattern + tdata[i].offset, buf, 
                   DATA_BULK - tdata[i].offset) != 0)
        {
            TEST_FAIL("Data are corrupted during transfering");
        }
    }

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < 4; i++)
        CLEANUP_RPC_CLOSE(tdata[i].clnt, tdata[i].s);

    /* We should read from control sockets before closing. */
    CLEANUP_RPC_FTP_CLOSE(pco_tst, s_c1);
    CLEANUP_RPC_FTP_CLOSE(pco_tst2, s_c2);
    CLEANUP_RPC_FTP_CLOSE(pco_tst, s_c3);
    CLEANUP_RPC_FTP_CLOSE(pco_tst2, s_c4);

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
