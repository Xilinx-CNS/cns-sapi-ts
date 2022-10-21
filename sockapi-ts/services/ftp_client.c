/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ftp_client FTP client functionality
 *
 * @objective Check that FTP client are able to connect to FTP server
 *            for files downloading/uploading.
 *
 * @param pco_tst1   Tester PCO 
 * @param pco_tst2   Tester PCO 
 * @param library    transport library to be used on the IUT
 * @param passive    if @c TRUE, use passive mode
 * @param ftp_client FTP client program to be used (ftp, lftp, ncftp).
 *
 * @pre Host with @p pco_iut should have two network interfaces.
 *      One should be connected to the host with @p pco_tst1; other - to
 *      the host with @p pco_tst2.
 *
 * @par Scenario
 * -# Enable FTP servers on @p pco_tst1 and @p pco_tst2.
 * -# Generate file @p g and put it to @p pco_iut.                      
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Create .netrc file in /tmp on the @p pco_iut with the string 
 * \n default login anonymous password foobar
 * -# For @p pco_tst1 and @p pco_tst2 perform the following:
 *   -# Generate file @p f to @p pco_tstN to "pub" directory of anonymous home.
 *   -# Remove file @p f from @p pco_iut, if exists.
 *   -# Execute command 
 *   \n HOME=/tmp &lt;ftp_client&gt; pco_tstN 
 *   \n command and connect to its standard input.
 *   -# If @p passive, enable passive mode using client-dependent command.
 *   -# Pass commands 'cd pub', 'get f', 'put g' and 'bye' to the standard input
 *      of the FTP client. 
 *   -# Check that file @p f arose on the @p pco_iut and file @p g
 *      arose on @p pco_tstN.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Remove all files created during the test.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ftp_client"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "tapi_tad.h"
/*
 * FIXME: test is broken - tcl/expect functionality has been disabled, see
 * OL bug 10742.
 */
#include "tapi_cli.h"
#include "services.h"

#define DATA_BULK       128  /**< Size of data to be sent/received */

/** IUT PCO handle */
static rcf_rpc_server *pco_iut = NULL;

/** FTP client CLI CSAP on the PCO IUT */
static csap_handle_t csap = CSAP_INVALID_HANDLE;

/** If true, passive FTP mode should ba used */
static te_bool passive;

static char  pattern[DATA_BULK]; /**< Data contained in transferred files */
static char  buf[DATA_BULK + 1]; /**< Auxiliary buffer */
static char *localfile;          /**< File generated on the engine */

/** Information about each temporary file created on any TA */
static struct {
    char *ta;
    char  file[RCF_MAX_PATH];
} tmp_files[16];

/** Index in the temporary file array */
static int ind = 0;

/** Add TA/file to the list of files to be deleted during cleanup */
#define TMP_FILE(_ta, _file) \
    do {                                    \
        tmp_files[ind].ta = _ta;            \
        strcpy(tmp_files[ind].file, _file); \
        ind++;                              \
    } while (0)

/** 
 * Login to ftp server.
 *
 * @param server        IP address of the FTP server
 */
typedef void (* login)(const char *server);

/** 
 * Put file to the FTP server.

 *
 * @param file   local file name
 */
typedef void (* put_file)(const char *file);

/** 
 * Get file from the FTP server.
 *
 * @param file   remote file name
 */
typedef void (* get_file)(const char *file);

/** Routines to work with the client specified in the test parameter */
static login    login_rtn;
static put_file put_file_rtn;
static get_file get_file_rtn;

/**
 * Enter command on the client and check an answer.
 *
 * @param p_answer      location for answer or NULL
 * @param fmt           command format string
 */
static inline void
ftp_write(char **p_answer, char *fmt, ...)
{
    char *msg = NULL;
    
    va_list ap;
    
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    
    if (tapi_cli_send_recv(pco_iut->ta, 0, csap, buf, &msg, 10) != 0)
        TEST_FAIL("tapi_cli_send_recv() failed for command <%s>", buf);
        
    if (msg == NULL)
        TEST_FAIL("tapi_cli_send_recv() returned NULL answer");
        
    if (p_answer != NULL)
        *p_answer = msg;
    else
        free(msg);
}

static void
ftp_login(const char *server)
{
    char *answer = NULL;
    int   rc;

    sprintf(buf, "HOME=/tmp ftp -p %s", server);

    if ((rc = tapi_cli_csap_shell_create(pco_iut->ta, 0, buf, 
                  TAPI_CLI_PROMPT_TYPE_PLAIN, "ftp> ", 
                  TAPI_CLI_PROMPT_TYPE_PLAIN, NULL, NULL, 
                  TAPI_CLI_PROMPT_TYPE_PLAIN, NULL, NULL, &csap)) != 0)
    {                 
        TEST_FAIL("tapi_cli_csap_create() failed; error %r", rc); 
    }

    ftp_write(&answer, "cd pub");
    if (strstr(answer, "250") == NULL)
    {
        ERROR("Cannot change directory; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
    ftp_write(NULL, "binary");
    if (!passive)
        ftp_write(NULL, "passive");
    ftp_write(NULL, "lcd /tmp");
}

static void
ftp_put_file(const char *file)
{
    char *answer;
    
    ftp_write(&answer, "put %s", file);
    if (strstr(answer, "bytes") == NULL)
    {
        ERROR("Failed to put file; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
}

static void
ftp_get_file(const char *file)
{
    char *answer;
    
    ftp_write(&answer, "get %s", file);
    if (strstr(answer, "bytes") == NULL)
    {
        ERROR("Failed to get file; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
}

static void
lftp_login(const char *server)
{
    char *answer;
    int   rc;
    
    sprintf(buf, "HOME=/tmp lftp %s", server);

    if ((rc = tapi_cli_csap_shell_create(pco_iut->ta, 0, buf, 
                  TAPI_CLI_PROMPT_TYPE_REG_EXP, "lftp .*> ", 
                  TAPI_CLI_PROMPT_TYPE_PLAIN, NULL, NULL, 
                  TAPI_CLI_PROMPT_TYPE_PLAIN, NULL, NULL, &csap)) != 0)
    {                 
        TEST_FAIL("tapi_cli_csap_create() failed; error %r", rc); 
    }
    
    ftp_write(&answer, "cd pub");
    if (strstr(answer, "cd ok") == NULL)
    {
        ERROR("Cannot change directory; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
    ftp_write(NULL, "set ftp:passive-mode %s", passive ? "on" : "off");
    ftp_write(NULL, "lcd /tmp");
}

static void
lftp_put_file(const char *file)
{
    char *answer;
    
    ftp_write(&answer, "put %s", file);
    if (strstr(answer, "bytes") == NULL)
    {
        ERROR("Failed to put file; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
}

static void
lftp_get_file(const char *file)
{
    char *answer;
    
    ftp_write(&answer, "get %s", file);
    if (strstr(answer, "bytes") == NULL)
    {
        ERROR("Failed to get file; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
}

static void
ncftp_login(const char *server)
{
    char *answer;
    int   rc;
    
    sprintf(buf, "HOME=/tmp ncftp %s", server);

    if ((rc = tapi_cli_csap_shell_create(pco_iut->ta, 0, buf, 
                  TAPI_CLI_PROMPT_TYPE_REG_EXP, "ncftp .*> ", 
                  TAPI_CLI_PROMPT_TYPE_PLAIN, NULL, NULL, 
                  TAPI_CLI_PROMPT_TYPE_PLAIN, NULL, NULL, &csap)) != 0)
    {                 
        TEST_FAIL("tapi_cli_csap_create() failed; error %r", rc); 
    }
    
    ftp_write(NULL, "set confirm-close no");
    ftp_write(NULL, "set passive %s", passive ? "on" : "off");
    ftp_write(&answer, "cd pub");
    free(answer);
    ftp_write(NULL, "binary");
    ftp_write(NULL, "lcd /tmp");
}

static void
ncftp_put_file(const char *file)
{
    char *answer;
    
    ftp_write(&answer, "put %s", file);
    if (strstr(answer, "B/s") == NULL)
    {
        ERROR("Failed to put file; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
}

static void
ncftp_get_file(const char *file)
{
    char *answer;
    
    ftp_write(&answer, "get %s", file);
    if (strstr(answer, "B/s") == NULL)
    {
        ERROR("Failed to get file; FTP server returned:\n%s", answer);
        free(answer);
        TEST_STOP;
    }
    free(answer);
}

/**
 * Check that file arised on the specified TA and has the content is correct.
 *
 * @param ta    Test Agent
 * @param path  file pathname on the TA
 */
static void
check_file(char *ta, const char *path)
{
    char *tmpfile = tapi_file_generate_pathname();
    FILE *f;
    int   len;
    
    if (rcf_ta_get_file(ta, 0, path, tmpfile) != 0)
        TEST_FAIL("Cannot get file %s from the %s", path, ta);
        
    if ((f = fopen(tmpfile, "r")) == NULL)
    {
        unlink(tmpfile);
        TEST_FAIL("Cannot open temporary file for reading");
    }
    len = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    unlink(tmpfile);
    
    if (len != DATA_BULK)
        TEST_FAIL("Incorrect length of transferred file: %d instead %d",
                  len, DATA_BULK);

    if (memcmp(buf, pattern, DATA_BULK) != 0)
        TEST_FAIL("Data are corrupted during transferring", len, DATA_BULK);
}

/**
 * Check that file downloading/uploading may be performed successfully.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       tester PCO
 * @param get           if TRUE, the file should be downloaded
 */
static void
check_op(rcf_rpc_server *pco_tst, te_bool get)
{
    char *fname = tapi_file_generate_name();
    char  tst_f[RCF_MAX_PATH];
    char  iut_f[RCF_MAX_PATH];
    int   rc;
    
    char *orig = get ? tst_f : iut_f;
    char *copy = get ? iut_f : tst_f;
    char *orig_ta = get ? pco_tst->ta : pco_iut->ta;
    char *copy_ta = get ? pco_iut->ta : pco_tst->ta;
    
    sprintf(tst_f, RCF_FILE_FTP_PREFIX "pub/%s", fname);
    sprintf(iut_f, "/tmp/%s", fname);
    if ((rc = rcf_ta_put_file(orig_ta, 0, localfile, orig)) != 0)
        TEST_FAIL("Cannot put file %s to %s:%s %x", 
                  localfile, orig, orig_ta, rc); 
    
    TMP_FILE(orig_ta, orig);
    TMP_FILE(copy_ta, copy);
   
    if (get)
        get_file_rtn(fname);
    else
        put_file_rtn(fname); 

    check_file(copy_ta, copy);
}

/**
 * Logout from the FTP client.
 *
 * @return 0 (success) or -1 (failure)
 */
static int
ftp_logout()
{
    int rc = 0;
    
    if (tapi_cli_send(pco_iut->ta, 0, csap, "bye") != 0)
        WARN("tapi_cli_send_recv() failed for command <bye>");
    
    if (tapi_tad_csap_destroy(pco_iut->ta, 0, csap) != 0)
        WARN("tapi_tad_csap_destroy() failed");
    
    return rc;
}


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *tst2_addr;
    const char             *ftp_client;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_STRING_PARAM(ftp_client);
    TEST_GET_BOOL_PARAM(passive);

    TEST_CHECK_SERVICE(pco_tst->ta, ftpserver);
    TEST_CHECK_SERVICE(pco_tst2->ta, ftpserver);

    if (strcmp(ftp_client, "ftp") == 0)
    {
        login_rtn = ftp_login;
        get_file_rtn = ftp_get_file;
        put_file_rtn = ftp_put_file;
    }
    else if (strcmp(ftp_client, "lftp") == 0)
    {
        login_rtn = lftp_login;
        get_file_rtn = lftp_get_file;
        put_file_rtn = lftp_put_file;
    }
    else if (strcmp(ftp_client, "ncftp") == 0)
    {
        login_rtn = ncftp_login;
        get_file_rtn = ncftp_get_file;
        put_file_rtn = ncftp_put_file;
    }
    else
        TEST_FAIL("Unsupported FTP client: %s", ftp_client);

    CHECK_NOT_NULL(localfile = tapi_file_create(DATA_BULK, pattern, TRUE));

    CHECK_RC(tapi_file_create_ta(pco_iut->ta, "/tmp/.netrc", "%s",
                                 "default login anonymous password foobar"));
    TMP_FILE(pco_iut->ta, "/tmp/.netrc");

    /* Solaris requires this to be */
    rpc_system(pco_iut, "chmod go-rwx /tmp/.netrc");

    /* Start FTP server on tester PCOs */                                 
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)1, 
                                  "/agent:%s/ftpserver:", pco_tst->ta));
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)1, 
                                  "/agent:%s/ftpserver:", pco_tst2->ta));
    SLEEP(1);
    
    login_rtn(te_sockaddr_get_ipstr(tst_addr));
    check_op(pco_tst, TRUE);
    check_op(pco_tst, FALSE);

    if (ftp_logout() != 0)
    {
        csap = CSAP_INVALID_HANDLE;
        TEST_STOP;
    }
    csap = CSAP_INVALID_HANDLE;

    login_rtn(te_sockaddr_get_ipstr(tst2_addr));
    check_op(pco_tst2, TRUE);
    check_op(pco_tst2, FALSE);

    TEST_SUCCESS;

cleanup:
    if (csap != CSAP_INVALID_HANDLE && ftp_logout() != 0)
        result = -1;

    /* Delete temporary files */
    for (; ind > 0; ind--)
        rcf_ta_del_file(tmp_files[ind - 1].ta, 0, tmp_files[ind - 1].file);
    
    if (localfile != NULL)
    {
        unlink(localfile);
        free(localfile);
    }

    SLEEP(5);

    TEST_END;
}

