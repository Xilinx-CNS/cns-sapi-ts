/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-slapd_ldapsearch slapd and ldapsearch functionality
 *
 * @objective Check that slapd and ldapsearch work together correctly.
 *
 * @param pco_iut    PCO for the IUT
 * @param pco_tst    PCO for the TST
 * @param server     Is IUT tested as slapd server?
 *
 * @par Scenario
 * -# Choose unused port P1 on the @p pco_srv.
 * -# Start slapd on pco_srv with P1 port with sample database.
 * -# Get output of ldapsearch and check it.
 * -# Kill slapd on the @p pco_srv.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_srv and 
 *    @p pco_clnt.
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/slapd_ldapsearch"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/** LDAP database stub name */
#define DBNAME  "sample.ldif"

#define FIND_NEXT_LINE(p) \
    do                                                        \
    {                                                         \
        if(((p) = strchr((p), '\n')) != NULL)                 \
            (p)++;                                            \
        else                                                  \
            TEST_FAIL("Unexpected end of ldapsearch output"); \
    }                                                         \
    while(0)

#define CHECK_EMPTY_LINE(p) \
    do                                                        \
    {                                                         \
        if (os == OS_LINUX)                                   \
        {                                                     \
            if (*(p)++ != '\n')                               \
                TEST_FAIL("Unexpected empty line absence");   \
        }                                                     \
    }                                                         \
    while(0)


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    te_bool                server;

    rcf_rpc_server  *srv = NULL;
    rcf_rpc_server  *clnt = NULL;
    struct sockaddr *srv_addr;

    cfg_handle      handle = CFG_HANDLE_INVALID;
    uint16_t        slapd_port;

    char           *buf = NULL;
    char            filename[RCF_MAX_PATH];
    char            remote_file[RCF_MAX_PATH];
    struct stat     st;

    char const *ldapsearch_cmdline = "echo \"slapd_ldapsearch test "
                                     "internal error: ldapsearch_cmdline "
                                     "variable is not initialized\"";

    char const *const version_substring = "version:";
    char const *const answer_substring  = "dn: uid=tester,";

    os_t os;
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(server);
    
    TE_SPRINTF(filename, "%s/sockapi-ts/services/%s", 
               getenv("TE_INSTALL_SUITE"), DBNAME);
    
    if (stat(filename, &st) != 0)
        TEST_FAIL("File " DBNAME "does not exist");
        
    TE_SPRINTF(remote_file, "/tmp/slapd_ldapsearch_%s", 
               tapi_file_generate_name());
    
    if (remote_file == NULL)
        TEST_STOP;

    srv = server ? pco_iut : pco_tst;
    clnt = server ? pco_tst : pco_iut;
    srv_addr = (struct sockaddr *)(server ? iut_addr : tst_addr);

    CHECK_RC(rcf_ta_put_file(srv->ta, 0, filename, remote_file));
    
    slapd_port = ntohs(te_sockaddr_get_port(srv_addr));

    if (cfg_add_instance_fmt(&handle, CVT_STRING, remote_file, 
                             "/agent:%s/slapd:%d", srv->ta, slapd_port) != 0)
    {
        TEST_FAIL("Cannot configure slapd with port %d on the TA %s",
                  slapd_port, srv->ta);
    }

    switch(os = OS(pco_iut))
    {
        case OS_LINUX:
            ldapsearch_cmdline = "ldapsearch -LL -x -b dc=testing,dc=te "
                                 "-H ldap://%s:%d/ uid=tester cn";
            break;
        case OS_SOLARIS:
            ldapsearch_cmdline = "ldapsearch -L -b dc=testing,dc=te "
                                 "-h %s:%d uid=tester cn";
            break;
        case OS_FREEBSD:
            TEST_FAIL("FreeBSD is not supported yet");
            break;
        default:
            TEST_FAIL("It seems OS() is updated but test is not aware of");
    }

    rpc_shell_get_all(clnt, &buf, ldapsearch_cmdline,
                      -1, inet_ntoa(SIN(srv_addr)->sin_addr), slapd_port);

    /* Check buf */
    RING("ldapsearch output:\n%s-------", buf);

    /* As Solaris has no option to disable printing of the LDIF version,
     * so Linux is instructed to print version string too - perform checking.
     */
    if (strncmp(buf, version_substring, strlen(version_substring)) == 0)
        FIND_NEXT_LINE(buf);

    /* Linux's ldapsearch inserts additional empty lines */
    CHECK_EMPTY_LINE(buf);

    if (strncmp(buf, answer_substring, strlen(answer_substring)) != 0)
        TEST_FAIL("Unexpected slapd answer:\n%s", buf);

    FIND_NEXT_LINE(buf);

    if (strncmp(buf, "cn: Tester Tester", strlen("cn: Tester Tester")) != 0)
        TEST_FAIL("Unexpected cn attribute in slapd answer: \"%s\" (%c %d)",
                  buf, buf[0], strlen(buf));

    FIND_NEXT_LINE(buf);

    /* Linux's ldapsearch inserts additional empty lines */
    CHECK_EMPTY_LINE(buf);

    if (*buf != '\0')
        TEST_FAIL("Unexpected extra slapd answer:\n%s", buf);

    TEST_SUCCESS;

cleanup:
    if (handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(handle, FALSE));

    if (remote_file != NULL)
        rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink", &rc, 1, 
                    FALSE, RCF_STRING, remote_file);
    
    TEST_END;
}
