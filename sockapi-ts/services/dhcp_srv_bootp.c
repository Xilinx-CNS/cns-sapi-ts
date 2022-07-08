/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-dhcp_srv_bootp DHCP server / BOOTP client interaction
 *
 * @objective Check that DHCP server may process BOOTP client requests.
 *
 * @param pco_iut       IUT PCO 
 * @param pco_tst1      Tester PCO
 * @param pco_tst2      Tester PCO 
 * @param bind_if1      Bind DHCP server to interface which connects
 *                      with the host with @p pco_tst1
 * @param bind_if2      Bind DHCP server to interface which connects
 *                      with the host with @p pco_tst2
 * @param library       Transport library to be used on the IUT
 *
 * @pre Host with @p pco_iut should have two network interfaces.
 *      One should be connected to the host with @p pco_tst1;
 *      other - to the host with @p pco_tst2.
 *
 * @par Scenario
 * -# Stop DHCP server on the @p pco_iut (if it is running).
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Configure DHCP server to serve two networks corresponding to network
 *    interfaces of the @p pco_uit host connected to @p pco_tst1 and
 *    @p pco_tst2 correspondingly. Specify host with fixed IP address
 *    in each network (@p host1 and @p host2).
 * -# Start DHCP server.
 * -# Send BOOTP requests on behalf @p host1 and @p host2
 *    from @p pco_tst1 and @p pco_tst2.
 * -# If DHCP server is bound to the corresponding interface or is not
 *    bound at all, receive answer and verify that IP address is the
 *    same as ones specified in DHCP server configuration file.
 * -# Disable DHCP server on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/dhcp_srv_bootp"

#define DHCP_MAGIC_SIZE        4
#define DHCP_VEND_FIELD_SIZE   64

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_tad.h"
#include "tapi_dhcp.h"
#include "tapi_cfg_dhcp.h"
#include "services.h"


static int
test_bootp_request_reply(const char *ta, const char *if_name,
                         const struct sockaddr *lladdr,
                         const struct sockaddr_in *exp_ip,
                         te_bool exp_ok)
{
    int                     i;
    int                     result = EXIT_FAILURE;
    int                     rc;
    uint16_t                flags;
    struct dhcp_message    *request = NULL;
    struct dhcp_message    *reply = NULL;
    unsigned int            timeout;
    const char             *err_msg;

    csap_handle_t           csap = CSAP_INVALID_HANDLE;


    rc = tapi_dhcpv4_plain_csap_create(ta, if_name,
                                       DHCP4_CSAP_MODE_CLIENT,
                                       &csap);
    if (rc != 0)
    {
        TEST_FAIL("Failed to create DHCP client CSAP on %s:%s: %r",
                  ta, if_name, rc);
    }

    request = dhcpv4_bootp_message_create(DHCP_OP_CODE_BOOTREQUEST);
    if (request == NULL)
    {
        TEST_FAIL("Failed to create BOOTP message");
    }

    flags = FLAG_BROADCAST;
    dhcpv4_message_set_flags(request, &flags);
    dhcpv4_message_set_chaddr(request, lladdr->sa_data);

    /* The last option must be the 'end' option */
    dhcpv4_message_add_option(request, 255, 0, NULL);

    /* Complete 'vend' field of 'bootp' packet */
    for (i = 0; i < DHCP_VEND_FIELD_SIZE - DHCP_MAGIC_SIZE - 1; i++)
        dhcpv4_message_add_option(request, 0, 0, NULL);

    timeout = 10000; /* 10 sec */
    reply = tapi_dhcpv4_send_recv(ta, csap, request, &timeout, &err_msg);
    if (exp_ok)
    {
        if (reply == NULL)
        {
            TEST_FAIL("Failed send/receive BOOTP request/reply: %s",
                      err_msg);
        }
        if (reply->yiaddr != exp_ip->sin_addr.s_addr)
        {
            char buf1[INET_ADDRSTRLEN];
            char buf2[INET_ADDRSTRLEN];

            TEST_FAIL("Unexpected IPv4 address '%s' is provided by "
                      "DHCP server instead of expected '%s'",
                      inet_ntop(AF_INET, &reply->yiaddr,
                                buf1, sizeof(buf1)),
                      inet_ntop(AF_INET, &(exp_ip->sin_addr),
                                buf2, sizeof(buf2)));
        }
    }
    else
    {
        if (reply != NULL)
        {
            TEST_FAIL("Unexpected BOOTP reply got, DHCP server is not "
                      "bound to the interface %s:%s the BOOTP request "
                      "was sent", ta, if_name);
        }
        if (err_msg == NULL ||
            strcmp(err_msg, "DHCP message doesn't come") != 0)
        {
            TEST_FAIL("Unexpected error in BOOTP request/reply: %s",
                      err_msg);
        }
    }
    result = EXIT_SUCCESS;

    free(reply);
    free(request);
    if (csap != CSAP_INVALID_HANDLE)
    {
        rc = tapi_tad_csap_destroy(ta, 0, csap);
        if (rc != 0)
        {
            ERROR("tapi_tad_csap_destroy() failed: %r", rc);
            result = EXIT_FAILURE;
        }
    }
    return result;
}


int
main(int argc, char *argv[])
{
    tapi_env_net               *net1 = NULL;
    tapi_env_net               *net2 = NULL;

    tapi_env_host              *host_iut = NULL;
    tapi_env_host              *host_tst1 = NULL;
    tapi_env_host              *host_tst2 = NULL;
    rcf_rpc_server             *pco_iut = NULL;

    const struct if_nameindex  *if_iut1 = NULL;
    const struct if_nameindex  *if_iut2 = NULL;
    const struct if_nameindex  *if_tst1 = NULL;
    const struct if_nameindex  *if_tst2 = NULL;

    const struct sockaddr      *iut1_addr = NULL;
    const struct sockaddr      *iut2_addr = NULL;
    const struct sockaddr      *tst1_la = NULL;
    const struct sockaddr      *tst2_la = NULL;
    struct sockaddr            *tst1_addr = NULL;
    struct sockaddr            *tst2_addr = NULL;

    te_bool                     bind_if1;
    te_bool                     bind_if2;


    TEST_START;

    TEST_GET_NET(net1);
    TEST_GET_NET(net2);
    
    TEST_GET_HOST(host_iut);
    TEST_GET_HOST(host_tst1);
    TEST_GET_HOST(host_tst2);

    TEST_GET_PCO(pco_iut);

    TEST_GET_IF(if_iut1);
    TEST_GET_IF(if_iut2);
    TEST_GET_IF(if_tst1);
    TEST_GET_IF(if_tst2);

    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_iut, iut2_addr);
    TEST_GET_ADDR_NO_PORT(tst1_la);
    TEST_GET_ADDR_NO_PORT(tst2_la);

    TEST_GET_BOOL_PARAM(bind_if1);
    TEST_GET_BOOL_PARAM(bind_if2);

    TEST_CHECK_SERVICE(host_iut->ta, dhcpserver);

    /* Disable DHCP server */
    rc = cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                              "/agent:%s/dhcpserver:", host_iut->ta);
    if (rc != 0)
    {
        TEST_FAIL("Failed to stop DHCP server on TA '%s': %r",
                  host_iut->ta, rc);
    }

    /* Specifiy DHCP server interfaces, if required */
    if (bind_if1 || bind_if2)
    {
        char ifs[((bind_if1) ? (strlen(if_iut1->if_name) + 1) : 0) +
                 ((bind_if2) ? (strlen(if_iut2->if_name) + 1) : 0)];

        *ifs = '\0';
        if (bind_if1)
        {
            strcpy(ifs, if_iut1->if_name);
            if (bind_if2)
                strcat(ifs, " ");
        }
        if (bind_if2)
        {
            strcat(ifs, if_iut2->if_name);
        }
        rc = cfg_set_instance_fmt(CVT_STRING, ifs,
                                  "/agent:%s/dhcpserver:/interfaces:",
                                  host_iut->ta);
        if (rc != 0)
        {
            TEST_FAIL("Failed to set DHCP server interfaces to '%s': %r",
                      ifs, rc);
        }
    }

    /* Add subnet for the first interface/network */
    rc = tapi_cfg_dhcps_add_subnet(host_iut->ta,
                                   net1->ip4addr, net1->ip4pfx,
                                   NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP subnet configuration entry: %r", rc);
    }

    /* Add host declaration for the first client */
    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &tst1_addr, NULL));
    rc = tapi_cfg_dhcps_add_host(host_iut->ta, NULL, NULL,
                                 tst1_la, NULL, 0, tst1_addr,
                                 NULL, NULL, "9", NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP host configuration entry: %r", rc);
    }

    /* Add subnet for the second interface/network */
    rc = tapi_cfg_dhcps_add_subnet(host_iut->ta,
                                   net2->ip4addr, net2->ip4pfx,
                                   NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP subnet configuration entry: %r", rc);
    }

    /* Add host declaration for the second client */
    CHECK_RC(tapi_env_allocate_addr(net2, AF_INET, &tst2_addr, NULL));
    rc = tapi_cfg_dhcps_add_host(host_iut->ta, NULL, NULL,
                                 tst2_la, NULL, 0, tst2_addr,
                                 NULL, NULL, "9", NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP host configuration entry: %r", rc);
    }

    /* Enable DHCP server */
    rc = cfg_set_instance_fmt(CVT_INTEGER, (void *)1,
                              "/agent:%s/dhcpserver:", host_iut->ta);
    if (rc != 0)
    {
        TEST_FAIL("Failed to start DHCP server on TA '%s': %r",
                  host_iut->ta, rc);
    }

    /* Test the first client */
    if (test_bootp_request_reply(host_tst1->ta, if_tst1->if_name, tst1_la,
            SIN(tst1_addr), bind_if1 || !bind_if2) != EXIT_SUCCESS)
    {
        TEST_STOP;
    }
    /* Test the second client */
    if (test_bootp_request_reply(host_tst2->ta, if_tst2->if_name, tst2_la,
            SIN(tst2_addr), bind_if2 || !bind_if1) != EXIT_SUCCESS)
    {
        TEST_STOP;
    }

    TEST_SUCCESS;

cleanup:
        
    TEST_END;
}

