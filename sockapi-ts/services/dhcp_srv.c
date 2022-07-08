/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-dhcp_srv  DHCP server functionality
 *
 * @objective Check that DHCP server may process DHCP client requests
 *
 * @param pco_iut    IUT PCO 
 * @param pco_tst1   Tester PCO 
 * @param pco_tst2   Tester PCO 
 * @param library    transport library to be used on the IUT
 *
 * @pre Host with @p pco_iut should have two network interfaces.
 *      One should be connected to the host with @p pco_tst1; other - to
 *      the host with @p pco_tst2.
 *
 * @par Scenario
 * -# Stop DHCP server on the @p pco_iut (if it is running).
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Configure DHCP server to serve two networks corresponding to network
 *    interfaces of the @p pco_uit host connected to @p pco_tst1 and
 *    @p pco_tst2 correspondingly.
 * -# Start DHCP server.
 * -# Send DHCP requests from @p pco_tst1 and @p pco_tst2 to obtain leases.
 * -# Send DHCP requests from @p pco_tst1 and @p pco_tst2 to refresh leases.
 * -# Send DHCP requests from @p pco_tst1 and @p pco_tst2 to release leases.
 * -# Disable DHCP server on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/dhcp_srv"

#define DHCP_MAGIC_SIZE        4

#define SERVER_ID_OPTION       54
#define REQUEST_IP_ADDR_OPTION 50

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "tapi_tad.h"
#include "tapi_dhcp.h"
#include "tapi_cfg_dhcp.h"
#include "services.h"


/**
 * Tries to send DHCP request and waits for ans answer
 *
 * @param ta        TA name
 * @param csap      DHCP CSAP handle
 * @param lladdr    Local hardware address
 * @param type      Message type (DHCP Option 53)
 * @param broadcast Whether DHCP request is marked as broadcast
 * @param myaddr    in: current IP address; out: obtained IP address
 * @param srvaddr   in: current IP address; out: obtained IP address
 * @param xid       DHCP XID field
 * @param xid       DHCP XID field
 *
 * @return boolean success
 */
static te_bool
test_dhcp_request_reply(const char *ta, csap_handle_t csap,
                        const struct sockaddr *lladdr, 
                        int type, te_bool broadcast,
                        struct in_addr *myaddr,
                        struct in_addr *srvaddr,
                        unsigned long *xid, te_bool set_ciaddr)
{
    te_bool              result = FALSE;
    struct dhcp_message *request = NULL;

    if ((request = dhcpv4_message_create(type)) != NULL)
    {
        char     test_failed_message[1024] = { '\0' };
        uint16_t flags = (broadcast ? FLAG_BROADCAST : 0);
        struct dhcp_option **opt;
        int      i;

        dhcpv4_message_set_flags(request, &flags);
        dhcpv4_message_set_chaddr(request, lladdr->sa_data);
        dhcpv4_message_set_xid(request, xid);

        if (set_ciaddr)
            dhcpv4_message_set_ciaddr(request, myaddr);

        if (type != DHCPDISCOVER)
            dhcpv4_message_add_option(request, SERVER_ID_OPTION,
                                      sizeof(srvaddr->s_addr),
                                      &srvaddr->s_addr);
        if (type == DHCPREQUEST)
            dhcpv4_message_add_option(request, REQUEST_IP_ADDR_OPTION,
                                      sizeof(myaddr->s_addr),
                                      &myaddr->s_addr);

        /* Add the 'end' option (RFC2131, chapter 4.1, page 22:
         * "The last option must always be the 'end' option")
         */
        dhcpv4_message_add_option(request, 255, 0, NULL);

        /* Calculate the space in octets currently occupied by options */
        for (i = DHCP_MAGIC_SIZE, opt = &(request->opts);
             *opt != NULL;
             opt = &((*opt)->next))
        {
            int opt_type = (*opt)->type;

            i++;                          /** Option type length       */
            if (opt_type != 255 && opt_type != 0)
                i += 1 + (*opt)->val_len; /** Option len + body length */
        }

        /* Align to 32-octet boundary; no such requirement in RFC,
         * Solaris 'dhcp' server does this way, so the test too:
         * alignment is performed over adding appropriate number
         * of 'pad' options
         */
        for (i = 32 - i % 32; i < 32 && i > 0; i--)
            dhcpv4_message_add_option(request, 0, 0, NULL);

        if (type != DHCPRELEASE)
        {
            const char          *err_msg;
            unsigned int         timeout = 10000; /**< 10 sec */
            struct dhcp_message *reply   = tapi_dhcpv4_send_recv(ta, csap,
                                                                 request,
                                                                 &timeout,
                                                                 &err_msg);

            if (reply != NULL)
            {
                myaddr->s_addr = dhcpv4_message_get_yiaddr(reply);
                RING("Got address %d.%d.%d.%d", 
                     (myaddr->s_addr & 0xFF),
                     (myaddr->s_addr >> 8) & 0xFF,
                     (myaddr->s_addr >> 16) & 0xFF,
                     (myaddr->s_addr >> 24) & 0xFF);

                if (dhcpv4_message_get_xid(reply) == *xid)
                {
                    struct dhcp_option const *server_id_option =
                        dhcpv4_message_get_option(reply, 54);

                    if (server_id_option != NULL)
                    {
                        if (server_id_option->len == 4)
                        {
                            if (server_id_option->val_len == 4)
                            {
                                memcpy(&srvaddr->s_addr,
                                       server_id_option->val, 4);
                                result = TRUE;
                            }
                            else
                                TE_SPRINTF(test_failed_message,
                                           "Invalid ServerID option "
                                           "value length: %u",
                                           server_id_option->val_len);
                        }
                        else
                            TE_SPRINTF(test_failed_message,
                                       "Invalid ServerID option length: %u",
                                       server_id_option->len);
                    }
                    else
                        TE_SPRINTF(test_failed_message,
                                   "Cannot get ServerID option");
                }
                else
                    TE_SPRINTF(test_failed_message,
                               "Reply XID doesn't match that of request");

                free(reply);
            }
            else
                TE_SPRINTF(test_failed_message,
                           "Failed send/receive DHCP request/reply: %s",
                           err_msg);
        }
        else
            result = (tapi_dhcpv4_message_send(ta, csap, request) == 0);
    
        free(request);

        if (*test_failed_message != '\0')
            TEST_FAIL("%s", test_failed_message);
    }
    else
        TEST_FAIL("Failed to create DHCP message");

    return result;
}


/**
 * Checks for a complete DHCP session with a given agent:
 * discovery - request - request - release
 *
 * @param ta      TA name
 * @param if_name Interface name
 * @param lladdr  Local hardware address
 */
static void
test_dhcp_sequence(const char *ta, const char *if_name, 
                   const struct sockaddr *lladdr)
{
    int                     rc;
    csap_handle_t           csap = CSAP_INVALID_HANDLE;
    struct in_addr          myaddr = {INADDR_ANY};
    struct in_addr          srvaddr = {INADDR_ANY};
    unsigned long           xid = random();

    rc = tapi_dhcpv4_plain_csap_create(ta, if_name,
                                       DHCP4_CSAP_MODE_CLIENT,
                                       &csap);
    if (rc != 0)
        TEST_FAIL("Failed to create DHCP client CSAP on %s:%s: %X",
                  ta, if_name, rc);

    if (!test_dhcp_request_reply(ta, csap, lladdr, DHCPDISCOVER, TRUE,
                                 &myaddr, &srvaddr, &xid, FALSE))
    {
        (void)tapi_tad_csap_destroy(ta, 0, csap);
        TEST_FAIL("DHCP discovery failed");
    }

    if (!test_dhcp_request_reply(ta, csap, lladdr, DHCPREQUEST, TRUE,
                                 &myaddr, &srvaddr, &xid, FALSE))
    {
        (void)tapi_tad_csap_destroy(ta, 0, csap);
        TEST_FAIL("DHCP lease cannot be obtained");
    }

    if (!test_dhcp_request_reply(ta, csap, lladdr, DHCPREQUEST, TRUE,
                                 &myaddr, &srvaddr, &xid, TRUE))
    {
        (void)tapi_tad_csap_destroy(ta, 0, csap);
        TEST_FAIL("DHCP lease cannot be renewed");
    }

    if (!test_dhcp_request_reply(ta, csap, lladdr, DHCPRELEASE, FALSE,
                                 &myaddr, &srvaddr, &xid, TRUE))
    {
        (void)tapi_tad_csap_destroy(ta, 0, csap);
        TEST_FAIL("Error releasing DHCP lease");
    }

    CHECK_RC(tapi_tad_csap_destroy(ta, 0, csap));
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

    TEST_CHECK_SERVICE(host_iut->ta, dhcpserver);

    /* Disable DHCP server */
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                                  "/agent:%s/dhcpserver:", host_iut->ta));

    /* Add subnet for the first interface/network */
    rc = tapi_cfg_dhcps_add_subnet(host_iut->ta,
                                   net1->ip4addr, net1->ip4pfx,
                                   NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP subnet configuration entry: %X", rc);
    }


    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &tst1_addr, NULL));

    rc = tapi_cfg_dhcps_add_host(host_iut->ta, NULL, NULL,
                                 tst1_la, NULL, 0, tst1_addr,
                                 NULL, NULL, "1", NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP host configuration entry: %X", rc);
    }


    /* Add subnet for the second interface/network */
    rc = tapi_cfg_dhcps_add_subnet(host_iut->ta,
                                   net2->ip4addr, net2->ip4pfx,
                                   NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP subnet configuration entry: %X", rc);
    }


    /* Add host declaration for the second client */
    CHECK_RC(tapi_env_allocate_addr(net2, AF_INET, &tst2_addr, NULL));

    rc = tapi_cfg_dhcps_add_host(host_iut->ta, NULL, NULL,
                                 tst2_la, NULL, 0, tst2_addr,
                                 NULL, NULL, "1", NULL);
    if (rc != 0)
    {
        TEST_FAIL("Failed to add DHCP host configuration entry: %X", rc);
    }

    /* Enable DHCP server */
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)1,
                                  "/agent:%s/dhcpserver:", host_iut->ta));

    /* Test the first client */
    test_dhcp_sequence(host_tst1->ta, if_tst1->if_name, tst1_la);

    /* Test the second client */
    test_dhcp_sequence(host_tst2->ta, if_tst2->if_name, tst2_la);

    TEST_SUCCESS;

cleanup:
    if (host_iut != NULL)
    {
        CLEANUP_CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                                              "/agent:%s/dhcpserver:",
                                              host_iut->ta));
    }

    TEST_END;
}
