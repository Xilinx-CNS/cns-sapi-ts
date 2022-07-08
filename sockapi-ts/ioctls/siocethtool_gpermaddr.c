/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocethtool_gpermaddr Usage of @c SIOCETHTOOL request with @c ETHTOOL_GPERMADDR command
 *
 * @objective Check that @c SIOCETHTOOL request with @c ETHTOOL_GPERMADDR
 *            command returns a permanent hardware address of a specified
 *            interface.
 *
 * @type conformance
 *
 * @param sock_type         Type of socket used in the test
 * @param pco_iut           PCO on IUT
 * @param iut_if            One of interfaces on @p pco_iut
 * @param alien_link_addr   Ethernet address not belonging to
 *                          any existing device in network
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut.
 * -# Call @b ioctl(@c SIOCETHTOOL) with command @c ETHTOOL_GPERMADDR
 *    and check whether returned permanent ethernet address is the same
 *    as the current ethernet address.
 * -# Change current hardware address of @p iut_if to @p alien_link_addr.
 * -# Call @b ioctl(@c SIOCETHTOOL) with command @c ETHTOOL_GPERMADDR
 *    and check that the permanent ethernet address was not changed.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocethtool_gpermaddr"

#include "sockapi-test.h"
#include "conf_api.h"
#include "te_ethtool.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    const struct if_nameindex *iut_if;
    struct ifreq               ifreq_var;
    struct ethtool_perm_addr  *ethtool_addr;
    uint32_t                   perm_addr_size;
    unsigned char              hwaddr_perm[IFHWADDRLEN];
    unsigned char              hwaddr_old[IFHWADDRLEN];
    size_t                     hwaddr_old_len = sizeof(hwaddr_old);
    unsigned char              hwaddr[IFHWADDRLEN];
    size_t                     hwaddr_len = sizeof(hwaddr);
    const void                *alien_link_addr;
    te_bool                    addr_changed = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);
    TEST_GET_LINK_ADDR(alien_link_addr);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name,
            sizeof(ifreq_var.ifr_name));

    ethtool_addr = calloc(1, sizeof(*ethtool_addr) + IFHWADDRLEN);
    ifreq_var.ifr_data = (char *)ethtool_addr;
    ethtool_addr->size = IFHWADDRLEN;
    ethtool_addr->cmd = RPC_ETHTOOL_GPERMADDR;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, RPC_SIOCETHTOOL, &ifreq_var);
    if (rc != 0)
    {
        TEST_VERDICT("ioctl(SIOCETHTOOL) failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    CHECK_RC(tapi_cfg_get_hwaddr(pco_iut->ta, iut_if->if_name,
                                 hwaddr, &hwaddr_len));

    if (memcmp(ethtool_addr->data,
               hwaddr, hwaddr_len) != 0)
        RING("@ioctl(SIOCETHTOOL) with ETHTOOL_GPERMADDR "
             "command returned permanent hardware address "
             "which is not the same as the current one");

    perm_addr_size = ethtool_addr->size;
    memcpy(hwaddr_perm, ethtool_addr->data, ethtool_addr->size);
    hwaddr_old_len = hwaddr_len;
    memcpy(hwaddr_old, hwaddr, hwaddr_len);
    memcpy(hwaddr, CVT_HW_ADDR(alien_link_addr), IFHWADDRLEN);

    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name));
    CHECK_RC(tapi_cfg_set_hwaddr(pco_iut->ta, iut_if->if_name,
                                 hwaddr, IFHWADDRLEN));
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name));
    CFG_WAIT_CHANGES;
    addr_changed = TRUE;

    memset(ethtool_addr, 0, sizeof(*ethtool_addr) + IFHWADDRLEN);
    ethtool_addr->size = IFHWADDRLEN;
    ethtool_addr->cmd = RPC_ETHTOOL_GPERMADDR;
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCETHTOOL, &ifreq_var);

    if (ethtool_addr->size != perm_addr_size ||
        memcmp(ethtool_addr->data,
               hwaddr_perm, ethtool_addr->size) != 0)
        TEST_VERDICT("@ioctl(SIOCETHTOOL) with ETHTOOL_GPERMADDR "
                      "command returns changed hardware address but "
                      "should return a permanent one");

    TEST_SUCCESS;

cleanup:

    if (addr_changed)
    {
        CLEANUP_CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta,
                                               iut_if->if_name));
        CLEANUP_CHECK_RC(tapi_cfg_set_hwaddr(pco_iut->ta, iut_if->if_name,
                                             hwaddr_old, hwaddr_old_len));
        CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta,
                                             iut_if->if_name));
        CFG_WAIT_CHANGES;
    }

    free(ethtool_addr);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
