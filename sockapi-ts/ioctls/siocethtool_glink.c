/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocethtool_glink Usage of @c SIOCETHTOOL request with @c ETHTOOL_GLINK command
 *
 * @objective Check that @c SIOCETHTOOL request with @c ETHTOOL_GLINK
 *            command returns a status of a specified interface.
 *
 * @type conformance
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 * @param iut_if        One of interfaces on @p pco_iut
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut.
 * -# Call @b ioctl(@c SIOCETHTOOL) with command @c ETHTOOL_GLINK to check
 *    that @p iut_if interface is up.
 * -# Disable @p iut_if interface.
 * -# Call @b ioctl(@c SIOCETHTOOL) with command @c ETHTOOL_GLINK to check
 *    that @p iut_if interface is down.
 * -# Enable @p iut_if interface.
 * -# Call @b ioctl(@c SIOCETHTOOL) with command @c ETHTOOL_GLINK to check
 *    that @p iut_if interface is up.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocethtool_glink"

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
    struct ethtool_value       ethtool_val;
    te_bool                    is_failed = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    
    TEST_GET_IF(iut_if);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    memset(&ifreq_var, 0, sizeof(ifreq_var));
    strncpy(ifreq_var.ifr_name, iut_if->if_name, sizeof(ifreq_var.ifr_name));

    memset(&ethtool_val, 0, sizeof(ethtool_val));
    ifreq_var.ifr_data = (char *)&ethtool_val;
    ethtool_val.cmd = RPC_ETHTOOL_GLINK;

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCETHTOOL, &ifreq_var);

    if (!ethtool_val.data)
    {
        ERROR_VERDICT("ETHTOOL_GLINK says that an interface is down "
                      "at the beginning of the test");
        is_failed = TRUE;
    }

    tapi_cfg_base_if_down(pco_iut->ta, iut_if->if_name);
    CFG_WAIT_CHANGES;

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCETHTOOL, &ifreq_var);

    if (ethtool_val.data)
    {
        ERROR_VERDICT("ETHTOOL_GLINK says that an interface is up "
                      "when it should be down");
        is_failed = TRUE;
    }

    tapi_cfg_base_if_up(pco_iut->ta, iut_if->if_name);
    CFG_WAIT_CHANGES;

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCETHTOOL, &ifreq_var);

    if (!ethtool_val.data)
    {
        ERROR_VERDICT("ETHTOOL_GLINK says that an interface is down "
                      "when it should be up");
        is_failed = TRUE;
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
