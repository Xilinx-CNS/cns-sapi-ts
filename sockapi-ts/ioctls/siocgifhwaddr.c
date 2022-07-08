/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocgifhwaddr Usage of SIOCGIFHWADDR request
 *
 * @objective Check that @c SIOCGIFHWADDR request returns 
 *            link layer address of the interface.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 16.6
 *
 * @param sock_type     Type of socket used in the test
 * @param pco_iut       PCO on IUT
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @p sock_type from @c PF_INET domain
 *    on @p pco_iut;
 * -# For each interface obtained by using @c SIOGIFCONF @b ioctl() request
 *    do the following:
 *        - Call @b ioctl() with @c SIOCGIFHWADDR;
 *        - Check that the function returns @c 0;
 *        - Check that the value of @a ifr_hwaddr is the valid link-layer
 *          address;
 *        .
 * -# Close @p iut_s socket;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgifhwaddr"

#include "sockapi-test.h"
#include "tapi_cfg.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;
    rpc_socket_type            sock_type;
    int                        ifreqs_size;
    struct ifreq              *ifreqs = NULL;
    struct ifreq              *ifreq_ptr = NULL;
    unsigned char              hwaddr[IFHWADDRLEN];
    size_t                     hwaddr_len = sizeof(hwaddr);
    struct ifconf              ifconf_var;
    te_bool                    checked = FALSE;
    int                        ret;
    
    
    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);

    
    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    CHECK_RC(get_ifconf_size(pco_iut, iut_s, &ifreqs_size));
    
    CHECK_NOT_NULL(ifreqs = (struct ifreq *)calloc(1, ifreqs_size));
    
    ifconf_var.ifc_len = ifreqs_size;
    ifconf_var.ifc_req = ifreqs;
            
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFCONF, &ifconf_var);

    for (ifreq_ptr = ifreqs; 
         ifreq_ptr != ifreqs + (ifreqs_size / sizeof(struct ifreq));
         ifreq_ptr++)
    {
        rc = tapi_cfg_get_hwaddr(pco_iut->ta, ifreq_ptr->ifr_name,
                                 hwaddr, &hwaddr_len);
        if (rc == 0)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            ret = rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFHWADDR, ifreq_ptr);
            if (ret != 0)
            {
                TEST_VERDICT("ioctl(SIOCGIFHWADDR) failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }

            if (memcmp(ifreq_ptr->ifr_hwaddr.sa_data,
                       hwaddr, hwaddr_len) != 0)
            {
                TEST_FAIL("'ifr_hwaddr' field of ifreq structure "
                          "contains invalid link-layer address");
            }
            checked = TRUE;
        }
        else if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
        {
            /*
             * It is OK to get ENOENT, since some interfaces may be
             * out of our resources.
             */
            TEST_FAIL("Failed to get interface %s:%s link-layer "
                      "address via Configurator: %r",
                      pco_iut->ta, ifreq_ptr->ifr_name, rc);
        }
    }

    if (checked)
        TEST_SUCCESS;
    else
        TEST_FAIL("No interfaces may be used on TA '%s'", pco_iut->ta);

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(ifreqs);

    TEST_END;
}

