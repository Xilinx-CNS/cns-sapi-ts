/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-siocgifconf Usage of SIOCGIFCONF request
 *
 * @objective Check that @c SIOCGIFCONF request returns the list of
 *            interfaces registered in the system.
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
 * -# Fill in @p ifconf_var variable of type @c struct @c ifconf 
 *    structure as follows:
 *        - @c ifc_len: @c 0;
 *        - @c ifc_req: @c NULL;
 *        .
 * -# Call @b ioctl(@p iut_s, @c SIOCGIFCONF, @p &ifconf_var);
 * -# Check that the function returns @c 0, and updates @c ifc_len field
 *    of the structure with some positive value - the length of the buffer
 *    needed for the whole set of @c ifreq structures - @p buf_len.
 *    See @ref ioctls_siocgifconf_1 "note 1";
 * -# Set @p n to 0;
 * -# Repeat the following steps:
 *        - Fill in @p ifconf_var variable of type @c struct @c ifconf
 *          structure as follows:
 *              - @c ifc_len: (@p n * @c sizeof(struct ifreq)) @c + @c 1;
 *              - @c ifc_req: Pointer to the buffer of size @p buf_len;
 *              .
 *        - Call @b ioctl(@p iut_s, @c SIOCGIFCONF, @p &ifconf_var);
 *        - Check that the function returns @c 0, and updates @a ifc_len
 *          field of the structure with @p n * @c sizeof(struct ifreq;
 *        - If @p n * @c sizeof(struct ifreq) equals to @p buf_len, go to
 *          step 7, otherwise set @p n to @p n @c + @c 1, and repeat 
 *          step 6 once again;
 * -# For each entry in @c ifc_req field perform the following:
 *        - Copy @a ifr_addr to some variable @p if_addr;
 *        - Clear @a ifr_addr field of @c ifc_req structure;
 *        - Call @b ioctl(@p iut_s, @c SIOCGIFADDR, @p &ifconf_var);
 *        - Check that the value of @a ifr_addr field of @c ifc_req
 *          structure has the same value as @p if_addr;
 *        .
 * -# Close @p iut_s socket;
 *
 * @note
 * @anchor ioctls_siocgifconf_1
 * Solaris 2.5 returns @c EINVAL if the returned length would be greater
 * than or equal to the buffer length.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/siocgifconf"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"


#define TST_BUFFER_MAX      512

int
main(int argc, char *argv[])
{
    rpc_socket_type  sock_type;
    rcf_rpc_server  *pco_iut = NULL;
    int              iut_s = -1;

    const struct if_nameindex *iut_if = NULL;

    int              exp_len = 0;
    int              prev_len;
    struct ifconf    ifconf_var;
    int              n_reqs = 0;
    struct ifreq    *ifreq_ptr = NULL;
    struct ifreq    *req;

        
    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);

    /* 
     * Change configuration - delete all addresses except one on
     * 'iut_if' interfaces. Since ioctl with (SIOCGxxx)/(SIOCSxxx)
     * is incompatible with netlink (RTM_GETADDR)/(RTM_NEWADDR) 
     * messages output, it is the only chance for test to pass.
     */
    CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_iut->ta,
                                           iut_if->if_name, NULL));

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    ifconf_var.ifc_len = 0;
    ifconf_var.ifc_req = NULL;
    
#define ZERO_FILLED_STRUCT_LOG_MSG \
    "ioctl(SIOCGIFCONF) called with ifconf structure filled in " \
    "as {ifc_len = 0, ifc_req = NULL} "

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFCONF, &ifconf_var);
    if (rc != 0)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                        ZERO_FILLED_STRUCT_LOG_MSG "returns -1, but");
        if (ifconf_var.ifc_len != 0)
        {
            TEST_FAIL(ZERO_FILLED_STRUCT_LOG_MSG "returns -1, but "
                      "updates 'ifc_len' field");
        }
        WARN(ZERO_FILLED_STRUCT_LOG_MSG "returns -1 and sets errno "
             "to EINVAL");
    }
    else
    {
        if (ifconf_var.ifc_len <= 0)
        {
            RING_VERDICT(ZERO_FILLED_STRUCT_LOG_MSG "returns 0, but does "
                         "not update 'ifc_len' field with the length of "
                         "expected buffer size");
        }
        else
        {
            if ((ifconf_var.ifc_len % sizeof(struct ifreq)) != 0)
            {
                TEST_FAIL("The value of 'ifc_len' field is not aligned to "
                          "sizeof(struct ifreq)");
            }
            exp_len = ifconf_var.ifc_len;
        }
    }

    do {
        struct ifreq *ptr;
        int           total_length;

        prev_len = n_reqs * sizeof(struct ifreq);
        total_length = ((++n_reqs) * sizeof(struct ifreq)) + 1;
        ptr = ifreq_ptr;

        if ((ifreq_ptr = (struct ifreq *)realloc(ptr, total_length)) == NULL)
        {
            free(ptr);
            TEST_FAIL("Cannot allocate necessary amount of memory");
        }
        memset(ifreq_ptr, 0, total_length);
        
        ifconf_var.ifc_len = total_length;
        ifconf_var.ifc_req = ifreq_ptr;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFCONF, &ifconf_var);
        INFO("ifc_len (IN): %d, ifc_len (OUT): %d",
             total_length, ifconf_var.ifc_len);
    } while ((prev_len != ifconf_var.ifc_len) &&
             (prev_len < TST_BUFFER_MAX));

    if (prev_len >= TST_BUFFER_MAX)
    {
        TEST_FAIL("Too big buffer for 'ifconf' allocated, it looks "
                  "like SIOCGIFCONF use all buffer in any case");
    }
    
    n_reqs--;

    if (rc != 0)
    {
        TEST_FAIL("ioctl(SIOCGIFCONF) correctly updates 'ifc_len' field "
                  "of ifconf structure, but returns %d instead of 0", rc);
    }

    if (exp_len > 0 && exp_len != ifconf_var.ifc_len)
    {
        TEST_FAIL("Expected length of the whole buffer is not correct");
    }

    /* 
     * Now we get information about all interfaces, check their network
     * addresses
     */
    for (req = ifreq_ptr; req != (ifreq_ptr + n_reqs - 1); req++)
    {
        struct sockaddr addr;

        if (req->ifr_addr.sa_family != AF_INET)
        {
            TEST_FAIL("'sa_family' of 'ifr_addr' field of ifreq structure "
                      "is not equal to AF_INET");
        }
        memcpy(&addr, &(req->ifr_addr), sizeof(struct sockaddr));
        memset(&(req->ifr_addr), 0, sizeof(struct sockaddr));

        rpc_ioctl(pco_iut, iut_s, RPC_SIOCGIFADDR, req);

        if (te_sockaddrcmp(&(req->ifr_addr), sizeof(struct sockaddr),
                           &addr, sizeof(struct sockaddr)) != 0)
        {
            char buf1[INET_ADDRSTRLEN];
            char buf2[INET_ADDRSTRLEN];

            
            if (strncmp(req->ifr_name, iut_if->if_name, strlen(iut_if->if_name) + 1) == 0)
            {
                ERROR("sockaddr structures %s %s", 
                      inet_ntop(AF_INET, &(SIN(&(req->ifr_name))->sin_addr), buf1, INET_ADDRSTRLEN),
                      inet_ntop(AF_INET, &(SIN(&addr)->sin_addr), buf2, INET_ADDRSTRLEN));
                TEST_FAIL("sockaddr structures returned by SIOCGIFCONF and "
                          "SIOCGIFADDR are different");
            }
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(ifreq_ptr);

    TEST_END;
}

