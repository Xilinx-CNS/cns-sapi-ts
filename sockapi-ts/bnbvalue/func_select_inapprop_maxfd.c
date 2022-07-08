/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_select_inapprop_maxfd Using select() function with inappropriate value of maxfd parameter
 *
 * @objective Check that @b select() does not process descriptors whose number more than the value of @a maxfd parameter minus one.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param sock_type Socket type that can be  @c SOCK_STREAM or @c SOCK_DGRAM
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 *
 * @par Scenario:
 * -# Create a connection of type @p sock_type between @p pco_iut 
 *    and @p pco_tst. As a result two sockets appear @p iut_s and @p tst_s.
 * -# Send some data from @p tst_s socket.
 * -# Initialize a variable @p set of type @c fd_set as the following:
 *    - @c FD_ZERO(@p set);
 *    - @c FD_SET(@p iut_s, @p set);
 * -# Set @p maxfd to @p iut_s, not adding @c 1 to it.
 * -# Call @b select(@p maxfd, @p set, @c NULL, @c NULL, @p timeout).
 * -# Check that the function returns @c 0, i.e. completes by timeout,
 *    although some data arrived on @p iut_s socket.
 * -# Report result of @c FD_ISSET(@p iut_s, @p set) operation.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s and @p tst_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_select_inapprop_maxfd"

#include "sockapi-test.h"

 
int 
main(int argc, char *argv[]) 
{ 
    rcf_rpc_server     *pco_iut = NULL; 
    rcf_rpc_server     *pco_tst = NULL; 
    rpc_socket_type     sock_type;
    int                 iut_s = -1; 
    int                 tst_s = -1;
    rpc_fd_set_p        set= RPC_NULL;
    tarpc_timeval       timeout = { 0, 0 };
    
    void             *tx_buf = NULL;
    size_t            tx_buf_len;
    
    const struct sockaddr  *tst_addr; 
    const struct sockaddr  *iut_addr; 

  
    TEST_START; 
 
    /* Preambule */ 
    TEST_GET_PCO(pco_iut); 
    TEST_GET_PCO(pco_tst); 
    TEST_GET_ADDR(pco_tst, tst_addr); 
    TEST_GET_ADDR(pco_iut, iut_addr);     
    TEST_GET_SOCK_TYPE(sock_type);    
    
    timeout.tv_sec = rand_range(0, 10);
    timeout.tv_usec = rand_range(0, 10);
    
    CHECK_NOT_NULL(tx_buf = sockts_make_buf_stream(&tx_buf_len));
    
    set = rpc_fd_set_new(pco_iut);

    /* Scenario */ 
    GEN_CONNECTION_WILD(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    rpc_do_fd_zero(pco_iut, set); 
    rpc_do_fd_set(pco_iut, iut_s, set);
    
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);    
   
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_select(pco_iut, iut_s, set, RPC_NULL, RPC_NULL, &timeout); 
    if (rc != 0)
    {     
         TEST_VERDICT("RPC select() has returned (%d) instead of 0",
                       rc);
    }
        
    rc = rpc_do_fd_isset(pco_iut, iut_s, set);
    /* !!! */
    RING("FD_SET(iut_s, set) result: %d", rc);
    
    TEST_SUCCESS; 
 
cleanup: 
    if (set != RPC_NULL)
        rpc_fd_set_delete(pco_iut, set); 

    if (tx_buf != NULL)
        free(tx_buf);
    
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);  
    CLEANUP_RPC_CLOSE(pco_iut, iut_s); 
        
    TEST_END; 
} 
