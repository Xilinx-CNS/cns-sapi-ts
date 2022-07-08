/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used during mmap handling
 * 
 * $Id$
 */

/** @page level5-ulv-mmap  Corrupt data used during mmap handling
 *
 * @objective Check that corruption of data used during mmaping of 
 *            resources does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param field         Field to be corrupted: 
 *                          "netif_mmap_bytes";
 *                          "buf_mmap_bytes";
 *                          "io_mmap_bytes";
 *                          "evq_timer_reg";
 *                          "table_ofs";
 *                          "buf_ofs";
 *                          "ep_ofs";
 *                          "synrecv_ofs";
 *                          "asyncops_ofs";
 *                          "max_iobufset".
 *
 * @par Scenario
 * -# Create several connections between @p pco_iut and @p pco_tst.
 * -# If @p field is equal to "*_bytes", set it to random value.
 * -# If @p field is equal to "*_offs" or "evq_timer_reg" set it to point 
 *    out of the shared state.
 * -# If @p field is equal to "max_iobufset", increase it.
 * -# Call @b exec() on @p pco_iut.
 * -# Open a socket on the @p pco_iut.
 * -# Send/receive data via existing connections using AIO and usual
 *    functions.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/mmap"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
