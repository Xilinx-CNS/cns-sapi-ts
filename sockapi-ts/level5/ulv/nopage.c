/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used during nopage handling
 * 
 * $Id$
 */

/** @page level5-ulv-nopage  Corrupt data used during nopage handling
 *
 * @objective Check that corrupting of data used during handling of "nopage"
 *            for buf mmap does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param val           Value to be set to buf_ofs: 
 *                          1: random value, < dma_desc_ofs;
 *                          2: random value in range [dma_desc_ofs, buf_ofs];
 *                          3: random value > buf_ofs.
 *
 * @par Scenario
 * -# Create several connections between @p pco_iut and @p pco_tst.
 * -# Change @p field according to @p val.
 * -# Send a lot of traffic via all connections from @p pco_iut without 
 *    reading data on @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/nopage"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
