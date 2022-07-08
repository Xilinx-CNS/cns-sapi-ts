/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt parameters used during allocation additional packet buffers
 * 
 * $Id$
 */

/** @page level5-ulv-more_pktbufs  Corrupt parameters used during allocation additional packet buffers
 *
 * @objective Check that corruption of data used during allocation additional
 *            packet buffers does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 *
 * @par Scenario
 * -# Create several stream connections between @p pco_iut and @p pco_tst.
 * -# Increase size_iobufset.
 * -# Send a lot of traffic via all connections from @p pco_iut without 
 *    reading data on @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/more_pktbufs"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
