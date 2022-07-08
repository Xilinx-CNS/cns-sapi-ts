/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt double-linked list element
 * 
 * $Id$
 */

/** @page level5-ulv-corrupt_dll Corrupt double-linked list element
 *
 * @objective Corrupt double-linked list element.
 *
 * @param pco_iut        IUT PCO
 * @param field          Element to be corrupted
 * @param fake           If true, set @p field to id pointing to area
 *                       starting inside shared state, but finishing
 *                       outside it;
 *                       If false, set @p fiels to id pointing to area
 *                       outside of the shared state.
 *
 * @par Scenario
 * -# Assign N to netif_mmap_bytes + size of control plane.
 * -# If @p fake is true, N -= sizeof(link_t).
 * -# If @p fake, write random value > N to memory on offset N from 
 *    ci_netif_state.
 * -# If not @p fake increase N to random value.
 * -# Assign N to @p field.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

