/**
 * \addtogroup uip6
 * @{
 */
/*
 * Copyright (c) 2009, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */
/**
 * \file
 *         Management of extension headers for ContikiRPL.
 *
 * \author Vincent Brillault <vincent.brillault@imag.fr>,
 *         Joakim Eriksson <joakime@sics.se>,
 *         Niclas Finne <nfi@sics.se>,
 *         Nicolas Tsiftes <nvt@sics.se>.
 */

#include "net/uip.h"
#include "net/tcpip.h"
#include "net/uip-ds6.h"
#include "net/rpl/rpl-private.h"

#define DEBUG DEBUG_NONE
#include "net/uip-debug.h"

#include <limits.h>
#include <string.h>

/************************************************************************/
#define UIP_IP_BUF                ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_EXT_HDR_OPT_BUF       ((struct uip_ext_hdr_opt *)&uip_buf[uip_l2_l3_hdr_len + uip_ext_opt_offset])
#define UIP_EXT_HDR_OPT_RPL_BUF   ((struct uip_ext_hdr_opt_rpl *)&uip_buf[uip_l2_l3_hdr_len + uip_ext_opt_offset])
/************************************************************************/
int
rpl_verify_header(int uip_ext_opt_offset)
{
  rpl_instance_t *instance;
  int down;
  uint8_t sender_closer;

  if(UIP_EXT_HDR_OPT_RPL_BUF->opt_len != RPL_HDR_OPT_LEN) {
    PRINTF("RPL: Bad header option! (wrong length)\n");
    return 1;
  }

  if(UIP_EXT_HDR_OPT_RPL_BUF->flags & RPL_HDR_OPT_FWD_ERR) {
    PRINTF("RPL: Forward error!\n");
    /* We should try to repair it, not implemented for the moment */
    return 2;
  }

  instance = rpl_get_instance(UIP_EXT_HDR_OPT_RPL_BUF->instance);
  if(instance == NULL) {
    PRINTF("RPL: Unknown instance: %u\n",
           UIP_EXT_HDR_OPT_RPL_BUF->instance);
    return 1;
  }

  if(!instance->current_dag->joined) {
    PRINTF("RPL: No DAG in the instance\n");
    return 1;
  }

  down = 0;
  if(UIP_EXT_HDR_OPT_RPL_BUF->flags & RPL_HDR_OPT_DOWN) {
    down = 1;
  }

  PRINTF("RPL: Packet going %s\n", down == 1 ? "down" : "up");

  sender_closer = UIP_EXT_HDR_OPT_RPL_BUF->senderrank < instance->current_dag->rank;
  if((down && !sender_closer) || (!down && sender_closer)) {
    PRINTF("RPL: Loop detected - senderrank: %d my-rank: %d sender_closer: %d\n",
	   UIP_EXT_HDR_OPT_RPL_BUF->senderrank, instance->current_dag->rank,
	   sender_closer);
    if(UIP_EXT_HDR_OPT_RPL_BUF->flags & RPL_HDR_OPT_RANK_ERR) {
      PRINTF("RPL: Rank error signalled in RPL option!\n");
      /* We should try to repair it, not implemented for the moment */
      return 3;
    }
    PRINTF("RPL: Single error tolerated\n");
    UIP_EXT_HDR_OPT_RPL_BUF->flags |= RPL_HDR_OPT_RANK_ERR;
    return 0;
  }

  PRINTF("RPL: Rank OK\n");

  return 0;
}
/************************************************************************/
int
rpl_update_header(uip_ipaddr_t *addr)
{
  struct uip_ext_hdr_opt_rpl* rpl_opt_ptr;
  struct rpl_parent* parent;

  if(default_instance == NULL || !default_instance->used ||
      !default_instance->current_dag->joined)
  {
    PRINTF("RPL: Unable to update RPL Option: incorrect default instance\n");
    return 1;
  }

  rpl_opt_ptr = (struct uip_ext_hdr_opt_rpl*)find_ext_hdr_opt(UIP_PROTO_HBHO,
      UIP_EXT_HDR_OPT_RPL, NULL, NULL, NULL);
  if(!rpl_opt_ptr)
  {
    /* Create and update instance ID. */
    rpl_opt_ptr = (struct uip_ext_hdr_opt_rpl*)add_ext_hdr_opt(UIP_PROTO_HBHO,
        UIP_EXT_HDR_OPT_RPL, 6, 2);
    if(!rpl_opt_ptr)
    {
      PRINTF("RPL: Unable to add RPL Option\n");
      return 1;
    }

    rpl_opt_ptr->instance = default_instance->instance_id;
  }
  /* Update rank and direction. */
  rpl_opt_ptr->senderrank = default_instance->current_dag->rank;

  parent = rpl_find_parent(default_instance->current_dag, addr);
  if(parent == NULL || parent != parent->dag->preferred_parent)
    rpl_opt_ptr->flags = RPL_HDR_OPT_DOWN;

  return 0;
}
/************************************************************************/
uint8_t
rpl_invert_header(void)
{
  uint8_t uip_ext_opt_offset;
  uint8_t last_uip_ext_len;

  last_uip_ext_len = uip_ext_len;
  uip_ext_len = 0;
  uip_ext_opt_offset = 2;

  PRINTF("RPL: Verifying the presence of the RPL header option\n");
  switch(UIP_IP_BUF->proto) {
  case UIP_PROTO_HBHO:
    break;
  default:
    PRINTF("RPL: No hop-by-hop Option found\n");
    uip_ext_len = last_uip_ext_len;
    return 0;
  }

  switch (UIP_EXT_HDR_OPT_BUF->type) {
  case UIP_EXT_HDR_OPT_RPL:
    PRINTF("RPL: Updating RPL option (switching direction)\n");
    UIP_EXT_HDR_OPT_RPL_BUF->flags &= RPL_HDR_OPT_DOWN;
    UIP_EXT_HDR_OPT_RPL_BUF->flags ^= RPL_HDR_OPT_DOWN;
    UIP_EXT_HDR_OPT_RPL_BUF->senderrank = rpl_get_instance(UIP_EXT_HDR_OPT_RPL_BUF->instance)->current_dag->rank;
    uip_ext_len = last_uip_ext_len;
    return RPL_HOP_BY_HOP_LEN;
  default:
    PRINTF("RPL: Multi Hop-by-hop options not implemented\n");
    uip_ext_len = last_uip_ext_len;
    return 0;
  }
}
/************************************************************************/
