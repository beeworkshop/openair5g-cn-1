/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*****************************************************************************
  Source      esm_recv.c

  Version     0.1

  Date        2013/02/06

  Product     NAS stack

  Subsystem   EPS Session Management

  Author      Frederic Maurel

  Description Defines functions executed at the ESM Service Access
        Point upon receiving EPS Session Management messages
        from the EPS Mobility Management sublayer.

*****************************************************************************/
#include <pthread.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "bstrlib.h"

#include "log.h"
#include "dynamic_memory_check.h"
#include "common_types.h"
#include "3gpp_24.007.h"
#include "3gpp_24.008.h"
#include "3gpp_29.274.h"
#include "commonDef.h"
#include "mme_app_ue_context.h"
#include "nas_itti_messaging.h"
#include "esm_recv.h"
#include "esm_pt.h"
#include "esm_ebr.h"
#include "esm_proc.h"
#include "esm_cause.h"
#include "mme_config.h"


#include "intertask_interface.h"
#include "itti_free_defined_msg.h"

#include "esm_proc.h"

#include "mem2str2mem.h"
#include "cJSON.h"

/****************************************************************************/
/****************  E X T E R N A L    D E F I N I T I O N S  ****************/
/****************************************************************************/

/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/

/****************************************************************************/
/******************  E X P O R T E D    F U N C T I O N S  ******************/
/****************************************************************************/

/*
   --------------------------------------------------------------------------
   Functions executed by both the UE and the MME upon receiving ESM messages
   --------------------------------------------------------------------------
*/
/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_status()                                         **
 **                                                                        **
 ** Description: Processes ESM status message                              **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **      pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fails                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/

esm_cause_t
esm_recv_status (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const esm_status_msg * msg)
{
  esm_cause_t                             esm_cause = ESM_CAUSE_SUCCESS;
  int                                     rc = RETURNerror;

  OAILOG_FUNC_IN (LOG_NAS_ESM);
  OAILOG_INFO(LOG_NAS_ESM,  "ESM-SAP   - Received ESM status message (pti=%d, ebi=%d)\n", pti, ebi);
  /*
   * Message processing
   */
  /*
   * Get the ESM cause
   */
  esm_cause = msg->esmcause;
  /*
   * Execute the ESM status procedure
   */
  rc = esm_proc_status_ind (emm_context, pti, ebi, &esm_cause);

  if (rc != RETURNerror) {
    esm_cause = ESM_CAUSE_SUCCESS;
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}


/*
   --------------------------------------------------------------------------
   Functions executed by the MME upon receiving ESM message from the UE
   --------------------------------------------------------------------------
*/
/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_pdn_connectivity_request()                       **
 **                                                                        **
 ** Description: Processes PDN connectivity request message                **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **      pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     new_ebi:   New assigned EPS bearer identity           **
 **      data:      PDN connection and EPS bearer context data **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fails                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
esm_cause_t
esm_recv_pdn_connectivity_request (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const pdn_connectivity_request_msg * msg,
  ebi_t *new_ebi)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  int                                     esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t                        ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO(LOG_NAS_ESM, "ESM-SAP   - Received PDN Connectivity Request message " "(ue_id=%u, pti=%d, ebi=%d)\n", ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if ((pti == ESM_PT_UNASSIGNED) || esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case a
     * * * * Reserved or unassigned PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (ebi != ESM_EBI_UNASSIGNED) {
    /*
     * 3GPP TS 24.301, section 7.3.2, case a
     * * * * Reserved or assigned EPS bearer identity value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)\n", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }




  struct esm_proc_data_s * esm_data = (struct esm_proc_data_s*)calloc(1,sizeof(struct esm_proc_data_s));

  printf("in esm_recv.c of request\n");
  char * esm_data_str = (char*)calloc(1,sizeof(struct esm_proc_data_s)*2+1);
  //struct esm_context_s * esm_p = (struct esm_context_s*)malloc(sizeof(struct esm_context_s));
  cJSON * root;
  char * Json;
  root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root,"task",14);
  char * gutiStr = mem2str((void*)&emm_context->_guti,sizeof(guti_t));
  cJSON_AddStringToObject(root,"guti",gutiStr);
  Json = cJSON_Print(root);
  Client(Json,&esm_data_str);
  //printf("esm_p_str\t%s\n",esm_data_str);
  void * tmp = str2mem(esm_data_str);
  memcpy(esm_data,(struct esm_proc_data_s*)tmp,sizeof(struct esm_proc_data_s));
  //printf("esm_data\t%s\n",(mem2str((void*)esm_data,sizeof(struct esm_proc_data_s))));
  free(esm_data_str);free(root);free(gutiStr);free(tmp);

  int isPdnTypeMdfy = 1;
  int isApnMdfy = 0;
  int isPcoMdfy = 0;

  esm_data->pti = pti;
  /*
   * Get the PDN connectivity request type
   */
  
  if (msg->requesttype == REQUEST_TYPE_INITIAL_REQUEST) {
    esm_data->request_type = ESM_PDN_REQUEST_INITIAL;
  } else if (msg->requesttype == REQUEST_TYPE_HANDOVER) {
    esm_data->request_type = ESM_PDN_REQUEST_HANDOVER;
  } else if (msg->requesttype == REQUEST_TYPE_EMERGENCY) {
    esm_data->request_type = ESM_PDN_REQUEST_EMERGENCY;
  } else {
    /*
     * Unkown PDN request type
     */
    esm_data->request_type = -1;
    OAILOG_ERROR (LOG_NAS_ESM, "ESM-SAP   - Invalid PDN request type (INITIAL/HANDOVER/EMERGENCY)\n");
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_MANDATORY_INFO);
  }
  /*
   * Get the value of the PDN type indicator
   */
  if (msg->pdntype == PDN_TYPE_IPV4) {
    esm_data->pdn_type = ESM_PDN_TYPE_IPV4;
  } else if (msg->pdntype == PDN_TYPE_IPV6) {
    esm_data->pdn_type = ESM_PDN_TYPE_IPV6;
  } else if (msg->pdntype == PDN_TYPE_IPV4V6) {
    esm_data->pdn_type = ESM_PDN_TYPE_IPV4V6;
  } else {
    /*
     * Unkown PDN type
     */
	isPdnTypeMdfy = 0;
    OAILOG_ERROR (LOG_NAS_ESM, "ESM-SAP   - Invalid PDN type\n");
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_UNKNOWN_PDN_TYPE);
  }
  /*
   * Get the Access Point Name, if provided
   */
  if (msg->presencemask & PDN_CONNECTIVITY_REQUEST_ACCESS_POINT_NAME_PRESENT) {
    if (esm_data->apn) bdestroy_wrapper(&esm_data->apn);
    esm_data->apn = msg->accesspointname;
	isApnMdfy = 1;
  }
  if (msg->presencemask & PDN_CONNECTIVITY_REQUEST_PROTOCOL_CONFIGURATION_OPTIONS_PRESENT) {
    if (esm_data->pco.num_protocol_or_container_id) clear_protocol_configuration_options(&esm_data->pco);
    copy_protocol_configuration_options(&esm_data->pco, &msg->protocolconfigurationoptions);
	isPcoMdfy = 1;
  }
  /*
   * Get the ESM information transfer flag
   */
  if (msg->presencemask & PDN_CONNECTIVITY_REQUEST_ESM_INFORMATION_TRANSFER_FLAG_PRESENT) {
    if (!mme_config.nas_config.disable_esm_information) {
      esm_proc_esm_information_request(emm_context, pti);
      OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
    }
  }
{
  printf("in esm_recv.c\n");
  cJSON * root;
  char * Json;
  root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root,"task",16);
  char * gutiStr = mem2str((void*)&emm_context->_guti,sizeof(guti_t));
  cJSON_AddStringToObject(root,"guti",gutiStr);
  char * esm_data_str = mem2str((void*)esm_data,sizeof(struct esm_proc_data_s));
  cJSON_AddStringToObject(root,"esm_data",esm_data_str);
  if(!esm_data->apn){
	  printf("null\n");
	  cJSON_AddNumberToObject(root,"isApnNull",1);
  }else{
		cJSON_AddNumberToObject(root,"esm_data_apn_mlen",esm_data->apn->mlen);
		cJSON_AddNumberToObject(root,"esm_data_apn_slen",esm_data->apn->slen);
		cJSON_AddNumberToObject(root,"esm_data_apn_data_length",strlen(esm_data->apn->data));
		char * esm_data_apn_data_str = mem2str((void*)esm_data->apn->data,strlen(esm_data->apn->data));
		cJSON_AddStringToObject(root,"esm_data_apn_data",esm_data_apn_data_str);
		free(esm_data_apn_data_str);
  }
  cJSON_AddNumberToObject(root,"isPdnTypeMdfy",isPdnTypeMdfy);
  cJSON_AddNumberToObject(root,"isApnMdfy",isApnMdfy);
  cJSON_AddNumberToObject(root,"isPcoMdfy",isPcoMdfy);
  Json = cJSON_Print(root);
  Client(Json,NULL);
  free(root);free(Json);free(gutiStr);free(esm_data_str);
}

#if ORIGINAL_CODE
  /*
   * Execute the PDN connectivity procedure requested by the UE
   */
  int pid = esm_proc_pdn_connectivity_request (emm_context, pti, request_type,
      &esm_data->apn,
      esm_data->pdn_type,
      &esm_data->pdn_addr,
      &esm_data->qos,
      &esm_cause);

  if (pid != RETURNerror) {
    int rc = esm_proc_default_eps_bearer_context (ctx, pid, new_ebi, &esm_data->qos, &esm_cause);

    if (rc != RETURNerror) {
      esm_cause = ESM_CAUSE_SUCCESS;
    }
  }
#else
  nas_itti_pdn_config_req(pti, ue_id, &emm_context->_imsi, esm_data, esm_data->request_type);
  esm_cause = ESM_CAUSE_SUCCESS;
#endif
  /*
   * Return the ESM cause value
   */

  free(esm_data);
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);

}

/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_pdn_disconnect_request()                         **
 **                                                                        **
 ** Description: Processes PDN disconnect request message                  **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **      pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     linked_ebi:    Linked EPS bearer identity of the default  **
 **             bearer associated with the PDN to discon-  **
 **             nect from                                  **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fails                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
esm_cause_t
esm_recv_pdn_disconnect_request (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const pdn_disconnect_request_msg * msg,
  ebi_t *linked_ebi)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  esm_cause_t                               esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t      ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO(LOG_NAS_ESM, "ESM-SAP   - Received PDN Disconnect Request message " "(ue_id=%d, pti=%d, ebi=%d)\n", ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if ((pti == ESM_PT_UNASSIGNED) || esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case b
     * * * * Reserved or unassigned PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (ebi != ESM_EBI_UNASSIGNED) {
     /** 3GPP TS 24.301, section 7.3.2, case b*/
     /** * * * Reserved or assigned EPS bearer identity value*/

    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)\n", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }

  /*
   * Message processing
   */
  /*
   * Execute the PDN disconnect procedure requested by the UE
   */
  int pid = esm_proc_pdn_disconnect_request (emm_context, pti, &esm_cause);

  if (pid != RETURNerror) {
    /*
     * Get the identity of the default EPS bearer context assigned to
     * * * * the PDN connection to disconnect from
     */
    *linked_ebi = msg->linkedepsbeareridentity;
    /*
     * Release the associated default EPS bearer context
     */
    int bid = 0;
    int rc = esm_proc_eps_bearer_context_deactivate (emm_context, false, *linked_ebi, &pid, &bid, &esm_cause);

    if (rc != RETURNerror) {
      esm_cause = ESM_CAUSE_SUCCESS;
    }
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}

//------------------------------------------------------------------------------
esm_cause_t esm_recv_information_response (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const esm_information_response_msg * msg)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  esm_cause_t                               esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t      ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO(LOG_NAS_ESM, "ESM-SAP   - Received ESM Information response message " "(ue_id=%d, pti=%d, ebi=%d)\n", ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if ((pti == ESM_PT_UNASSIGNED) || esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case b
     * * * * Reserved or unassigned PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (ebi != ESM_EBI_UNASSIGNED) {
    /*
     * 3GPP TS 24.301, section 7.3.2, case b
     * * * * Reserved or assigned EPS bearer identity value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)\n", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }

  /*
   * Message processing
   */
  /*
   * Execute the PDN disconnect procedure requested by the UE
   */
  int pid = esm_proc_esm_information_response (emm_context, pti, msg->accesspointname, &msg->protocolconfigurationoptions, &esm_cause);

  if (pid != RETURNerror) {

    // Continue with pdn connectivity request
  printf("in esm_recv.c of response\n");
  char * esm_data_str = (char*)malloc(sizeof(struct esm_proc_data_s)*2+1);
  cJSON * root;
  char * Json;
  root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root,"task",19);
  char * gutiStr = mem2str((void*)&emm_context->_guti,sizeof(guti_t));
  cJSON_AddStringToObject(root,"guti",gutiStr);
  Json = cJSON_Print(root);
  Client(Json,&esm_data_str);
  struct esm_proc_data_s * esm_data = (struct esm_proc_data_s*)malloc(sizeof(struct esm_proc_data_s));
  void * tmp = str2mem(esm_data_str);
  memcpy(esm_data,tmp,sizeof(struct esm_proc_data_s));

  free(esm_data_str);free(root);free(Json);free(gutiStr);free(tmp);
 
  nas_itti_pdn_config_req(pti, ue_id, &emm_context->_imsi, esm_data, esm_data->request_type);
  esm_cause = ESM_CAUSE_SUCCESS;
  free(esm_data);
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}

/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_activate_default_eps_bearer_context_accept()     **
 **                                                                        **
 ** Description: Processes Activate Default EPS Bearer Context Accept      **
 **      message                                                   **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **          pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fails                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
esm_cause_t
esm_recv_activate_default_eps_bearer_context_accept (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const activate_default_eps_bearer_context_accept_msg * msg)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  esm_cause_t                              esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t      ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO(LOG_NAS_ESM, "ESM-SAP   - Received Activate Default EPS Bearer Context " "Accept message (ue_id=%d, pti=%d, ebi=%d)\n",
          ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if (esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case f
     * * * * Reserved PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (esm_ebr_is_reserved (ebi) || esm_ebr_is_not_in_use (emm_context, ebi)) {
    /*
     * 3GPP TS 24.301, section 7.3.2, case f
     * * * * Reserved or assigned value that does not match an existing EPS
     * * * * bearer context
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)\n", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }

  /*
   * Message processing
   */
  /*
   * Execute the default EPS bearer context activation procedure accepted
   * * * * by the UE
   */
  int rc = esm_proc_default_eps_bearer_context_accept (emm_context, ebi, &esm_cause);

  if (rc != RETURNerror) {
    esm_cause = ESM_CAUSE_SUCCESS;
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}

/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_activate_default_eps_bearer_context_reject()     **
 **                                                                        **
 ** Description: Processes Activate Default EPS Bearer Context Reject      **
 **      message                                                   **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **          pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fail                       **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
esm_cause_t
esm_recv_activate_default_eps_bearer_context_reject (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const activate_default_eps_bearer_context_reject_msg * msg)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  esm_cause_t                             esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t                        ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO(LOG_NAS_ESM, "ESM-SAP   - Received Activate Default EPS Bearer Context " "Reject message (ue_id=%d, pti=%d, ebi=%d)\n",
          ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if (esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case f
     * * * * Reserved PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (esm_ebr_is_reserved (ebi) || esm_ebr_is_not_in_use (emm_context, ebi)) {
    /*
     * 3GPP TS 24.301, section 7.3.2, case f
     * * * * Reserved or assigned value that does not match an existing EPS
     * * * * bearer context
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }

  /*
   * Message processing
   */
  /*
   * Execute the default EPS bearer context activation procedure not accepted
   * * * * by the UE
   */
  int rc = esm_proc_default_eps_bearer_context_reject (emm_context, ebi, &esm_cause);

  if (rc != RETURNerror) {
    esm_cause = ESM_CAUSE_SUCCESS;
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}

/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_activate_dedicated_eps_bearer_context_accept()   **
 **                                                                        **
 ** Description: Processes Activate Dedicated EPS Bearer Context Accept    **
 **      message                                                   **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **          pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fails                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
esm_cause_t
esm_recv_activate_dedicated_eps_bearer_context_accept (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const activate_dedicated_eps_bearer_context_accept_msg * msg)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  esm_cause_t                             esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t                        ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO (LOG_NAS_ESM, "ESM-SAP   - Received Activate Dedicated EPS Bearer " "Context Accept message (ue_id=%d, pti=%d, ebi=%d)\n",
          ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if (esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case f
     * * * * Reserved PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (esm_ebr_is_reserved (ebi) || esm_ebr_is_not_in_use (emm_context, ebi)) {
    /*
     * 3GPP TS 24.301, section 7.3.2, case f
     * * * * Reserved or assigned value that does not match an existing EPS
     * * * * bearer context
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)\n", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }

  /*
   * Message processing
   */
  /*
   * Execute the dedicated EPS bearer context activation procedure accepted
   * * * * by the UE
   */
  int rc = esm_proc_dedicated_eps_bearer_context_accept (emm_context, ebi, &esm_cause);

  if (rc != RETURNerror) {
    esm_cause = ESM_CAUSE_SUCCESS;
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}

/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_activate_dedicated_eps_bearer_context_reject()   **
 **                                                                        **
 ** Description: Processes Activate Dedicated EPS Bearer Context Reject    **
 **      message                                                   **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **          pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fail                       **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
esm_cause_t
esm_recv_activate_dedicated_eps_bearer_context_reject (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const activate_dedicated_eps_bearer_context_reject_msg * msg)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  esm_cause_t                             esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t                        ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO (LOG_NAS_ESM, "ESM-SAP   - Received Activate Dedicated EPS Bearer " "Context Reject message (ue_id=%d, pti=%d, ebi=%d)\n",
          ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if (esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case f
     * * * * Reserved PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (esm_ebr_is_reserved (ebi) || esm_ebr_is_not_in_use (emm_context, ebi)) {
    /*
     * 3GPP TS 24.301, section 7.3.2, case f
     * * * * Reserved or assigned value that does not match an existing EPS
     * * * * bearer context
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)\n", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }

  /*
   * Message processing
   */
  /*
   * Execute the dedicated EPS bearer context activation procedure not
   * * * *  accepted by the UE
   */
  int rc = esm_proc_dedicated_eps_bearer_context_reject (emm_context, ebi, &esm_cause);

  if (rc != RETURNerror) {
    esm_cause = ESM_CAUSE_SUCCESS;
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}

/****************************************************************************
 **                                                                        **
 ** Name:    esm_recv_deactivate_eps_bearer_context_accept()           **
 **                                                                        **
 ** Description: Processes Deactivate EPS Bearer Context Accept message    **
 **                                                                        **
 ** Inputs:  ue_id:      UE local identifier                        **
 **          pti:       Procedure transaction identity             **
 **      ebi:       EPS bearer identity                        **
 **      msg:       The received ESM message                   **
 **      Others:    None                                       **
 **                                                                        **
 ** Outputs:     None                                                      **
 **      Return:    ESM cause code whenever the processing of  **
 **             the ESM message fails                      **
 **      Others:    None                                       **
 **                                                                        **
 ***************************************************************************/
esm_cause_t
esm_recv_deactivate_eps_bearer_context_accept (
  emm_context_t * emm_context,
  proc_tid_t pti,
  ebi_t ebi,
  const deactivate_eps_bearer_context_accept_msg * msg)
{
  OAILOG_FUNC_IN (LOG_NAS_ESM);
  esm_cause_t                             esm_cause = ESM_CAUSE_SUCCESS;
  mme_ue_s1ap_id_t                        ue_id = PARENT_STRUCT(emm_context, struct ue_mm_context_s, emm_context)->mme_ue_s1ap_id;

  OAILOG_INFO (LOG_NAS_ESM, "ESM-SAP   - Received Deactivate EPS Bearer Context " "Accept message (ue_id=%d, pti=%d, ebi=%d)\n",
          ue_id, pti, ebi);

  /*
   * Procedure transaction identity checking
   */
  if (esm_pt_is_reserved (pti)) {
    /*
     * 3GPP TS 24.301, section 7.3.1, case f
     * * * * Reserved PTI value
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid PTI value (pti=%d)\n", pti);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_PTI_VALUE);
  }
  /*
   * EPS bearer identity checking
   */
  else if (esm_ebr_is_reserved (ebi) || esm_ebr_is_not_in_use (emm_context, ebi)) {
    /*
     * 3GPP TS 24.301, section 7.3.2, case f
     * * * * Reserved or assigned value that does not match an existing EPS
     * * * * bearer context
     */
    OAILOG_WARNING (LOG_NAS_ESM, "ESM-SAP   - Invalid EPS bearer identity (ebi=%d)\n", ebi);
    OAILOG_FUNC_RETURN (LOG_NAS_ESM, ESM_CAUSE_INVALID_EPS_BEARER_IDENTITY);
  }

  /*
   * Message processing
   */
  /*
   * Execute the default EPS bearer context activation procedure accepted
   * * * * by the UE
   */
  int pid = esm_proc_eps_bearer_context_deactivate_accept (emm_context, ebi, &esm_cause);

  if (pid != RETURNerror) {
    /*
     * Release all the resources reserved for the PDN
     */
    int rc = esm_proc_pdn_disconnect_accept (emm_context, pid, &esm_cause);

    if (rc != RETURNerror) {
      esm_cause = ESM_CAUSE_SUCCESS;
    }
  }

  /*
   * Return the ESM cause value
   */
  OAILOG_FUNC_RETURN (LOG_NAS_ESM, esm_cause);
}

/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/
