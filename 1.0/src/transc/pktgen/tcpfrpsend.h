/*
  Copyright 2015 Concurrent Computer Corporation

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef TCPFRPSEND_H
#define TCPFRPSEND_H

#ifdef __cplusplus
extern "C" {
#endif

CCUR_PROTECTED(BOOL)
tcPfrPsendInitIsTxIntfLinkUp(
        tc_pktgen_thread_ctxt_t * pCntx);

CCUR_PROTECTED(tresult_t)
tcPfrPsendInitLibPfringTx(tc_pktgen_thread_ctxt_t*  pCntx,
                          U16                       nIntfIdx);

CCUR_PROTECTED(tresult_t)
tcPfrPsendShutdownLibPfringTx(
        tc_outintf_out_t*    pOutIntf);

CCUR_PROTECTED(I32)
tcPfrPsendLibPfringTx(
        tc_pktgen_thread_ctxt_t*        pCntx,
        tc_outintf_out_t*              pOutIntf,
        tc_pktgen_pktinj_t*             pkt);

CCUR_PROTECTED(CHAR*)
tcPfrPsendGetStatPfringTx(
        tc_pktgen_thread_ctxt_t*    pCntx,
        CHAR*                       strBuff,
        U32                         nstrBuff);

#ifdef __cplusplus
}
#endif
#endif /* TCPFRPSEND_H */
