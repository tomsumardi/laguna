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

#include "tcpktparse.h"
#include "tcutil.h"

/* IP Layer Macro */
#define TRANSC_PRS_L3IPV4               0x0800
#define TRANSC_PRS_L3IPV6               0x86DD

/**************** PROTECTED Functions **********************/
CCUR_PROTECTED(tresult_t)
tcPktParseTCP(U8 * pTcpHdrLen,
        tc_pktdesc_t * pPktDesc, tc_phshdr_sz_t * pPktDescSz)
{
    U8*         _pTcpHdr;
    U8          _nHdrLenBytes;
    U32         _nCapturedPktLen;
    tresult_t   _result;

    CCURASSERT(pPktDesc);

    do
    {
        _result = EFAILURE;
        _nCapturedPktLen =
                pPktDesc->nCaplen-
                pPktDescSz->nL4Offset;
        /* TCP start Header pointer  */
        _pTcpHdr =
                pPktDesc->pMsgStrt+
                pPktDescSz->nL4Offset;
        memcpy( &_nHdrLenBytes,
                _pTcpHdr + 12, sizeof( U8 ) );
       _nHdrLenBytes =
                (_nHdrLenBytes & 0xF0) >> 2;
        if(_nCapturedPktLen < _nHdrLenBytes)
            break;
        *pTcpHdrLen = _nHdrLenBytes;
        /* TCP start payload pointer  */
        pPktDesc->tcpHdr.pPyld =
                _pTcpHdr + _nHdrLenBytes;
        pPktDescSz->nPayloadOffset =
                pPktDescSz->nL4Offset+
                _nHdrLenBytes;
        /* TCP Payload length */
        pPktDesc->tcpHdr.nPyldLen =
                pPktDesc->nCaplen -
                pPktDescSz->nPayloadOffset;
        if(pPktDesc->tcpHdr.nPyldLen < 0 )
            break;
        /* Populate packet descriptor with header data.  */
        pPktDesc->tcpHdr.nSrcPort = ccur_nptrtohs( _pTcpHdr );
        pPktDesc->tcpHdr.nDstPort = ccur_nptrtohs( _pTcpHdr + 2 );
        pPktDesc->tcpHdr.nTcpFlags = *(_pTcpHdr + 13);
        /*pPktDesc->tcpHdr.nTcpWindow = ccur_nptrtohs( _pTcpHdr + 14 );*/
        pPktDesc->tcpHdr.nTcpSeq = ccur_nptrtohl( _pTcpHdr + 4 );
        if( pPktDesc->tcpHdr.nTcpFlags & TCTCPFLG_ACK )
            pPktDesc->tcpHdr.nTcpAck = ccur_nptrtohl( _pTcpHdr + 8 );
        /*if( pPktDesc->tcpHdr.nTcpFlags & TCTCPFLG_URG )
            pPktDesc->tcpHdr.nTcpUrgPtr = ccur_nptrtohl( _pTcpHdr + 18 );*/
        _result = ESUCCESS;
    }while(FALSE);

    return _result;
}
