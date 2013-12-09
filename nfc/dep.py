# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://www.osor.eu/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------

import logging
log = logging.getLogger(__name__)

from os import urandom
from time import time
from collections import namedtuple

import nfc.clf

class DataExchangeProtocol(object):
    def __init__(self, clf):
        self.exchange = lambda self, send_data, timeout: None
        self.count = Counters()
        self.clf = clf
        self.gbi = ""
        self.gbt = ""

    @property
    def general_bytes(self):
        """The general bytes received with the ATR exchange"""
        if isinstance(self, Initiator):
            return str(self.gbt)
        if isinstance(self, Target):
            return str(self.gbi)

    @property
    def role(self):
        """Role in DEP communication, either 'Target' or 'Initiator'"""
        if isinstance(self, Initiator):
            return "Initiator"
        if isinstance(self, Target):
            return "Target"

    @property
    def stat(self):
        return str(self) + " sent/rcvd " \
            "INF {count.inf_sent}/{count.inf_rcvd} " \
            "ATN {count.atn_sent}/{count.atn_rcvd} " \
            "ACK {count.ack_sent}/{count.ack_rcvd} " \
            "NAK {count.nak_sent}/{count.nak_rcvd} " \
            .format(count=self.count)

class Initiator(DataExchangeProtocol):
    def __init__(self, clf):
        DataExchangeProtocol.__init__(self, clf)
        self.brm = None # bit-rate modulation ('106A', '212F', '424F')
        self.miu = None # maximum information unit size
        self.did = None # dep device identifier
        self.nad = None # dep node address
        self.gbt = None # general bytes from target
        self.pni = None # dep packet number information
        self.rwt = None # target response waiting time

    def __str__(self):
        return "NFC-DEP Initiator"

    def activate(self, timeout=None, brs=(0, 1, 2), gbi='', did=None, lr=3):
        """Activate DEP communication as Initiator."""

        if self.clf.capabilities.get('NFC-DEP') is True:
            log.debug("using hardware DEP implementation")
            gbt = self.clf.sense(targets=None, gbi=gbi)
            self.exchange = self._hw_dep_exchange
            return gbt
            
        # brs: bit rate selection, an integer or list of integers, 0 => 106A
        if not timeout: timeout = 4096 * 2**12 / 13.56E6
        if type(brs) == int: brs = (brs,)
        if did is not None: self.did = did

        assert min(brs) >= 0 and max(brs) <= 2
        
        ba = lambda s: bytearray(s.decode("hex"))
        tta = {'cfg': None, 'uid': None}
        ttf = {'idm': ba("01FE"), 'pmm': None, 'sys': ba('FFFF')}

        targets = []
        for br in brs:
            if   br == 0: targets.append(nfc.clf.TTA(br=106, **tta))
            elif br == 1: targets.append(nfc.clf.TTF(br=212, **ttf))
            elif br == 2: targets.append(nfc.clf.TTF(br=424, **ttf))

        target = self.clf.sense(targets)
        if target is None:
            return None
        if type(target) == nfc.clf.TTA:
            if len(target.cfg) < 3 or target.cfg[2] & 0x40 == 0:
                return None
        
        self.brm = {106: '106A', 212: '212F', 424: '424F'}[target.br]
        log.info("communication with p2p target started in {0}"
                 .format(self.brm))

        if type(target) == nfc.clf.TTA:
            nfcid3 = target.uid + urandom(4) + '\x00\x00'
        if type(target) == nfc.clf.TTF:
            nfcid3 = target.idm + '\x00\x00'

        ppi = (lr << 4) | (bool(gbi) << 1) | int(bool(self.nad))
        did = int(bool(self.did))
        
        atr_req = ATR_REQ(nfcid3, did, 0, 0, ppi, gbi)
        if len(atr_req) > 64:
            raise nfc.clf.ProtocolError("14.6.1.1")

        try: atr_res = self.send_req_recv_res(atr_req, timeout=2**24/13.56E6)
        except nfc.clf.DigitalProtocolError: return
        
        if type(atr_res) != ATR_RES:
            raise nfc.clf.ProtocolError("Table-86")
        if len(atr_res) > 64:
            raise nfc.clf.ProtocolError("14.6.1.3")

        self.rwt = 4096/13.56E6 * pow(2, atr_res.wt if atr_res.wt < 15 else 14)
        self.miu = atr_res.lr - 3
        self.gbt = atr_res.gb

        if (106, 212, 424).index(target.br) < max(brs):
            psl_req = PSL_REQ(self.did, max(brs) | max(brs)<<3, lr)
            try: psl_res = self.send_req_recv_res(psl_req, timeout=self.rwt)
            except nfc.clf.DigitalProtocolError: return
            if type(psl_res) != PSL_RES:
                raise nfc.clf.ProtocolError("Table-86")
            if psl_res.did != psl_req.did:
                raise nfc.clf.ProtocolError("14.7.2.2")
            self.brm = ("106A", "212F", "424F")[psl_req.dsi]
            self.clf.set_communication_mode(self.brm)
            log.info("communication with p2p target changed to {0}"
                     .format(self.brm))

        self.pni = 0
        self.exchange = self._sw_dep_exchange
        return atr_res.gb

    def deactivate(self, release=True):
        if self.exchange == self._sw_dep_exchange:
            REQ, RES = (RLS_REQ, RLS_RES) if release else (DSL_REQ, DSL_RES)
            req = REQ(self.did)
            try:
                res = self.send_req_recv_res(req, 0.1)
            except nfc.clf.DigitalProtocolError:
                pass
            else:
                if type(res) != RES:
                    raise nfc.clf.ProtocolError("Table-86")
                if res.did != req.did:
                    raise nfc.clf.ProtocolError("14.7.2.2")
            log.info(self.stat)
        self.exchange = lambda self, send_data, timeout: None
        return True

    def _hw_dep_exchange(self, send_data, timeout):
        log.debug("dep raw >> " + str(send_data).encode("hex"))
        send_data = bytearray(send_data)
        recv_data = self.clf.exchange(send_data, timeout)
        if recv_data is not None:
            recv_data = str(recv_data)
            log.debug("dep raw << " + recv_data.encode("hex"))
            return recv_data
        
    def _sw_dep_exchange(self, send_data, timeout):
        def INF(pni, data, more, did, nad):
            pdu_type = (DEP_REQ.LastInformation, DEP_REQ.MoreInformation)[more]
            pfb = DEP_REQ.PFB(pdu_type, nad is not None, did is not None, pni)
            return DEP_REQ(pfb, did, nad, data)
            
        def ACK(pni, did, nad):
            pdu_type = DEP_REQ.PositiveAck
            pfb = DEP_REQ.PFB(pdu_type, nad is not None, did is not None, pni)
            return DEP_REQ(pfb, did, nad, data=None)
        
        def RTOX(rtox, did, nad):
            if rtox < 1 or rtox > 59:
                raise nfc.clf.ProtocolError("14.8.4.2")
            pdu_type = DEP_REQ.TimeoutExtension
            pfb = DEP_REQ.PFB(pdu_type, nad is not None, did is not None, 0)
            return DEP_REQ(pfb, did, nad, data=bytearray([rtox]))

        #log.debug("dep raw >> " + str(send_data).encode("hex"))
        send_data = bytearray(send_data)
        
        while send_data:
            data = send_data[0:self.miu]; del send_data[0:self.miu]
            req = INF(self.pni, data, bool(send_data), self.did, self.nad)
            res = self.send_dep_req_recv_dep_res(req, timeout)
            self.count.inf_sent += 1
            if res.pfb.type == DEP_RES.TimeoutExtension:
                req = RTOX(res.data[0], self.did, self.nad)
                rwt = res.data[0] * self.rwt
                log.warning("target requested %.3f sec more time" % rwt)
                res = self.send_dep_req_recv_dep_res(req, min(timeout, rwt))
            if res.pfb.type == DEP_RES.TimeoutExtension:
                log.error("target repeated timeout extension request")
                raise nfc.clf.TimeoutError("repeated timeout extension")
            if res.pfb.type == DEP_RES.PositiveAck:
                self.count.ack_rcvd += 1
                if not send_data:
                    raise nfc.clf.ProtocolError("14.12.4.3")
            if res.pfb.pni != self.pni:
                raise nfc.clf.ProtocolError("14.12.3.3")
            self.pni = (self.pni + 1) & 0x3
        
        if (res.pfb.type != DEP_RES.LastInformation and
            res.pfb.type != DEP_RES.MoreInformation):
            raise nfc.clf.ProtocolError("14.12.4.6")
        
        recv_data = res.data
        self.count.inf_rcvd += 1
        
        while res.pfb.type == DEP_RES.MoreInformation:
            req = ACK(self.pni, self.did, self.nad)
            res = self.send_dep_req_recv_dep_res(req, timeout)
            self.count.ack_sent += 1
            if res.pfb.type == DEP_RES.TimeoutExtension:
                req = RTOX(res.data[0], self.did, self.nad)
                rwt = res.data[0] * self.rwt
                log.warning("target requested %.3f sec more time" % rwt)
                res = self.send_dep_req_recv_dep_res(req, min(timeout, rwt))
            if res.pfb.type == DEP_RES.TimeoutExtension:
                log.error("target repeated timeout extension request")
                raise nfc.clf.TimeoutError("repeated timeout extension")
            if (res.pfb.type != DEP_RES.LastInformation and
                res.pfb.type != DEP_RES.MoreInformation):
                raise nfc.clf.ProtocolError("14.12.4.7")
            if res.pfb.pni != self.pni:
                raise nfc.clf.ProtocolError("14.12.3.3")
            recv_data += res.data
            self.pni = (self.pni + 1) & 0x3
            self.count.inf_rcvd += 1
                
        #log.debug("dep raw << " + str(recv_data).encode("hex"))
        return str(recv_data)

    def send_dep_req_recv_dep_res(self, req, timeout):
        def NAK(pni, did, nad):
            pdu_type = DEP_REQ.NegativeAck
            pfb = DEP_REQ.PFB(pdu_type, nad != None, did != None, self.pni)
            return DEP_REQ(pfb, did, nad, data=None)

        def ATN():
            pdu_type = DEP_REQ.Attention
            pfb = DEP_REQ.PFB(pdu_type, nad=False, did=False, pni=0)
            return DEP_REQ(pfb, did=None, nad=None, data=None)

        def request_attention(self, n_retry_atn, deadline):
            req = ATN()
            for i in range(n_retry_atn):
                timeout = min(self.rwt, deadline - time())
                if timeout <= 0: raise nfc.clf.TimeoutError
                try:
                    res = self.send_req_recv_res(req, timeout)
                except nfc.clf.DigitalProtocolError:
                    continue
                self.count.atn_sent += 1
                if res.pfb.type == DEP_RES.TimeoutExtension:
                    raise nfc.clf.ProtocolError("14.12.4.4")
                if res.pfb.type != DEP_RES.Attention:
                    raise nfc.clf.ProtocolError("14.12.4.2")
                self.count.atn_rcvd += 1
                return
            raise nfc.clf.ProtocolError("14.12.5.6")
            
        def request_retransmission(self, n_retry_nak, deadline):
            req = NAK(self.pni, self.did, self.nad)
            for i in range(n_retry_nak):
                timeout = min(self.rwt, deadline - time())
                if timeout <= 0: raise nfc.clf.TimeoutError
                try:
                    res = self.send_req_recv_res(req, timeout)
                except nfc.clf.DigitalProtocolError:
                    continue
                self.count.nak_sent += 1
                if res.pfb.type == DEP_RES.TimeoutExtension:
                    raise nfc.clf.ProtocolError("14.12.4.4")
                expected = (DEP_RES.LastInformation, DEP_RES.MoreInformation)
                if res.pfb.type not in expected:
                    raise nfc.clf.ProtocolError("14.12.5.4")
                return res
            raise nfc.clf.ProtocolError("14.12.5.6")
        
        deadline = time() + timeout
        while True:
            timeout = min(self.rwt, deadline - time())
            if timeout <= 0: raise nfc.clf.TimeoutError()
            try:
                res = self.send_req_recv_res(req, timeout)
                break
            except nfc.clf.TimeoutError:
                request_attention(self, 2, deadline)
                continue
            except nfc.clf.TransmissionError:
                res = request_retransmission(self, 2, deadline)
                break

        if res.pfb.type == DEP_RES.NegativeAck:
            raise nfc.clf.ProtocolError("14.12.4.5")
        
        return res
        
    def send_req_recv_res(self, req, timeout):
        cmd = self.encode_frame(req)
        rsp = self.clf.exchange(cmd, timeout)
        res = self.decode_frame(rsp)
        if res.PDU_NAME[0:3] != req.PDU_NAME[0:3]:
            raise nfc.clf.ProtocolError("Table-86")
        return res

    def encode_frame(self, packet):
        log.debug(">> {0}".format(packet))
        frame = packet.encode()
        frame = chr(len(frame) + 1) + frame
        if self.brm == '106A':
            frame = '\xF0' + frame
        return frame
        
    def decode_frame(self, frame):
        if self.brm == '106A' and frame.pop(0) != 0xF0:
            raise nfc.clf.ProtocolError("14.4.1.1")
        if len(frame) != frame.pop(0):
            raise nfc.clf.ProtocolError("14.4.1.2")
        if len(frame) < 2:
            raise nfc.clf.TransmissionError("14.4.1.3")
        if frame[0] != 0xD5 or frame[1] not in (1, 5, 7, 9, 11):
            raise nfc.clf.ProtocolError("Table-86")
        res_name = {1: 'ATR', 5: 'PSL', 7: 'DEP', 9: 'DSL', 11: 'RLS'}
        packet = eval(res_name[frame[1]] + "_RES").decode(frame)
        log.debug("<< {0}".format(packet))
        return packet
        
class Target(DataExchangeProtocol):
    def __init__(self, clf):
        DataExchangeProtocol.__init__(self, clf)
        self.brm = None # bit-rate modulation (106A, 212F, 424F)
        self.miu = None # maximum information unit size
        self.did = None # dep device identifier
        self.nad = None # dep node address
        self.gbi = None # general bytes from initiator
        self.pni = None # dep packet number information
        self.rwt = None # target response waiting time
        self.req = None # first dep-req received in activation

    def __str__(self):
        return "NFC-DEP Target"

    def activate(self, timeout=None, brs=None, gbt='', wt=8, lr=3):
        """Activate DEP communication as Target."""
        # brs (int): bit rate selection, 0 => 106A, 1 => 212F, 2 => 424F
        if not timeout: timeout = (372 + ord(urandom(1))) * 1E-3

        ba = lambda s: bytearray(s.decode("hex"))
        tta = {'cfg':ba('010040'),'uid':ba('08')+urandom(3)}
        ttf = {'idm':ba("01FE")+urandom(6),'pmm':ba("FF"*8),'sys':ba('FFFF')}
        
        deadline = time() + timeout

        target = nfc.clf.DEP(br={0: 106, 1: 212, 2: 424}.get(brs), gb=gbt)
        activated = self.clf.listen(target, timeout)
        if not activated: return None

        target, req_frame = activated
        self.brm = {106: '106A', 212: '212F', 424: '424F'}[target.br]
        log.debug("communication as p2p target started in {0}"
                  .format(self.brm))

        if self.clf.capabilities.get('NFC-DEP') is True:
            self.exchange = self._hw_dep_exchange
            self.req = req_frame
            return target.gb
        
        req = self.decode_frame(req_frame)
        while type(req) != ATR_REQ or len(req) > 64:
            req = self.send_res_recv_req(None, max(deadline, time()+1.0))
        
        atr_req = req
        if (type(target) == nfc.clf.TTF and not
            atr_req.nfcid3.startswith(target.idm)):
            raise nfc.clf.ProtocolError("14.6.2.1")

        self.miu = atr_req.lr - 3
        self.did = atr_req.did if atr_req.did > 0 else None
        self.gbi = atr_req.gb
        
        pp = (lr << 4) | (bool(gbt) << 1) | int(bool(self.nad))        
        atr_res = ATR_RES(atr_req.nfcid3, atr_req.did, 0, 0, wt, pp, gbt)
        if len(atr_res) > 64:
            raise nfc.clf.ProtocolError("14.6.1.4")

        try: req = self.send_res_recv_req(atr_res, max(deadline, time()+1.0))
        except nfc.clf.TimeoutError: return
        
        if type(req) == PSL_REQ and req.did == atr_req.did:
            self.miu = req.lr - 3
            res = PSL_RES(did=req.did)
            self.send_res_recv_req(res, 0)
            self.brm = ("106A", "212F", "424F")[req.dsi]
            self.clf.set_communication_mode(self.brm)
            # FIXME: wait time should be shorter
            req = self.send_res_recv_req(None, max(deadline, time()+2.0))
            log.debug("communication as p2p target changed to {0}"
                      .format(self.brm))

        if type(req) == DEP_REQ and req.did == self.did:
            self.exchange = self._sw_dep_exchange
            self.rwt = 4096/13.56E6 * pow(2, wt)
            self.pni = 0
            self.req = req
            return atr_req.gb
        elif type(req) == DSL_REQ:
            self.send_res_recv_req(DSL_RES(self.did), 0)
        elif type(req) == RLS_REQ:
            self.send_res_recv_req(RLS_RES(self.did), 0)
    
    def deactivate(self):
        if self.exchange == self._sw_dep_exchange:
            log.info(self.stat)
        self.exchange = lambda self, send_data, timeout: None

    def _hw_dep_exchange(self, send_data, timeout):
        if self.req is not None:
            # first packet is received in activate()
            assert send_data is None, "send_data must be None on first call"
            recv_data = self.req; self.req = None
        else:
            log.debug("dep raw >> " + str(send_data).encode("hex"))
            send_data = bytearray(send_data)
            recv_data = self.clf.exchange(send_data, timeout)

        if recv_data is not None:
            recv_data = str(recv_data)
            log.debug("dep raw << " + recv_data.encode("hex"))
            return recv_data

    def _sw_dep_exchange(self, send_data, timeout):
        def INF(pni, data, more, did, nad):
            pdu_type = (DEP_RES.LastInformation, DEP_RES.MoreInformation)[more]
            pfb = DEP_RES.PFB(pdu_type, nad is not None, did is not None, pni)
            return DEP_RES(pfb, did, nad, data)
            
        def ACK(pni, did, nad):
            pdu_type = DEP_RES.PositiveAck
            pfb = DEP_RES.PFB(pdu_type, nad is not None, did is not None, pni)
            return DEP_RES(pfb, did, nad, data=None)

        if send_data is not None and len(send_data) == 0:
            raise ValueError("send_data must not be empty")

        deadline = time() + timeout
        
        if self.req is not None:
            # first packet is received in activate()
            assert send_data is None, "send_data must be None on first call"
            req = self.req; self.req = None
        else:
            send_data = bytearray(send_data)
            while send_data:
                data = send_data[0:self.miu];
                more = len(send_data) > self.miu
                res = INF(self.pni, data, more, self.did, self.nad)
                req = self.send_dep_res_recv_dep_req(res, deadline)
                if req is None: return None
                if more and req.pfb.type is not DEP_REQ.PositiveAck:
                    raise nfc.clf.ProtocolError("14.12.2.1")
                self.pni = (self.pni + 1) & 0x3
                if req.pfb.pni != self.pni:
                    raise nfc.clf.ProtocolError("14.12.3.3")
                del send_data[0:self.miu]

        recv_data = bytearray()
        while req.pfb.type == DEP_REQ.MoreInformation:
            recv_data += req.data
            res = ACK(self.pni, self.did, self.nad)
            req = self.send_dep_res_recv_dep_req(res, deadline)
            if req is None: return None
            self.pni = (self.pni + 1) & 0x3
            if req.pfb.pni != self.pni:
                raise nfc.clf.ProtocolError("14.12.3.3")
            
        recv_data += req.data
        return str(recv_data)

    def send_timeout_extension(self, rtox):
        def RTOX(rtox, did, nad):
            pdu_type = DEP_RES.TimeoutExtension
            pfb = DEP_RES.PFB(pdu_type, nad is not None, did is not None, 0)
            return DEP_RES(pfb, did, nad, data=bytearray([rtox]))
        
        res = RTOX(rtox, self.did, self.nad)
        req = self.send_dep_res_recv_dep_req(res, deadline=time()+1)
        if type(req) == DEP_REQ and req.pfb.type == DEP_REQ.TimeoutExtension:
            return req.data[0] & 0x3F
    
    def send_dep_res_recv_dep_req(self, dep_res, deadline):
        def ATN(did, nad):
            pdu_type = DEP_RES.Attention
            pfb = DEP_RES.PFB(pdu_type, nad is not None, did is not None, 0)
            return DEP_RES(pfb, did, nad, data=None)

        res = dep_res; dep_req = None
        while dep_req == None:
            req = self.send_res_recv_req(res, deadline)
            if req is None:
                return None
            elif req.did != self.did:
                res = None
            elif type(req) == DSL_REQ:
                return self.send_res_recv_req(DSL_RES(self.did), 0)
            elif type(req) == RLS_REQ:
                return self.send_res_recv_req(RLS_RES(self.did), 0)
            elif type(req) == DEP_REQ:
                if req.pfb.type == DEP_REQ.Attention:
                    self.count.atn_rcvd += 1
                    res = ATN(self.did, self.nad)
                    self.count.atn_sent += 1
                elif req.pfb.type == DEP_REQ.NegativeAck:
                    self.count.nak_rcvd += 1
                    res = dep_res
                elif req.pfb.type == DEP_REQ.TimeoutExtension:
                    dep_req = req
                elif req.pfb.pni == self.pni:
                    res = dep_res                        
                else:
                    dep_req = req
        return dep_req
            
    def send_res_recv_req(self, res, deadline):
        frame = self.encode_frame(res) if res is not None else None
        while True:
            timeout = deadline - time() if deadline > time() else 0
            try:
                frame = self.clf.exchange(frame, timeout=timeout)
                return self.decode_frame(frame) if frame else None
            except nfc.clf.TransmissionError:
                frame = None

    def encode_frame(self, packet):
        log.debug(">> {0}".format(packet))
        frame = packet.encode()
        frame = chr(len(frame) + 1) + frame
        if self.brm == '106A':
            frame = '\xF0' + frame
        return frame
        
    def decode_frame(self, frame):
        if self.brm == '106A' and frame.pop(0) != 0xF0:
            raise nfc.clf.ProtocolError("14.4.1.1")
        if len(frame) != frame.pop(0):
            raise nfc.clf.ProtocolError("14.4.1.2")
        if len(frame) < 2:
            raise nfc.clf.TransmissionError("14.4.1.3")
        if frame[0] != 0xD4 or frame[1] not in (0, 4, 6, 8, 10):
            raise nfc.clf.ProtocolError("Table-86")
        req_name = {0: 'ATR', 4: 'PSL', 6: 'DEP', 8: 'DSL', 10: 'RLS'}
        packet = eval(req_name[frame[1]] + "_REQ").decode(frame)
        log.debug("<< {0}".format(packet))
        return packet
        
#
# Data Exchange Protocol Data Units
#
class ATR_REQ_RES(object):
    def __str__(self):
        nfcid3, gb = [str(ba).encode("hex") for ba in [self.nfcid3, self.gb]]
        return self.PDU_SHOW.format(self=self, nfcid3=nfcid3, gb=gb)
    
    @property
    def lr(self):
        return (64, 128, 192, 254)[(self.pp >> 4) & 0x3]
    
class ATR_REQ(ATR_REQ_RES):
    PDU_CODE = bytearray('\xD4\x00')
    PDU_NAME = 'ATR-REQ'
    PDU_SHOW = "{self.PDU_NAME} NFCID3={nfcid3} DID={self.did:02x} "\
        "BS={self.bs:02x} BR={self.br:02x} PP={self.pp:02x} GB={gb}"
    
    def __init__(self, nfcid3, did, bs, br, pp, gb):
        self.nfcid3, self.did, self.bs, self.br, self.pp, self.gb = \
            nfcid3, did, bs, br, pp, gb

    def __len__(self):
        return 16 + len(self.gb)

    @staticmethod
    def decode(data):
        if data.startswith(ATR_REQ.PDU_CODE):
            nfcid3, (did, bs, br, pp) = data[2:12], data[12:16]
            gb = data[16:] if pp & 0x02 else bytearray()
            return ATR_REQ(nfcid3, did, bs, br, pp, gb)

    def encode(self):
        data = ATR_REQ.PDU_CODE + self.nfcid3
        data.extend([self.did, self.bs, self.br, self.pp])
        return data + self.gb
    
class ATR_RES(ATR_REQ_RES):
    PDU_CODE = bytearray('\xD5\x01')
    PDU_NAME = 'ATR-RES'
    PDU_SHOW = "{self.PDU_NAME} NFCID3={nfcid3} DID={self.did:02x} "\
        "BS={self.bs:02x} BR={self.br:02x} TO={self.to:02x} "\
        "PP={self.pp:02x} GB={gb}"
    
    def __init__(self, nfcid3, did, bs, br, to, pp, gb):
        self.nfcid3, self.did, self.bs, self.br, self.to, self.pp, self.gb = \
            nfcid3, did, bs, br, to, pp, gb
    
    def __len__(self):
        return 17 + len(self.gb)

    @staticmethod
    def decode(data):
        if data.startswith(ATR_RES.PDU_CODE):
            nfcid3, (did, bs, br, to, pp) = data[2:12], data[12:17]
            gb = data[17:] if pp & 0x02 else bytearray()
            return ATR_RES(nfcid3, did, bs, br, to, pp, gb)

    def encode(self):
        data = ATR_RES.PDU_CODE + self.nfcid3
        data.extend([self.did, self.bs, self.br, self.to, self.pp])
        return data + self.gb

    @property
    def wt(self):
        return self.to & 0x0F

class PSL_REQ_RES(object):
    def __str__(self):
        return self.PDU_SHOW.format(name=self.PDU_NAME, self=self) 
    
    @classmethod
    def decode(cls, data):
        if data.startswith(cls.PDU_CODE):
            try:
                return cls(*data[2:])
            except ValueError:
                raise ProtocolError(cls.PDU_SPEC)

class PSL_REQ(PSL_REQ_RES):
    PDU_CODE = bytearray('\xD4\x04')
    PDU_NAME = 'PSL-REQ'
    PDU_SPEC = 'Table-98'
    PDU_SHOW = "{name} DID={self.did} BRS={self.brs:02x}, FSL={self.fsl:02x}"
    
    def __init__(self, did, brs, fsl):
        self.did, self.brs, self.fsl = did if did else 0, brs, fsl

    def encode(self):
        return PSL_REQ.PDU_CODE + bytearray([self.did, self.brs, self.fsl])
    
    @property
    def dsi(self):
        return self.brs >> 3 & 0x07
    
    @property
    def dri(self):
        return self.brs & 0x07

    @property
    def lr(self):
        return (64, 128, 192, 254)[self.fsl & 0x03]

class PSL_RES(PSL_REQ_RES):
    PDU_CODE = bytearray('\xD5\x05')
    PDU_NAME = 'PSL-RES'
    PDU_SPEC = 'Table-102'
    PDU_SHOW = "{name} DID={self.did}"
    
    def __init__(self, did):
        self.did = did

    def encode(self):
        return PSL_RES.PDU_CODE + bytearray([self.did])

class DEP_REQ_RES(object):
    PDU_SHOW = "{self.PDU_NAME} {self.pfb} DID={self.did} "\
        "NAD={self.nad} DATA={data}"
    
    PFB = namedtuple("PFB", "type, nad, did, pni")
    LastInformation, MoreInformation, PositiveAck, NegativeAck,\
        Attention, TimeoutExtension = (0, 1, 4, 5, 8, 9)

    def __init__(self, pfb, did, nad, data):
        self.pfb, self.did, self.nad = pfb, did, nad
        self.data = bytearray() if data is None else data

    def __str__(self):
        data = str(self.data).encode("hex")
        return self.PDU_SHOW.format(self=self, data=data)
    
    @classmethod
    def decode(cls, data):
        if data.startswith(cls.PDU_CODE):
            del data[0:2]
            try:
                pfb = data.pop(0)
                pfb = cls.PFB(pfb >> 4, bool(pfb & 8), bool(pfb & 4), pfb & 3)
                did = data.pop(0) if pfb.did else None
                nad = data.pop(0) if pfb.nad else None
            except IndexError:
                raise ProtocolError(cls.PDU_SPEC)                
            return cls(pfb, did, nad, data)

    def encode(self):
        pfb = self.pfb
        pfb = (pfb.type << 4) | (pfb.nad << 3) | (pfb.did << 2) | (pfb.pni)
        data = self.PDU_CODE + chr(pfb)
        if self.pfb.did: data.append(self.did)
        if self.pfb.nad: data.append(self.nad)
        return data + self.data

class DEP_REQ(DEP_REQ_RES):
    PDU_CODE = bytearray('\xD4\x06')
    PDU_NAME = 'DEP-REQ'
    PDU_SPEC = 'Table-103'
    
class DEP_RES(DEP_REQ_RES):
    PDU_CODE = bytearray('\xD5\x07')
    PDU_NAME = 'DEP-RES'
    PDU_SPEC = 'Table-104'
    
class DSL_REQ_RES(object):
    def __init__(self, did):
        self.did = did

    def __str__(self):
        return "{0} DID={1}".format(self.PDU_NAME, self.did)
    
    @classmethod
    def decode(cls, data):
        if data.startswith(cls.PDU_CODE):
            if len(data) > 3:
                raise ProtocolError(cls.PDU_SPEC)
            return cls(data[2] if len(data) == 3 else None)
        
    def encode(self):
        return self.PDU_CODE + ('' if self.did is None else chr(self.did))
    
class DSL_REQ(DSL_REQ_RES):
    PDU_CODE = bytearray('\xD4\x08')
    PDU_NAME = 'DSL-REQ'
    PDU_SPEC = 'Table-110'
    
class DSL_RES(DSL_REQ_RES):
    PDU_CODE = bytearray('\xD5\x09')
    PDU_NAME = 'DSL-RES'
    PDU_SPEC = 'Table-111'

class RLS_REQ_RES(DSL_REQ_RES):
    pass

class RLS_REQ(RLS_REQ_RES):
    PDU_CODE = bytearray('\xD4\x0A')
    PDU_NAME = 'RLS-REQ'
    PDU_SPEC = 'Table-112'
    
class RLS_RES(RLS_REQ_RES):
    PDU_CODE = bytearray('\xD5\x0B')
    PDU_NAME = 'RLS-RES'
    PDU_SPEC = 'Table-113'

class Counters:
    inf_sent = 0
    inf_rcvd = 0
    atn_sent = 0
    atn_rcvd = 0
    ack_sent = 0
    ack_rcvd = 0
    nak_sent = 0
    nak_rcvd = 0

def fatal_error(message, retval=None):
    log.error(message)
    return retval

