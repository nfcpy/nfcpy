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
        return "sent/rcvd " \
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
        msg = "NFC-DEP Initiator {brty} {mode} mode MIU={miu} RWT={rwt:.6f}"
        return msg.format(brty=self.brm, miu=self.miu, rwt=self.rwt,
                          mode=("passive", "active")[self.acm])

    def activate(self, **options):
        """Activate DEP communication with a target."""

        log.debug("initiator options: {0}".format(options))

        timeout = 4096 * 2**12 / 13.56E6
        self.did = options.get('did', None)
        self.nad = options.get('nad', None)
        self.gbi = options.get('gbi', '')
        self.brs = options.get('brs', 2)
        self.lri = options.get('lri', 3)
        self.acm = options.get('acm', True)

        assert self.did is None or (self.did >=0 and self.did <= 255)
        assert self.nad is None or (self.nad >=0 and self.nad <= 255)
        assert self.brs in range(3)
        assert self.lri in range(4)
        assert len(self.gbi) <= 48

        ppi = (self.lri << 4) | (bool(self.gbi) << 1) | int(bool(self.nad))
        did = 0 if self.did is None else self.did
        atr_req = ATR_REQ(urandom(10), did, 0, 0, ppi, self.gbi).encode()
        psl_req = PSL_REQ(did, (0, 9, 18)[self.brs], self.lri).encode()

        targets = []
        if self.acm == True and self.brs > 0:
            # add 212 or 424 active communication mode
            targets.append(nfc.clf.DEP((212, 424)[self.brs], atr_req=atr_req))
            # add 106 active communication mode with bitrate change
            targets.append(nfc.clf.DEP(106, atr_req=atr_req, psl_req=psl_req))
        if self.acm == True and self.brs == 0:
            # only 106 kbps active communication mode is requested
            targets.append(nfc.clf.DEP(106, atr_req=atr_req))

        if self.brs > 0:
            # add sense for 212F or 424F passive communication mode
            targets.append(nfc.clf.TTF(106 << self.brs))

        # always sense for 106A passive communication mode
        targets.append(nfc.clf.TTA(106))

        self.clf.sense() # make sure to forget a captured target
        target = self.clf.sense(*targets, iterations=2, interval=0.1)
        if target is None: return None

        if type(target) is nfc.clf.TTA:
            if not (target.sel_res and target.sel_res[0] & 0x40 == 0x40):
                log.debug("Type A Target does not support DEP")
                return None

        if type(target) is nfc.clf.TTF:
            if not target.sens_res[1:3] == "\x01\xFE":
                log.debug("Type F Target does not support DEP")
                return None

        if type(target) in (nfc.clf.TTA, nfc.clf.TTF):
            self.acm = False
            passive_dep_target = nfc.clf.DEP(target.bitrate)
            passive_dep_target.atr_req = atr_req
            if target.bitrate < (106 << self.brs):
                passive_dep_target.psl_req = psl_req
            target = self.clf.sense(passive_dep_target)

        if not (target and target.atr_res and len(target.atr_res) >= 17):
            log.info("target activation failed")
            return None

        log.info("running p2p communication in {0}".format(target.brty))

        atr_res = ATR_RES.decode(target.atr_res)
        self.rwt = 4096/13.56E6 * 2**(atr_res.wt if atr_res.wt < 15 else 14)
        self.miu = atr_res.lr - 3
        self.gbt = atr_res.gb
        self.pni = 0
        self.brm = target.brty
        return self.gbt

    def deactivate(self, release=True):
        REQ, RES = (RLS_REQ, RLS_RES) if release else (DSL_REQ, DSL_RES)
        req = REQ(self.did)
        try:
            res = self.send_req_recv_res(req, 0.1)
        except nfc.clf.DigitalError:
            pass
        else:
            if type(res) != RES:
                log.error("received unexpected response for " + req.NAME)
            if res.did != req.did:
                log.error("target returned wrong DID in " + res.NAME)
        log.info("stop {0}, packets {1}".format(self, self.stat))
        return True

    def exchange(self, send_data, timeout):
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
                error = "NFC-DEP RTOX must be in range 1 to 59"
                raise nfc.clf.ProtocolError(error)
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
                    error = "unexpected or out-of-sequence NFC-DEP ACK PDU"
                    raise nfc.clf.ProtocolError(error)
            if res.pfb.pni != self.pni:
                raise nfc.clf.ProtocolError("wrong NFC-DEP packet number")
            self.pni = (self.pni + 1) & 0x3
        
        if (res.pfb.type != DEP_RES.LastInformation and
            res.pfb.type != DEP_RES.MoreInformation):
            error = "expected NFC-DEP INF PDU after sending"
            raise nfc.clf.ProtocolError(error)
        
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
                error = "NFC-DEP chaining not continued after ACK"
                raise nfc.clf.ProtocolError(error)
            if res.pfb.pni != self.pni:
                raise nfc.clf.ProtocolError("wrong NFC-DEP packet number")
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
                except nfc.clf.DigitalError:
                    continue
                self.count.atn_sent += 1
                if res.pfb.type == DEP_RES.TimeoutExtension:
                    error = "received NFC-DEP RTOX response to NACK or ATN"
                    raise nfc.clf.ProtocolError(error)
                if res.pfb.type != DEP_RES.Attention:
                    error = "expected NFC-DEP Attention response"
                    raise nfc.clf.ProtocolError(error)
                self.count.atn_rcvd += 1
                return
            error = "unrecoverable NFC-DEP error in attention request"
            raise nfc.clf.ProtocolError(error)
            
        def request_retransmission(self, n_retry_nak, deadline):
            req = NAK(self.pni, self.did, self.nad)
            for i in range(n_retry_nak):
                timeout = min(self.rwt, deadline - time())
                if timeout <= 0: raise nfc.clf.TimeoutError
                try:
                    res = self.send_req_recv_res(req, timeout)
                except nfc.clf.DigitalError:
                    continue
                self.count.nak_sent += 1
                if res.pfb.type == DEP_RES.TimeoutExtension:
                    error = "received NFC-DEP RTOX response to NACK or ATN"
                    raise nfc.clf.ProtocolError(error)
                expected = (DEP_RES.LastInformation, DEP_RES.MoreInformation)
                if res.pfb.type not in expected:
                    error = "unrecoverable NFC-DEP transmission error"
                    raise nfc.clf.ProtocolError(error)
                return res
            error = "unrecoverable NFC-DEP error in retransmission request"
            raise nfc.clf.ProtocolError(error)
        
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
            error = "received NFC-DEP NACK PDU from Target"
            raise nfc.clf.ProtocolError(error)
        
        return res
        
    def send_req_recv_res(self, req, timeout):
        cmd = self.encode_frame(req)
        rsp = self.clf.exchange(cmd, timeout)
        res = self.decode_frame(rsp)
        if res.PDU_NAME[0:3] != req.PDU_NAME[0:3]:
            raise nfc.clf.ProtocolError("invalid response for " + req.PDU_NAME)
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
            error = "first NFC-DEP frame byte must be F0h for 106A"
            raise nfc.clf.ProtocolError(error)
        if len(frame) != frame.pop(0):
            error = "NFC-DEP frame length byte must be data length + 1"
            raise nfc.clf.ProtocolError(error)
        if len(frame) < 2:
            error = "NFC-DEP frame length byte must be from 3 to 255"
            raise nfc.clf.TransmissionError(error)
        if frame[0] != 0xD5 or frame[1] not in (1, 5, 7, 9, 11):
            raise nfc.clf.ProtocolError("invalid NFC-DEP response code")
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
        msg = "NFC-DEP Target {brty} {mode} mode MIU={miu} RWT={rwt:.6f}"
        return msg.format(brty=self.brm, miu=self.miu, rwt=self.rwt,
                          mode=("passive", "active")[self.acm])

    def activate(self, timeout=None, **options):
        """Activate DEP communication as a target."""
        
        if timeout is None: timeout = 1.0
        self.gbt = options.get('gbt', '')
        self.lrt = options.get('lrt', 3)
        self.acm = options.get('acm', True)
        self.rwt = options.get('rwt', 0.077)
        for wt, rwt in enumerate([4096/13.56E6 * 2**wt for wt in range(15)]):
            if rwt >= self.rwt: self.rwt = rwt; break
        else: self.rwt = 67108864/13.56E6
        
        ba = lambda s: bytearray.fromhex(s)
        sensa_res=ba("0101"); sdd_res=ba("08") + urandom(3); sel_res=ba("40")
        sensf_res=ba("0101FE") + urandom(6) + ba("00000000 00000000 FFFF")

        pp = (self.lrt << 4) | (bool(self.gbt) << 1) | int(bool(self.nad))
        atr_res = ATR_RES(sensf_res[0:8]+"\0\0", 0, 0, 0, wt, pp, self.gbt)
        atr_res = atr_res.encode()
        
        tta = nfc.clf.TTA(sens_res=sensa_res, sdd_res=sdd_res, sel_res=sel_res)
        ttf = nfc.clf.TTF(sens_res=sensf_res)
        tta.atr_res = ttf.atr_res = atr_res
        target = nfc.clf.DEP(tta=tta, ttf=ttf)
        if self.acm: target.atr_res = atr_res

        target = self.clf.listen(target, timeout)
        if target and target.atr_req and target.cmd:
            log.debug("activated as " + str(target))
        
            atr_req = ATR_REQ.decode(target.atr_req)
            self.miu = atr_req.lr - 3
            self.did = atr_req.did if atr_req.did > 0 else None
            self.gbi = atr_req.gb
            self.cmd = target.cmd
            self.brm = target.brty
            self.acm = not (target.tta or target.ttf)

            log.info("running as " + str(self))
            return self.gbi
    
    def deactivate(self):
        log.info("stop {0}, packets {1}".format(self, self.stat))

    def exchange(self, send_data, timeout):
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
        
        if self.cmd is not None:
            # first command frame that was received in activate is
            # injected in send_res_recv_req and self.cmd set to None
            assert send_data is None, "send_data should be None on first call"
            req = self.send_dep_res_recv_dep_req(None, deadline)
            self.pni = 0
        else:
            send_data = bytearray(send_data)
            while send_data:
                data = send_data[0:self.miu];
                more = len(send_data) > self.miu
                res = INF(self.pni, data, more, self.did, self.nad)
                req = self.send_dep_res_recv_dep_req(res, deadline)
                self.count.inf_sent += 1
                if req is None: return None
                if more:
                    if req.pfb.type is not DEP_REQ.PositiveAck:
                        error = "expected ACK in NFC-DEP chaining"
                        raise nfc.clf.ProtocolError(error)
                    self.count.ack_rcvd += 1
                self.pni = (self.pni + 1) & 0x3
                if req.pfb.pni != self.pni:
                    raise nfc.clf.ProtocolError("wrong NFC-DEP packet number")
                del send_data[0:self.miu]

        recv_data = bytearray()
        while req.pfb.type == DEP_REQ.MoreInformation:
            recv_data += req.data
            self.count.inf_rcvd += 1
            res = ACK(self.pni, self.did, self.nad)
            req = self.send_dep_res_recv_dep_req(res, deadline)
            self.count.ack_sent += 1
            if req is None: return None
            self.pni = (self.pni + 1) & 0x3
            if req.pfb.pni != self.pni:
                raise nfc.clf.ProtocolError("wrong NFC-DEP packet number")
            
        recv_data += req.data
        self.count.inf_rcvd += 1
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
        if self.cmd is not None:
            # first command frame received in activate
            frame, self.cmd = self.cmd, None
            return self.decode_frame(frame)

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
            error = "first NFC-DEP frame byte must be F0h for 106A"
            raise nfc.clf.ProtocolError(error)
        if len(frame) != frame.pop(0):
            error = "NFC-DEP frame length byte must be data length + 1"
            raise nfc.clf.ProtocolError(error)
        if len(frame) < 2:
            error = "NFC-DEP frame length byte must be from 3 to 255"
            raise nfc.clf.TransmissionError(error)
        if frame[0] != 0xD4 or frame[1] not in (0, 4, 6, 8, 10):
            raise nfc.clf.ProtocolError("invalid NFC-DEP command code")
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
                raise ProtocolError("invalid format of the " + cls.PDU_NAME)

class PSL_REQ(PSL_REQ_RES):
    PDU_CODE = bytearray('\xD4\x04')
    PDU_NAME = 'PSL-REQ'
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
                raise ProtocolError("invalid format of the " + cls.PDU_NAME)
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
    
class DEP_RES(DEP_REQ_RES):
    PDU_CODE = bytearray('\xD5\x07')
    PDU_NAME = 'DEP-RES'
    
class DSL_REQ_RES(object):
    def __init__(self, did):
        self.did = did

    def __str__(self):
        return "{0} DID={1}".format(self.PDU_NAME, self.did)
    
    @classmethod
    def decode(cls, data):
        if data.startswith(cls.PDU_CODE):
            if len(data) > 3:
                raise ProtocolError("invalid format of the " + cls.PDU_NAME)
            return cls(data[2] if len(data) == 3 else None)
        
    def encode(self):
        return self.PDU_CODE + ('' if self.did is None else chr(self.did))
    
class DSL_REQ(DSL_REQ_RES):
    PDU_CODE = bytearray('\xD4\x08')
    PDU_NAME = 'DSL-REQ'
    
class DSL_RES(DSL_REQ_RES):
    PDU_CODE = bytearray('\xD5\x09')
    PDU_NAME = 'DSL-RES'

class RLS_REQ_RES(DSL_REQ_RES):
    pass

class RLS_REQ(RLS_REQ_RES):
    PDU_CODE = bytearray('\xD4\x0A')
    PDU_NAME = 'RLS-REQ'
    
class RLS_RES(RLS_REQ_RES):
    PDU_CODE = bytearray('\xD5\x0B')
    PDU_NAME = 'RLS-RES'

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

