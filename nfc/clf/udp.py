# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
"""Driver module for simulated contactless communication over
UDP/IP. It can be activated with the device path ``udp:<host>:<port>``
where the optional *host* may be the IP address or name of the node
where the targeted communication partner is listening on *port*. The
default values for *host* and *port* are ``localhost:54321``.

The driver implements almost all communication modes, with the current
exception of active communication mode data exchange protocol.

==========  =======  ============
function    support  remarks
==========  =======  ============
sense_tta   yes      
sense_ttb   yes      
sense_ttf   yes
sense_dep   no
listen_tta  yes
listen_ttb  yes
listen_ttf  yes
listen_dep  yes      
==========  =======  ============

"""
import logging
log = logging.getLogger(__name__)

import os
import time
import errno
import socket
import select
import operator
from binascii import hexlify

import nfc.clf

class Device(nfc.clf.device.Device):
    def __init__(self, host, port):
        host, port = socket.getnameinfo((host, port), socket.NI_NUMERICHOST)
        self.addr = (host, int(port))
        self.socket = None
    
    def close(self):
        self.mute()
    
    def mute(self):
        if self.socket:
            # send RFOFF when socket port != listen port
            if self.socket.getsockname()[1] != self.addr[1] and self.rcvd_data:
                self._send_data("RFOFF", "", self.addr)
            self.socket.close()
            self.socket = None

    def sense_tta(self, target):
        if not self.socket: self._create_socket()

        log.debug("sense_tta for %s on %s:%d", target, *self.addr)
        
        if target.brty not in ("106A", "212A", "424A"):
            message = "unsupported bitrate {0}".format(target.brty)
            raise nfc.clf.UnsupportedTargetError(message)

        sens_req = (target.sens_req if target.sens_req else
                    bytearray.fromhex("26"))
        
        log.debug("send SENS_REQ " + hexlify(sens_req))
        try:
            self._send_data(target.brty, sens_req, self.addr)
            brty, sens_res, addr = self._recv_data(1.0, target.brty)
        except nfc.clf.TimeoutError:
            return None
        
        log.debug("rcvd SENS_RES " + hexlify(sens_res))

        if sens_res[0] & 0x1F == 0:
            log.debug("type 1 tag target found")
            target = nfc.clf.RemoteTarget(target.brty, sens_res=sens_res)
            if sens_res[1] & 0x0F == 0b1100:
                rid_cmd = bytearray.fromhex("78 0000 00000000")
                log.debug("send RID_CMD " + hexlify(rid_cmd))
                try:
                    self._send_data(brty, rid_cmd, self.addr)
                    brty, rid_res, addr = self._recv_data(1.0, brty)
                    target.rid_res = rid_res
                except CommunicationError as error:
                    log.debug(error)
                    return None
            return target

        # other than type 1 tag
        try:
            if target.sel_req:
                uid = target.sel_req
                if len(uid) > 4: uid = "\x88" + uid
                if len(uid) > 8: uid = uid[0:4] + "\x88" + uid[4:]
                for i, sel_cmd in zip(range(0,len(uid),4),"\x93\x95\x97"):
                    sel_req = sel_cmd + "\x70" + uid[i:i+4]
                    sel_req.append(reduce(operator.xor, sel_req[2:6])) # BCC
                    log.debug("send SEL_REQ " + hexlify(sel_req))
                    self._send_data(brty, sel_req, addr)
                    brty, sel_res, addr = self._recv_data(0.5, brty)
                    log.debug("rcvd SEL_RES " + hexlify(sel_res))
                uid = target.sel_req
            else:
                uid = bytearray()
                for sel_cmd in "\x93\x95\x97":
                    sdd_req = sel_cmd + "\x20"
                    log.debug("send SDD_REQ " + hexlify(sdd_req))
                    self._send_data(brty, sdd_req, addr)
                    brty, sdd_res, addr = self._recv_data(0.5, brty)
                    log.debug("rcvd SDD_RES " + hexlify(sdd_res))
                    sel_req = sel_cmd + "\x70" + sdd_res
                    log.debug("send SEL_REQ " + hexlify(sel_req))
                    self._send_data(brty, sel_req, addr)
                    brty, sel_res, addr = self._recv_data(0.5, brty)
                    log.debug("rcvd SEL_RES " + hexlify(sel_res))
                    if sel_res[0] & 0b00000100: uid = uid + sdd_res[1:4]
                    else: uid = uid + sdd_res[0:4]; break
            if sel_res[0] & 0b00000100 == 0:
                target = nfc.clf.RemoteTarget(target.brty, _addr=addr)
                target.sens_res = sens_res
                target.sel_res = sel_res
                target.sdd_res = uid
                return target
        except nfc.clf.CommunicationError as error:
            log.debug(error)

    def sense_ttb(self, target):
        if not self.socket: self._create_socket()

        if target.brty not in ("106B", "212B", "424B"):
            message = "unsupported bitrate {0}".format(target.brty)
            raise nfc.clf.UnsupportedTargetError(message)

        sensb_req = (target.sensb_req if target.sensb_req else
                     bytearray.fromhex("050010"))
        
        log.debug("send SENSB_REQ " + hexlify(sensb_req))
        try:
            self._send_data(target.brty, sensb_req, self.addr)
            brty, sensb_res, addr = self._recv_data(1.0, target.brty)
        except nfc.clf.TimeoutError:
            return None
        
        if len(sensb_res) >= 12 and sensb_res[0] == 0x50:
            log.debug("rcvd SENSB_RES " + hexlify(sensb_res))
            return nfc.clf.RemoteTarget(brty, sensb_res=sensb_res, _addr=addr)

    def sense_ttf(self, target):
        if not self.socket: self._create_socket()

        log.debug("sense_ttf for %s on %s:%d", target, *self.addr)

        if target.brty not in ("212F", "424F"):
            message = "unsupported bitrate {0}".format(target.brty)
            raise nfc.clf.UnsupportedTargetError(message)

        if not target.sensf_req: sensf_req = bytearray.fromhex("0600FFFF0100")
        else: sensf_req = chr(len(target.sensf_req)+1) + target.sensf_req

        log.debug("send SENSF_REQ " + hexlify(buffer(sensf_req, 1)))
        try:
            self._send_data(target.brty, sensf_req, self.addr)
            brty, data, addr = self._recv_data(1.0, target.brty)
        except nfc.clf.TimeoutError:
            return None

        if len(data) >= 18 and data[0] == len(data) and data[1] == 1:
            log.debug("rcvd SENSF_RES " + hexlify(data[1:]))
            return nfc.clf.RemoteTarget(brty, sensf_res=data[1:], _addr=addr)

    def sense_dep(self, target):
        info = "{device} does not support sense for active DEP Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))
    
    def listen_tta(self, target, timeout):
        if not self.socket: self._create_socket()

        log.debug("listen_tta for %.3f seconds on %s:%d", timeout, *self.addr)
        
        time_to_return = time.time() + timeout
        if not self._bind_socket(time_to_return):
            log.debug("failed to bind socket")
            return None
        
        log.debug("wait for data on socket %s:%d", *self.socket.getsockname())
        return self._listen_tta(target, time_to_return)

    def _listen_tta(self, target, time_to_return, init=None):
        sdd_res = bytearray(target.sdd_res)
        if len(sdd_res) > 4: sdd_res.insert(0, 0x88)
        if len(sdd_res) > 8: sdd_res.insert(4, 0x88)
        sdd_res.insert(4, reduce(operator.xor, sdd_res[0:4]))
        if len(sdd_res) > 5:
            sdd_res.insert(9, reduce(operator.xor, sdd_res[5:9]))
        if len(sdd_res) > 10:
            sdd_res.insert(14, reduce(operator.xor, sdd_res[10:14]))
        sel_res = bytearray([target.sel_res[0] & 0b11111011])

        while time.time() < time_to_return:
            if init is None:
                wait = max(0.5, time_to_return - time.time())
                try: brty, data, addr = self._recv_data(wait, target.brty)
                except nfc.clf.TimeoutError: return None
            else:
                (brty, data, addr), init = init, None
            if data == "\x26":
                log.debug("rcvd SENS_REQ %s", hexlify(data))
                sens_res = target.sens_res
                log.debug("send SENS_RES %s", hexlify(sens_res))
                self._send_data(brty, sens_res, addr)
            elif data == "\x93\x20":
                log.debug("rcvd SDD_REQ CL1 %s", hexlify(data))
                log.debug("send SDD_RES CL1 %s", hexlify(sdd_res[0:5]))
                self._send_data(brty, sdd_res[0:5], addr)
            elif data == "\x95\x20" and len(sdd_res) > 5:
                log.debug("rcvd SDD_REQ CL2 %s", hexlify(data))
                log.debug("send SDD_RES CL2 %s", hexlify(sdd_res[5:10]))
                self._send_data(brty, sdd_res[5:10], addr)
            elif data == "\x97\x20" and len(sdd_res) > 10:
                log.debug("rcvd SDD_REQ CL3 %s", hexlify(data))
                log.debug("send SDD_RES CL3 %s", hexlify(sdd_res[10:15]))
                self._send_data(brty, sdd_res[10:15], addr)
            elif data == "\x93\x70" + sdd_res[0:5]:
                log.debug("rcvd SEL_REQ Cl1 %s", hexlify(data))
                sel_res[0] = (sel_res[0] & 0b11111011) | (len(sdd_res)>5)<<2
                log.debug("send SEL_RES %s", hexlify(sel_res))
                self._send_data(brty, sel_res, addr)
            elif data == "\x95\x70" + sdd_res[5:10]:
                log.debug("rcvd SEL_REQ CL2 %s", hexlify(data))
                sel_res[0] = (sel_res[0] & 0b11111011) | (len(sdd_res)>10)<<2
                log.debug("send SEL_RES %s", hexlify(sel_res))
                self._send_data(brty, sel_res, addr)
            elif data == "\x95\x70" + sdd_res[10:15]:
                log.debug("rcvd SEL_REQ CL3 %s", hexlify(data))
                sel_res[0] = (sel_res[0] & 0b11111011)
                log.debug("send SEL_RES %s", hexlify(sel_res))
                self._send_data(brty, sel_res, addr)
            elif sel_res[0] & 0b00000100 == 0:
                target = nfc.clf.LocalTarget(
                    brty, _addr=addr, sens_res=target.sens_res,
                    sdd_res=target.sdd_res, sel_res=target.sel_res)
                if (data[0] == 0xF0 and len(data) >= 18 and
                    data[1] == len(data)-1 and data[2:4] == "\xD4\x00"):
                    target.atr_req = data[2:]
                elif data[0]==0xE0:
                    target.tt4_cmd = data[:]
                else:
                    target.tt2_cmd = data[:]
                return target
    
    def listen_ttb(self, target, timeout):
        if not self.socket: self._create_socket()

        log.debug("listen_ttb for %.3f seconds on %s:%d", timeout, *self.addr)
        
        time_to_return = time.time() + timeout
        if not self._bind_socket(time_to_return):
            log.debug("failed to bind socket")
            return None

        assert target.sensb_res and len(target.sensb_res) >= 12
        log.debug("wait for data on socket %s:%d", *self.socket.getsockname())
        
        while time.time() < time_to_return:
            wait = max(0.5, time_to_return - time.time())
            try: brty, data, addr = self._recv_data(wait, target.brty)
            except nfc.clf.TimeoutError: return None
            if data and len(data) == 3 and data.startswith('\x05'):
                req = "ALLB_REQ" if data[1] & 0x08 else "SENSB_REQ"
                sensb_req = data
                log.debug("rcvd %s %s", req, hexlify(sensb_req))
                log.debug("send SENSB_RES %s", hexlify(target.sensb_res))
                self._send_data(brty, target.sensb_res, addr)
                brty, data, addr = self._recv_data(wait, target.brty)
                return nfc.clf.LocalTarget(brty, sensb_req=sensb_req,
                                           sensb_res=target.sensb_res, 
                                           tt4_cmd=data, _addr=addr)
        
    def listen_ttf(self, target, timeout):
        if not self.socket: self._create_socket()

        log.debug("listen_ttf for %.3f seconds on %s:%d", timeout, *self.addr)
        
        time_to_return = time.time() + timeout
        if not self._bind_socket(time_to_return):
            log.debug("failed to bind socket")
            return None
        
        log.debug("wait for data on socket %s:%d", *self.socket.getsockname())
        return self._listen_ttf(target, time_to_return)
        
    def _listen_ttf(self, target, time_to_return, init=None):
        sensf_req = sensf_res = None
        while time.time() < time_to_return:
            if init is None:
                wait = max(0.5, time_to_return - time.time())
                try: brty, data, addr = self._recv_data(wait, target.brty)
                except nfc.clf.TimeoutError: return None
            else:
                (brty, data, addr), init = init, None
            if data and len(data) == data[0]:
                if data.startswith("\x06\x00"):
                    (sensf_req, sensf_res) = (data[1:], target.sensf_res[:])
                    if ((sensf_req[1]==255 or sensf_req[1]==sensf_res[17]) and
                        (sensf_req[2]==255 or sensf_req[2]==sensf_res[18])):
                        data = sensf_res[0:17]
                        if sensf_req[3] == 1:
                            data += sensf_res[17:19]
                        if sensf_req[3] == 2:
                            data += "\x00" + chr(1<<(target.brty=="424F"))
                        data = chr(len(data)+1) + data
                        self._send_data(brty, data, addr)
                elif sensf_req and sensf_res:
                    if data[2:10] == target.sensf_res[1:9]:
                        target = nfc.clf.LocalTarget(brty, _addr=addr)
                        target.sensf_req = sensf_req
                        target.sensf_res = sensf_res
                        target.tt3_cmd = data[1:]
                        return target
                    if data[1:11] == '\xD4\x00'+target.sensf_res[1:9]:
                        target = nfc.clf.LocalTarget(brty, _addr=addr)
                        target.sensf_req = sensf_req
                        target.sensf_res = sensf_res
                        target.atr_req = data[1:]
                        return target
        
    def listen_dep(self, target, timeout):
        if not self.socket: self._create_socket()

        log.debug("listen_dep for %.3f seconds on %s:%d", timeout, *self.addr)
        assert target.sensf_res is not None
        assert target.sens_res is not None
        assert target.sdd_res is not None
        assert target.sel_res is not None
        assert target.atr_res is not None
        assert len(target.sensf_res) == 19
        assert len(target.sens_res) == 2
        assert len(target.sdd_res) == 4
        assert len(target.sel_res) == 1
        assert len(target.atr_res) >= 17 and len(target.atr_res) <= 64

        time_to_return = time.time() + timeout
        if not self._bind_socket(time_to_return):
            log.debug("failed to bind socket")
            return None
        
        log.debug("wait for data on socket %s:%d", *self.socket.getsockname())
        atr_res = bytearray(target.atr_res)
        
        while time.time() < time_to_return:
            wait = max(0.5, time_to_return - time.time())
            try:
                brty, data, addr = self._recv_data(wait, '106A','212F','424F')
            except nfc.clf.CommunicationError:
                return None

            target.brty = brty
            if brty == '106A':
                if data == "\x26":
                    init = (brty, data, addr)
                    target = self._listen_tta(target, time_to_return, init)
                elif len(data) >= 18 and data[1] == len(data)-1:
                    if data[0] == 0xF0 and data[2:4] == '\xD4\x00':
                        target = nfc.clf.LocalTarget(
                            brty, atr_res=target.atr_res, atr_req=data[2:])
            elif brty in ('212F','424F') and data[0] == len(data):
                if data.startswith('\x06\x00'):
                    init = (brty, data, addr)
                    target = self._listen_ttf(target, time_to_return, init)
                elif len(data) >= 17 and data[1:3] == '\xD4\x00':
                    target = nfc.clf.LocalTarget(
                        brty, atr_res=target.atr_res, atr_req=data[1:])

            if target.atr_req:
                target.atr_res = atr_res
                log.debug("rcvd ATR_REQ %s", hexlify(target.atr_req))
                log.debug("send ATR_RES %s", hexlify(target.atr_res))
                data = chr(len(atr_res) + 1) + atr_res
                if brty == '106A': data.insert(0, 0xF0)
                self._send_data(brty, data, addr)
                brty, data, addr = self._recv_data(wait, brty)
                try:
                    if brty == '106A': assert data.pop(0) == 0xF0
                    assert len(data) == data.pop(0)
                except AssertionError: return None
                if data.startswith('\xD4\x04'):
                    target.psl_req = data[:]
                    target.psl_res = '\xD5\x05' + target.psl_req[2:3]
                    log.debug("rcvd PSL_REQ %s", hexlify(target.psl_req))
                    log.debug("send PSL_RES %s", hexlify(target.psl_res))
                    data = chr(len(target.psl_res) + 1) + target.psl_res
                    if brty == '106A': data.insert(0, 0xF0)
                    self._send_data(brty, data, addr)
                    brty = ('106A','212F','424F')[target.psl_req[3]>>3&7]
                    target.brty, data, addr = self._recv_data(wait, brty)
                    try:
                        if brty == '106A': assert data.pop(0) == 0xF0
                        assert len(data) == data.pop(0)
                    except AssertionError: return None
                if data.startswith('\xD4\x08'):
                    log.debug("rcvd DSL_REQ %s", hexlify(data))
                    data = '\xD5\x09' + data[2:3]
                    log.debug("send DSL_RES %s", hexlify(data))
                    data = chr(len(data) + 1) + data
                    if brty == '106A': data.insert(0, 0xF0)
                    self._send_data(brty, data, addr)
                    return None
                if data.startswith('\xD4\x0A'):
                    log.debug("rcvd RLS_REQ %s", hexlify(data))
                    data = '\xD5\x0B' + data[2:3]
                    log.debug("send RLS_RES %s", hexlify(data))
                    data = chr(len(data) + 1) + data
                    if brty == '106A': data.insert(0, 0xF0)
                    self._send_data(brty, data, addr)
                    return None
                if data.startswith('\xD4\x06'):
                    target.dep_req = data[:]
                    return target
        
    def send_cmd_recv_rsp(self, target, data, timeout):
        # send data, data should normally not be None for the Initiator
        if data is not None:
            self._send_data(target.brty, data, target._addr)
        
        # receive response data unless the timeout is zero
        if timeout > 0:
            brty, data, addr = self._recv_data(timeout, target.brty)
            if not data: raise nfc.clf.BrokenLinkError("no data received")
            return data

    def send_rsp_recv_cmd(self, target, data, timeout):
        # send data, data may be none as target keeps silence on error
        if data is not None:
            self._send_data(target.brty, data, target._addr)
            
        # recv response data unless the timeout is zero
        if timeout is None or timeout > 0:
            brty, data, addr = self._recv_data(timeout, target.brty)
            return data

    def get_max_send_data_size(self, target):
        return 290

    def get_max_recv_data_size(self, target):
        return 290

    def _create_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sent_data = self.rcvd_data = 0
    
    def _bind_socket(self, time_to_return):
        addr = ('0.0.0.0', self.addr[1])
        while time.time() < time_to_return:
            log.debug("trying to bind socket to %s:%d", *addr)
            try:
                self.socket.bind(addr)
                return True
            except socket.error as error:
                log.debug("bind failed with %s", error)
                if error.errno == errno.EADDRINUSE: return False
                else: raise error

    def _send_data(self, brty, data, addr):
        data = ("%s %s" % (brty, str(data).encode("hex"))).strip()
        log.log(logging.DEBUG-1, ">>> %s to %s:%d", data, *addr)
        if self.socket.sendto(data, addr) != len(data):
            raise nfc.clf.TransmissionError("failed to send data")
        self.sent_data += len(data)

    def _recv_data(self, timeout, *brty_list):
        time_to_return = None if timeout is None else (time.time() + timeout)
        while timeout is None or time.time() < time_to_return:
            wait = None if timeout is None else (time_to_return - time.time())
            if len(select.select([self.socket], [], [], wait)[0]) == 1:
                data, addr = self.socket.recvfrom(1024)
                log.log(logging.DEBUG-1, "<<< %s from %s:%d", data, *addr)
                if data.startswith("RFOFF"):
                    raise nfc.clf.BrokenLinkError("RFOFF")
                brty, data = data.split()
                data = bytearray.fromhex(data)
                self.rcvd_data += len(data)
                if brty in brty_list:
                    return (brty, data, addr)
        raise nfc.clf.TimeoutError("no data received")
        
def init(host, port):
    import platform
    device = Device(host, port)
    device._vendor_name = platform.uname()[0]
    device._device_name = "IP-Stack"
    device._chipset_name = "UDP"
    return device

