# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
#
# udp.py - NFC link simulation over UDP
#

import logging
log = logging.getLogger(__name__)

from nfc.clf import ProtocolError, TransmissionError, TimeoutError
import nfc.clf
import nfc.dev

import os
import time
import socket
import select

class Device(nfc.dev.Device):
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addr = (host, port)
    
    def close(self):
        try:
            if self.exchange == self.send_cmd_recv_rsp:
                self.socket.sendto("", self.addr)
        except AttributeError: pass
        self.socket.close()
    
    @property
    def capabilities(self):
        return {}

    def sense(self, targets):
        for tg in targets:
            if type(tg) == nfc.clf.TTA:
                target = self.sense_a()
                if (target and
                    (tg.cfg is None or target.cfg.startswith(tg.cfg)) and
                    (tg.uid is None or target.uid.startswith(tg.uid))):
                    break
            elif type(tg) == nfc.clf.TTB:
                target = self.sense_b()
                if target:
                    pass
            elif type(tg) == nfc.clf.TTF:
                br, sc, rc = tg.br, tg.sys, 0
                if sc is None: sc, rc = bytearray('\xFF\xFF'), 1
                target = self.sense_f(br, sc, rc)
                if (target and
                    (tg.sys is None or target.sys == tg.sys) and
                    (tg.idm is None or target.idm.startswith(tg.idm)) and
                    (tg.pmm is None or target.pmm.startswith(tg.pmm))):
                    break
        else:
            return None
        
        self.exchange = self.send_cmd_recv_rsp
        return target

    def sense_a(self):
        return None
    
    def sense_b(self):
        return None

    def sense_f(self, br, sc, rc):
        cmd = "0600{sc[0]:02x}{sc[1]:02x}{rc:02x}03".format(sc=sc, rc=rc)
        log.debug("poll NFC-F {0} to {1}".format(cmd, self.addr))
        cmd = bytearray(cmd.decode("hex"))

        self.socket.sendto(cmd, self.addr)
        if len(select.select([self.socket], [], [], 1.0)[0]) == 1:
            data, addr = self.socket.recvfrom(1024)
            log.debug("{0} {1}".format(data.encode("hex"), addr))
            rsp = bytearray(data)
            if len(rsp) >= 18 and rsp[0] == len(rsp) and rsp[1] == 1:
                if len(rsp) == 18: rsp += "\xff\xff"
                idm, pmm, sys = rsp[2:10], rsp[10:18], rsp[18:20]
                return nfc.clf.TTF(br=br, idm=idm, pmm=pmm, sys=sys)
    
    def listen_ttf(self, target, timeout):
        assert type(target) is nfc.clf.TTF
        
        if target.br is None:
            target.br = 212
            
        log.debug("bind socket to {0}".format(self.addr))
        try: self.socket.bind(self.addr)
        except socket.error: return
        log.debug("bound socket to {0}".format(self.addr))

        while True:
            data, self.addr = self.socket.recvfrom(1024)
            log.debug("<< {0} {1}".format(data.encode("hex"), self.addr))
            if data.startswith("\x06\x00"): break
            
        while True:
            cmd = bytearray(data)
            if cmd.startswith("\x06\x00"):
                rsp = "\x01" + target.idm + target.pmm
                if cmd[4] == 1: rsp += target.sys
                data = str(chr(len(rsp) + 1) + rsp)
                log.debug(">> {0} {1}".format(data.encode("hex"), self.addr))
                self.socket.sendto(data, self.addr)
            else: break
            if len(select.select([self.socket], [], [], 0.1)[0]) == 1:
                data, self.addr = self.socket.recvfrom(1024)
                log.debug("<< {0} {1}".format(data.encode("hex"), self.addr))
            else: return None

        self.exchange = self.send_rsp_recv_cmd
        return target, cmd
        
    def listen_dep(self, target, timeout):
        assert type(target) is nfc.clf.DEP

        target.br = 424
        target.idm = bytearray((0x01, 0xFE)) + os.urandom(6)
        target.pmm = bytearray(8)
        target.sys = bytearray((0xFF, 0xFF))

        log.debug("bind socket to {0}".format(self.addr))
        try: self.socket.bind(self.addr)
        except socket.error: return
        log.debug("bound socket to {0}".format(self.addr))

        while True:
            data, self.addr = self.socket.recvfrom(1024)
            log.debug("<< {0} {1}".format(data.encode("hex"), self.addr))
            if data.startswith("\x06\x00"): break
            
        while True:
            cmd = bytearray(data)
            if cmd.startswith("\x06\x00"):
                rsp = "\x01" + target.idm + target.pmm
                if cmd[4] == 1: rsp += target.sys
                data = str(chr(len(rsp) + 1) + rsp)
                log.debug(">> {0} {1}".format(data.encode("hex"), self.addr))
                self.socket.sendto(data, self.addr)
            else: break
            if len(select.select([self.socket], [], [], 0.1)[0]) == 1:
                data, self.addr = self.socket.recvfrom(1024)
                log.debug("<< {0} {1}".format(data.encode("hex"), self.addr))
            else: return None

        self.exchange = self.send_rsp_recv_cmd
        return target, cmd
        
    def send_cmd_recv_rsp(self, data, timeout):
        log.debug("send_cmd_recv_rsp with timeout {0} sec".format(timeout))

        # trash data if any, as on nfc we only recv future data
        rfd, wfd, xfd = select.select([self.socket], [], [], 0)
        if rfd and rfd[0] == self.socket:
            self.socket.recvfrom(1024)
        
        # send data, data should normally not be none for initiator
        if data is not None:
            log.debug(">> {0}".format(str(data).encode("hex")))
            self.socket.sendto(data, self.addr)
        
        # recv response data unless the timeout is zero
        if timeout > 0:
            rfd, wfd, xfd = select.select([self.socket], [], [], timeout)
            if rfd and rfd[0] == self.socket:
                data, self.addr = self.socket.recvfrom(1024)
                log.debug("<< {0}".format(data.encode("hex")))
                return bytearray(data) if len(data) else None
            else: log.debug("TimeoutError"); raise TimeoutError

    def send_rsp_recv_cmd(self, data, timeout):
        log.debug("send_rsp_recv_cmd with timeout {0} sec".format(timeout))
        
        # trash data if any, as on nfc we only recv future data
        rfd, wfd, xfd = select.select([self.socket], [], [], 0)
        if rfd and rfd[0] == self.socket:
            self.socket.recvfrom(1024)
        
        # send data, data may be none as target keeps silence on error
        if data is not None:
            log.debug(">> {0}".format(str(data).encode("hex")))
            self.socket.sendto(data, self.addr)
            
        # recv response data unless the timeout is zero
        if timeout > 0:
            rfd, wfd, xfd = select.select([self.socket], [], [], timeout)
            if rfd and rfd[0] == self.socket:
                data, self.addr = self.socket.recvfrom(1024)
                log.debug("<< {0}".format(data.encode("hex")))
                return bytearray(data) if len(data) else None
            else: log.debug("TimeoutError"); raise TimeoutError

    def set_communication_mode(self, brm, **kwargs):
        pass

def init(host, port):
    device = Device(host, port)
    import platform
    device._vendor_name = platform.uname()[0]
    device._device_name = "UDP/IP"
    return device

