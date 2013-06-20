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
from nfc.clf import TTA, TTB, TTF
import nfc.dev

from struct import pack, unpack
import os
import time
import socket
import select

class Device(nfc.dev.Device):
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addr = (host, port)
    
    def close(self):
        self.socket.close()
    
    def sense(self, targets):
        for tg in targets:
            if type(tg) == TTA:
                target = self.sense_a()
                if (target and
                    (tg.cfg is None or target.cfg.startswith(tg.cfg)) and
                    (tg.uid is None or target.uid.startswith(tg.uid))):
                    break
            elif type(tg) == TTB:
                target = self.sense_b()
                if target:
                    pass
            elif type(tg) == TTF:
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
        cmd = bytearray.fromhex(cmd)

        self.socket.sendto(cmd, self.addr)
        if len(select.select([self.socket], [], [], 1.0)[0]) == 1:
            data, addr = self.socket.recvfrom(1024)
            log.debug("{0} {1}".format(data.encode("hex"), addr))
            rsp = bytearray(data)
            if len(rsp) >= 18 and rsp[0] == len(rsp) and rsp[1] == 1:
                if len(rsp) == 18: rsp += "\xff\xff"
                idm, pmm, sys = rsp[2:10], rsp[10:18], rsp[18:20]
                return TTF(br=br, idm=idm, pmm=pmm, sys=sys)
    
    def listen(self, targets, timeout):
        """Listen for multiple targets. This hardware supports
        listening for Type A and Type F activation."""
        
        if not targets:
            return None

        nfca_params = bytearray.fromhex("FFFF000000FF")
        nfcf_params = bytearray(18) # all zero
        nfca_target = None
        nfcf_target = None
        
        for target in targets:
            if type(target) == TTA:
                nfca_params = target.cfg[0:2] + target.uid[1:] + target.cfg[2:]
                nfca_target = target
            if type(target) == TTF:
                nfcf_params = target.idm + target.pmm + target.sys
                nfcf_target = target
            
        assert len(nfca_params) == 6
        assert len(nfcf_params) == 18
        
        log.debug("bind socket to {0}".format(self.addr))
        try: self.socket.bind(self.addr)
        except socket.error: return
        log.debug("bound socket to {0}".format(self.addr))

        data = ""
        while not data.startswith("\x06\x00"):
            data, self.addr = self.socket.recvfrom(1024)
            log.debug("<< {0} {1}".format(data.encode("hex"), self.addr))

        data = ("\x12\x01" + target.idm + target.pmm
                + (target.sys if data[4] == 1 else ''))
        log.debug(">> {0} {1}".format(str(data).encode("hex"), self.addr))
        self.socket.sendto(data, self.addr)
        if len(select.select([self.socket], [], [], 0.1)[0]) == 1:
            data, self.addr = self.socket.recvfrom(1024)
            log.debug("<< {0} {1}".format(data.encode("hex"), self.addr))

            target = TTF(424, *nfcf_target[1:])
            self.exchange = self.send_rsp_recv_cmd
            return target, bytearray(data)

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
                return bytearray(data)
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
                return bytearray(data)
            else: log.debug("TimeoutError"); raise TimeoutError

    def set_communication_mode(self, brm, **kwargs):
        pass

def init(host, port):
    device = Device(host, port)
    device._vendor = os.uname()[0]
    device._product = "TCP/IP"
    return device

