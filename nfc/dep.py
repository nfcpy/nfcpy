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

import time

class DEP(object):
    def __init__(self, clf, general_bytes, role):
        self.clf = clf
        self._gb = general_bytes
        self._role = role

    @property
    def general_bytes(self):
        """The general bytes received with the ATR exchange"""
        return self._gb

    @property
    def role(self):
        """Role in DEP communication, either 'Target' or 'Initiator'"""
        return self._role

class DEPInitiator(DEP):
    def __init__(self, clf, general_bytes, response_waiting_time):
        DEP.__init__(self, clf, general_bytes, "Initiator")
        self.rwt = response_waiting_time
        self.miu = 251
        self.pni = 0

    def exchange(self, data, timeout):
        t0 = time.time()
        log.debug("send {0} byte dep cmd".format(len(data)))
        self.send_command(data)
        data = self.recv_response(timeout)
        elapsed = int((time.time() - t0) * 1000)
        log.debug("rcvd {0} byte dep rsp in {0} ms".format(len(data), elapsed))
        return data

    def send_command(self, data):
        """Send a data exchange protocol command.
        """
        log.debug("dep raw >> " + str(data).encode("hex"))
        data = bytearray(data)
        try:
            for i in range(0, len(data), self.miu):
                more = len(data) - i * self.miu > self.miu
                self._send_information(data[i:i+self.miu], more)
                if more: self._recv_acknowledge(self.rwt)
            return True
        except IOError as error:
            log.error(error)
            raise
            
    def recv_response(self, timeout):
        """Receive a data exchange protocol response.
        """
        log.debug("rwt is {0} ms".format(int(self.rwt * 1000)))
        try:
            data, more = self._recv_information(timeout)
            while more:
                self._send_acknowledge()
                fragment, more = self._recv_information(timeout)
                data += fragment
        except IOError as error:
            log.error(error)
            raise
        log.debug("dep raw << " + str(data).encode("hex"))
        return str(data)

    def _recv_information(self, timeout):
        pfb, data = self._recv_pdu(timeout)
        while pfb & 0xf3 == 0b10010000: # RTOX REQ
            log.warning("dep rtox req is not compliant with llcp")
            self._send_rtox_rsp(data[0])
            pfb, data = self._recv_pdu(timeout)
        if pfb & 0b11100000 != 0:
            raise IOError("dep inf pdu type error")
        if pfb & 0b00000011 != self.pni:
            raise IOError("dep inf pdu seq error")
        self.pni = (self.pni + 1) % 4
        return data, bool(pfb & 0b00010000)

    def _recv_acknowledge(self, timeout):
        """returns true for an ack and false for a nack"""
        pfb, data = self._recv_pdu(timeout)
        while pfb & 0xf3 == 0b10010000: # RTOX REQ
            log.warning("dep rtox req is not compliant with llcp")
            self._send_rtox_rsp(data[0])
            pfb, data = self._recv_pdu(timeout)
        if pfb & 0b11100000 != 0b01000000:
            raise IOError("dep ack pdu type error")
        if pfb & 0b00000011 != self.pni:
            raise IOError("dep ack pdu seq error")
        self.pni = (self.pni + 1)  % 4
        return pfb & 0b00010000 == 0
    
    def _recv_pdu(self, timeout):
        pdu = self.clf.dev.recv_response(timeout)
        if pdu is None or len(pdu) == 0:
            raise IOError("dep pdu receive error")
        if pdu[0] != len(pdu) or pdu[0] < 4:
            raise IOError("dep pdu length error")
        if pdu[1] != 0xd5 or pdu[2] != 0x07:
            raise IOError("dep pdu format error")
        if pdu[3] & 0b00001100 != 0:
            raise IOError("dep pdu did/nad error")
        return pdu[3], pdu[4:]
    
    def _send_information(self, data, more):
        pfb = 0b00000000 | int(more) << 4 | self.pni
        cmd = bytearray([4+len(data), 0xd4, 0x06, pfb]) + data
        self.clf.dev.send_command(cmd)

    def _send_acknowledge(self, nack=False):
        pfb = 0b01000000 | int(nack) << 4 | self.pni
        cmd = bytearray([4, 0xd4, 0x06, pfb])
        self.clf.dev.send_command(cmd)

    def _send_attention(self):
        cmd = bytearray([4, 0xd4, 0x06, 0b10000000])
        self.clf.dev.send_command(cmd)

    def _send_rtox_rsp(self, rtox):
        cmd = bytearray([5, 0xd4, 0x06, 0b10010000, rtox])
        self.clf.dev.send_command(cmd)

class DEPTarget(DEP):
    def __init__(self, clf, general_bytes):
        DEP.__init__(self, clf, general_bytes, "Target")

    @property
    def response_waiting_time(self):
        return self._dev.rwt

    def wait_command(self, timeout):
        """Receive an NFCIP-1 DEP command. If a command is received within
        *timeout* milliseconds the data portion is returned as a byte 
        string, otherwise an IOError exception is raised."""
        
        log.debug("wait up to {0} ms for a dep command".format(timeout))
        t0 = time.time()
        data = self._dev.dep_get_data(timeout)
        elapsed = int((time.time() - t0) * 1000)
        log.debug("dep raw << " + str(data).encode("hex"))
        log.debug("rcvd {0} byte cmd after {0} ms".format(len(data), elapsed))
        return data

    def send_response(self, data, timeout):
        """Send an NFCIP-1 DEP response with the byte string *data* as
        the payload."""
        
        log.debug("send {0} byte dep rsp in {1} ms".format(len(data), timeout))
        log.debug("dep raw >> " + str(data).encode("hex"))
        t0 = time.time()
        self._dev.dep_set_data(data, timeout)
        elapsed = int((time.time() - t0) * 1000)
        log.debug("sent {0} byte dep rsp in {0} ms".format(len(data), elapsed))

