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
#
# Simple NDEF Exchange Protocol (SNEP) - Client Base Class
#
import logging
log = logging.getLogger(__name__)

import struct
import nfc.llcp

def send_request(llc, socket, snep_request, send_miu):
    if len(snep_request) <= send_miu:
        return llc.send(socket, snep_request)
    else:
        if llc.send(socket, snep_request[0:send_miu]):
            if llc.recv(socket) == "\x10\x80\x00\x00\x00\x00":
                for offset in xrange(send_miu, len(snep_request), send_miu):
                    fragment = snep_request[offset:offset+send_miu]
                    if not llc.send(socket, fragment): break
                else: return True

def recv_response(llc, socket, acceptable_length, timeout):
    if llc.poll(socket, "recv", timeout):
        snep_response = llc.recv(socket)
        if len(snep_response) < 6:
            log.debug("snep response initial fragment too short")
            return None
        version, status, length = struct.unpack(">BBL", snep_response[:6])
        if length > acceptable_length:
            log.debug("snep response exceeds acceptable length")
            return None
        if len(snep_response) - 6 < length:
            # request remaining fragments
            llc.send(socket, "\x10\x00\x00\x00\x00\x00")
            while len(snep_response) - 6 < length:
                if llc.poll(socket, "recv", timeout):
                    snep_response += llc.recv(socket)
                else: return None                
        return snep_response

class SnepClient(object):
    """ Simple NDEF exchange protocol - client implementation
    """
    def __init__(self, llc, max_ndef_msg_recv_size=1024):
        self.acceptable_length = max_ndef_msg_recv_size
        self.socket = None
        self.llc = llc

    def connect(self, service_name):
        if self.socket: self.close()
        self.socket = self.llc.socket(nfc.llcp.DATA_LINK_CONNECTION)
        self.llc.connect(self.socket, service_name)
        self.send_miu = self.llc.getsockopt(self.socket, nfc.llcp.SO_SNDMIU)

    def close(self):
        if self.socket:
            self.llc.close(self.socket)
            self.socket = None

    def get(self, ndef_message='', timeout=1.0):
        """Get an NDEF message from the server. Temporarily connects
        to the default SNEP server if the client is not yet connected.
        """
        if not self.socket:
            self.connect('urn:nfc:sn:snep')
            self.release_connection = True
        else:
            self.release_connection = False
        llc, socket = self.llc, self.socket
        try:
            snep_request = '\x10\x01'
            snep_request += struct.pack('>L', 4 + len(ndef_message))
            snep_request += struct.pack('>L', self.acceptable_length)
            snep_request += ndef_message
            if send_request(llc, socket, snep_request, self.send_miu):
                snep_response = recv_response(
                    llc, socket, self.acceptable_length, timeout)
                if snep_response is not None:
                    response_code = ord(snep_response[1])
                    if response_code != 0x81:
                        raise SnepError(response_code)
                    return snep_response[6:]
        finally:
            if self.release_connection:
                self.close()

    def put(self, ndef_message, timeout=1.0):
        """Send an NDEF message to the server. Temporarily connects to
        the default SNEP server if the client is not yet connected.
        """
        if not self.socket:
            self.connect('urn:nfc:sn:snep')
            self.release_connection = True
        else:
            self.release_connection = False
        llc, socket = self.llc, self.socket
        try:
            ndef_msgsize = struct.pack('>L', len(ndef_message))
            snep_request = '\x10\x02' + ndef_msgsize + ndef_message
            if send_request(llc, socket, snep_request, self.send_miu):
                snep_response = recv_response(llc, socket, 0, timeout)
                if snep_response is not None:
                    response_code = ord(snep_response[1])
                    if response_code != 0x81:
                        raise SnepError(response_code)
        finally:
            if self.release_connection:
                self.close()

class SnepError(Exception):
    strerr = {0xC0: "resource not found",
              0xC1: "resource exceeds data size limit",
              0xC2: "malformed request not understood",
              0xE0: "unsupported functionality requested",
              0xE1: "unsupported protocol version"}

    def __init__(self, err):
        self.args = (err, SnepError.strerr.get(err, ""))

    def __str__(self):
        return "nfc.snep.SnepError: [{errno}] {info}".format(
            errno=self.args[0], info=self.args[1])

    @property
    def errno(self):
        return self.args[0]
