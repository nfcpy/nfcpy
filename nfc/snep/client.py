# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
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

import struct
import nfc.llcp

def send_request(socket, snep_request, send_miu):
    if len(snep_request) <= send_miu:
        nfc.llcp.send(socket, snep_request)
    else:
        nfc.llcp.send(socket, snep_request[0:send_miu])
        if nfc.llcp.recv(socket) == "\x10\x80\x00\x00\x00\x00":
            for offset in xrange(send_miu, len(snep_request), send_miu):
                fragment = snep_request[offset:offset+send_miu]
                nfc.llcp.send(socket, fragment)

def recv_response(socket, acceptable_length, timeout):
    if nfc.llcp.poll(socket, "recv", timeout):
        snep_response = nfc.llcp.recv(socket)
        if len(snep_response) < 6:
            log.debug("snep response initial fragment too short")
            return None
        version, status, length = struct.unpack(">BBL", snep_response[:6])
        if length > acceptable_length:
            log.debug("snep response exceeds acceptable length")
            return None
        # get remaining fragments, if any
        while len(snep_response) - 6 < length:
            if nfc.llcp.poll(socket, "recv", timeout):
                snep_response += nfc.llcp.recv(socket)
            else: return None
        return snep_response

class SnepClient(object):
    """
    """
    def __init__(self):
        self.socket = None
        self.acceptable_length = 1024

    def connect(self, service_name):
        if self.socket: self.close()
        self.socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        nfc.llcp.connect(self.socket, service_name)
        self.send_miu = nfc.llcp.getsockopt(self.socket, nfc.llcp.SO_SNDMIU)

    def close(self):
        if self.socket:
            nfc.llcp.close(self.socket)
            self.socket = None

    def get(self, ndef_message = ''):
        if not self.socket:
            self.connect('urn:nfc:sn:snep')
        snep_request = '\x10\x01'
        snep_request += struct.pack('>L', 4 + len(ndef_message))
        snep_request += struct.pack('>L', self.acceptable_length)
        snep_request += ndef_message
        if send_request(self.socket, snep_request, self.send_miu):
            snep_response = recv_response(self.socket, self.acceptable_length)
            response_code = ord(snep_response[1])
            if response_code != 0x81:
                raise SnepError(response_code)
            return snep_response[6:]

    def put(self, ndef_message):
        if not self.socket:
            self.connect('urn:nfc:sn:snep')
        ndef_msgsize = struct.pack('>L', len(ndef_message))
        snep_request = '\x10\x02' + ndef_msgsize + ndef_message
        if send_request(self.socket, snep_request, self.send_miu):
            snep_response = recv_response(self.socket, 0)
            response_code = ord(snep_response[1])
            if response_code != 0x81:
                raise SnepError(response_code)

class SnepError(Exception):
    strerr = {0xC0: "resource not found",
              0xC1: "resource exceeds data size limit",
              0xC2: "malformed request not understood",
              0xE0: "unsupported functionality requested",
              0xE1: "unsupported protocol version"}

    def __init__(self, err):
        self.args = (err, strerr.get(err, ""))

    def __str__(self):
        return "nfc.snep.SnepError: [{errno}] {info}".format(
            errno=self.args[0], info=self.args[1])
