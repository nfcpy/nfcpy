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

def send_request(socket, snep_request, send_miu):
    if len(snep_request) <= send_miu:
        return socket.send(snep_request)

    if not socket.send(snep_request[0:send_miu]):
        return False

    if socket.recv() != "\x10\x80\x00\x00\x00\x00":
        return False

    for offset in xrange(send_miu, len(snep_request), send_miu):
        fragment = snep_request[offset:offset+send_miu]
        if not socket.send(fragment):
            return False

    return True

def recv_response(socket, acceptable_length, timeout):
    if socket.poll("recv", timeout):
        snep_response = socket.recv()
        if len(snep_response) < 6:
            log.debug("snep response initial fragment too short")
            return None
        version, status, length = struct.unpack(">BBL", snep_response[:6])
        if length > acceptable_length:
            log.debug("snep response exceeds acceptable length")
            return None
        if len(snep_response) - 6 < length:
            # request remaining fragments
            socket.send("\x10\x00\x00\x00\x00\x00")
            while len(snep_response) - 6 < length:
                if socket.poll("recv", timeout):
                    snep_response += socket.recv()
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
        """Connect to a SNEP server. This needs only be called to
        connect to a server other than the Default SNEP Server at
        `urn:nfc:sn:snep` or if the client wants to send multiple
        requests with a single connection.
        """
        self.close()
        self.socket = nfc.llcp.Socket(self.llc, nfc.llcp.DATA_LINK_CONNECTION)
        self.socket.connect(service_name)
        self.send_miu = self.socket.getsockopt(nfc.llcp.SO_SNDMIU)

    def close(self):
        """Close the data link connection with the SNEP server.
        """
        if self.socket:
            self.socket.close()
            self.socket = None

    def get(self, ndef_message=None, timeout=1.0):
        """Get an NDEF message from the server. Temporarily connects
        to the default SNEP server if the client is not yet connected.
        """
        if ndef_message is None:
            ndef_message = nfc.ndef.Message(nfc.ndef.Record())
        ndef_message_data = self._get(ndef_message, timeout)
        try:
            return nfc.ndef.Message(ndef_message_data)
        except Exception as err:
            log.error(repr(err))
        
    def _get(self, ndef_message, timeout=1.0):
        """Get an NDEF message from the server. Temporarily connects
        to the default SNEP server if the client is not yet connected.
        """
        if not self.socket:
            self.connect('urn:nfc:sn:snep')
            self.release_connection = True
        else:
            self.release_connection = False
        try:
            snep_request = '\x10\x01'
            snep_request += struct.pack('>L', 4 + len(str(ndef_message)))
            snep_request += struct.pack('>L', self.acceptable_length)
            snep_request += str(ndef_message)
            if send_request(self.socket, snep_request, self.send_miu):
                snep_response = recv_response(
                    self.socket, self.acceptable_length, timeout)
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
        try:
            ndef_msgsize = struct.pack('>L', len(str(ndef_message)))
            snep_request = '\x10\x02' + ndef_msgsize + str(ndef_message)
            if send_request(self.socket, snep_request, self.send_miu):
                snep_response = recv_response(self.socket, 0, timeout)
                if snep_response is not None:
                    response_code = ord(snep_response[1])
                    if response_code == 0x81:
                        return True
                    else:
                        raise SnepError(response_code)
            return False
        finally:
            if self.release_connection:
                self.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
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
