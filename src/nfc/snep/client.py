# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
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
import ndef
import struct
import nfc.llcp

import logging
log = logging.getLogger(__name__)


def send_request(socket, snep_request, send_miu):
    if len(snep_request) <= send_miu:
        return socket.send(snep_request)

    if not socket.send(snep_request[0:send_miu]):
        return False

    if socket.recv() != b"\x10\x80\x00\x00\x00\x00":
        return False

    for offset in range(send_miu, len(snep_request), send_miu):
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
            socket.send(b"\x10\x00\x00\x00\x00\x00")
            while len(snep_response) - 6 < length:
                if socket.poll("recv", timeout):
                    snep_response += socket.recv()
                else:
                    return None

        return bytearray(snep_response)


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

    def get_records(self, records=None, timeout=1.0):
        """Get NDEF message records from a SNEP Server.

        .. versionadded:: 0.13

        The :class:`ndef.Record` list given by *records* is encoded as
        the request message octets input to :meth:`get_octets`. The
        return value is an :class:`ndef.Record` list decoded from the
        response message octets returned by :meth:`get_octets`. Same
        as::

            import ndef
            send_octets = ndef.message_encoder(records)
            rcvd_octets = snep_client.get_octets(send_octets, timeout)
            records = list(ndef.message_decoder(rcvd_octets))

        """
        octets = b''.join(ndef.message_encoder(records)) if records else None
        octets = self.get_octets(octets, timeout)
        if octets and len(octets) >= 3:
            return list(ndef.message_decoder(octets))

    def get_octets(self, octets=None, timeout=1.0):
        """Get NDEF message octets from a SNEP Server.

        .. versionadded:: 0.13

        If the client has not yet a data link connection with a SNEP
        Server, it temporarily connects to the default SNEP Server,
        sends the message octets, disconnects after the server
        response, and returns the received message octets.

        """
        if octets is None:
            # Send NDEF Message with one empty Record.
            octets = b'\xd0\x00\x00'

        if not self.socket:
            try:
                self.connect('urn:nfc:sn:snep')
            except nfc.llcp.ConnectRefused:
                return None
            else:
                self.release_connection = True
        else:
            self.release_connection = False

        try:
            request = struct.pack('>BBLL', 0x10, 0x01, 4 + len(octets),
                                  self.acceptable_length) + octets

            if not send_request(self.socket, request, self.send_miu):
                return None

            response = recv_response(
                self.socket, self.acceptable_length, timeout)

            if response is not None:
                if response[1] != 0x81:
                    raise SnepError(response[1])

                return response[6:]

        finally:
            if self.release_connection:
                self.close()

    def put_records(self, records, timeout=1.0):
        """Send NDEF message records to a SNEP Server.

        .. versionadded:: 0.13

        The :class:`ndef.Record` list given by *records* is encoded
        and then send via :meth:`put_octets`. Same as::

            import ndef
            octets = ndef.message_encoder(records)
            snep_client.put_octets(octets, timeout)

        """
        octets = b''.join(ndef.message_encoder(records))
        return self.put_octets(octets, timeout)

    def put_octets(self, octets, timeout=1.0):
        """Send NDEF message octets to a SNEP Server.

        .. versionadded:: 0.13

        If the client has not yet a data link connection with a SNEP
        Server, it temporarily connects to the default SNEP Server,
        sends the message octets and disconnects after the server
        response.

        """
        if not self.socket:
            try:
                self.connect('urn:nfc:sn:snep')
            except nfc.llcp.ConnectRefused:
                return False
            else:
                self.release_connection = True
        else:
            self.release_connection = False

        try:
            request = struct.pack('>BBL', 0x10, 0x02, len(octets)) + octets
            if not send_request(self.socket, request, self.send_miu):
                return False

            response = recv_response(self.socket, 0, timeout)
            if response is not None:
                if response[1] != 0x81:
                    raise SnepError(response[1])

            return True

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
