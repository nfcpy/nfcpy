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
# Negotiated Connection Handover - Client Base Class
#
import binascii
import logging
import time
import ndef
import nfc


log = logging.getLogger(__name__)


class HandoverClient(object):
    """ NFC Forum Connection Handover client
    """
    def __init__(self, llc):
        self.socket = None
        self.llc = llc

    def connect(self, recv_miu=248, recv_buf=2):
        """Connect to the remote handover server if available. Raises
        :exc:`nfc.llcp.ConnectRefused` if the remote device does not
        have a handover service or the service does not accept any
        more connections."""
        socket = nfc.llcp.Socket(self.llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, recv_buf)
        socket.setsockopt(nfc.llcp.SO_RCVMIU, recv_miu)
        socket.connect("urn:nfc:sn:handover")
        server = socket.getpeername()
        log.debug("handover client connected to remote sap {0}".format(server))
        self.socket = socket

    def close(self):
        """Disconnect from the remote handover server."""
        if self.socket:
            self.socket.close()
            self.socket = None

    def send_records(self, records):
        """Send handover request message records to the remote server."""
        log.debug("sending '{0}' message".format(records[0].type))
        try:
            octets = b''.join(ndef.message_encoder(records))
        except ndef.EncodeError as error:
            log.error(repr(error))
        else:
            return self.send_octets(octets)

    def send_octets(self, octets):
        log.debug(">>> %s", binascii.hexlify(octets).decode())
        miu = self.socket.getsockopt(nfc.llcp.SO_SNDMIU)
        while len(octets) > 0:
            if self.socket.send(octets[0:miu]):
                octets = octets[miu:]
            else:
                break
        return len(octets) == 0

    def recv_records(self, timeout=None):
        """Receive a handover select message from the remote server."""
        octets = self.recv_octets(timeout)
        records = list(ndef.message_decoder(octets, 'relax')) if octets else []
        if records and records[0].type == "urn:nfc:wkt:Hs":
            log.debug("received '{0}' message".format(records[0].type))
            return list(ndef.message_decoder(octets, 'relax'))
        else:
            log.error("received invalid message %s", binascii.hexlify(octets))
            return []

    def recv_octets(self, timeout=None):
        octets = bytearray()
        started = time.time()
        while self.socket.poll("recv", timeout):
            try:
                octets += self.socket.recv()
            except TypeError:
                log.debug("data link connection closed")
                return b''  # recv() returned None
            try:
                list(ndef.message_decoder(octets, 'strict', {}))
                log.debug("<<< %s", binascii.hexlify(octets).decode())
                return bytes(octets)
            except ndef.DecodeError:
                log.debug("message is incomplete (%d byte)", len(octets))
                if timeout:
                    timeout -= time.time() - started
                    started = time.time()
                    log.debug("%.3f seconds left to timeout", timeout)
                continue  # incomplete message

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
