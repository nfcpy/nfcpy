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
import nfc.llcp

import time

import logging
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

    def send(self, message):
        """Send a handover request message to the remote server."""
        log.debug("sending '{0}' message".format(message.type))
        send_miu = self.socket.getsockopt(nfc.llcp.SO_SNDMIU)
        try:
            data = str(message)
        except nfc.llcp.EncodeError as e:
            log.error("message encoding failed: {0}".format(e))
        else:
            return self._send(data, send_miu)

    def _send(self, data, miu):
        while len(data) > 0:
            if self.socket.send(data[0:miu]):
                data = data[miu:]
            else:
                break
        return bool(len(data) == 0)

    def recv(self, timeout=None):
        """Receive a handover select message from the remote server."""
        message = self._recv(timeout)
        if message and message.type == "urn:nfc:wkt:Hs":
            log.debug("received '{0}' message".format(message.type))
            return nfc.ndef.HandoverSelectMessage(message)
        else:
            log.error("received invalid message type {0}".format(message.type))
            return None

    def _recv(self, timeout=None):
        data = ''
        started = time.time()
        while self.socket.poll("recv", timeout):
            try:
                data += self.socket.recv()
                message = nfc.ndef.Message(data)
                log.debug("received message\n" + message.pretty())
                return message
            except nfc.ndef.LengthError:
                elapsed = time.time() - started
                log.debug("message is incomplete (%d byte)", len(data))
                if timeout:
                    timeout = timeout - elapsed
                    log.debug("%.3f seconds left to timeout", timeout)
                continue  # incomplete message
            except TypeError:
                log.debug("data link connection closed")
                break  # recv() returned None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
