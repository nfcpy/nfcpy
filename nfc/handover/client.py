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
# Negotiated Connection Handover - Client Base Class
#
import logging
log = logging.getLogger(__name__)

import nfc.llcp

class HandoverClient(object):
    """ NFC Forum Connection Handover client
    """
    def __init__(self):
        self.socket = None

    def connect(self):
        """Connect to the remote handover server if available. Raises
        :exc:`nfc.llcp.ConnectRefused` if the remote device does not
        have a handover service or the service does not accept any
        more connections."""
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        nfc.llcp.connect(socket, "urn:nfc:sn:handover")
        nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 15)
        log.info("handover client connected to remote sap {0}"
                 .format(nfc.llcp.getsockname(socket)))
        self.socket = socket

    def close(self):
        """Disconnect from the remote handover server."""
        if self.socket:
            nfc.llcp.close(self.socket)
            self.socket = None

    def send(self, request):
        """Send a handover request message to the remote server."""
        send_miu = nfc.llcp.getsockopt(self.socket, nfc.llcp.SO_SNDMIU)
        return self._send(str(request), send_miu)
        
    def _send(self, data, miu):
        while len(data) > 0:
            if nfc.llcp.send(self.socket, data[0:miu]):
                data = data[miu:]
            else: break
        return bool(len(data) == 0)
        
    def recv(self):
        """Receive a handover select message from the remote server."""
        message = self._recv()
        if message and message.type == "urn:nfc:wkt:Hs":
            log.debug("received '{0}' message".format(message.type))
            return message
        else:
            return None

    def _recv(self):
        data = ''
        while nfc.llcp.poll(socket, "recv"):
            try:
                data += nfc.llcp.recv(self.socket)
                message = nfc.ndef.Message(data)
                log.debug("received message\n" + message.pretty())
                break
            except nfc.ndef.ParseError:
                log.debug("message is incomplete ({0} byte)".format(len(data)))
                continue # incomplete message
            except TypeError:
                return None # recv() returned None
        return message
    
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        print exc_type
        print exc_value
        print traceback
        self.close()

