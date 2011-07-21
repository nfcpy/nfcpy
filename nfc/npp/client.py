# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011 André Cruz <andre@cabine.org>
# Copyright 2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
# NDEF Push Protocol (NPP) - Client Base Class
#

import logging
log = logging.getLogger(__name__)

import struct
import nfc.llcp

from nfc.npp import NPP_SERVICE_NAME

def send_request(socket, npp_request, send_miu):
    for offset in xrange(0, len(npp_request), send_miu):
        fragment = npp_request[offset:offset+send_miu]
        if not nfc.llcp.send(socket, fragment):
            return False
        return True

class NPPClient(object):
    """ A NPP implementation - client side
    """
    def __init__(self):
        self.socket = None
        self.acceptable_length = 1024

    def __connect(self):
        if self.socket: self.__close()
        self.socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        nfc.llcp.connect(self.socket, NPP_SERVICE_NAME)
        peer_sap = nfc.llcp.getpeername(self.socket)
        log.debug("connection established with sap {0}".format(peer_sap))
        self.send_miu = nfc.llcp.getsockopt(self.socket, nfc.llcp.SO_SNDMIU)

    def __close(self):
        if self.socket:
            nfc.llcp.close(self.socket)
            self.socket = None

    def put(self, ndef_message):
        """Send an NDEF message to the NPP server.
        """
        npp_message = "\x01" # NPP version
        npp_message += "\x00\x00\x00\x01" # sending one entry
        npp_message += "\x01" # action code
        npp_message += struct.pack('>I', len(ndef_message.tostring()))
        npp_message += ndef_message.tostring()
        log.debug("%d bytes to send" % len(npp_message))

        self.__connect()
        try:
            if send_request(self.socket, npp_message, self.send_miu):
                log.debug("Message sent")
        finally:
            self.__close()

