# -*- coding: utf-8 -*-

import logging
log = logging.getLogger(__name__)

import struct
import nfc.llcp

from nfc.npp import NPP_SERVICE_NAME

def send_request(socket, npp_request, send_miu):
    if len(npp_request) <= send_miu:
        return nfc.llcp.send(socket, npp_request)
    else:
        if nfc.llcp.send(socket, npp_request[0:send_miu]):
            for offset in xrange(send_miu, len(npp_request), send_miu):
                fragment = npp_request[offset:offset+send_miu]
                if not nfc.llcp.send(socket, fragment):
                    break
            else: return True

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
        """Send an NDEF message to the server. Temporarily connects to
        the server if the client is not yet connected.
        """
        if not self.socket:
            self.__connect()
        try:
            npp_message = "\x01" # NPP version
            npp_message += "\x00\x00\x00\x01" # sending one entry
            npp_message += "\x01" # action code
            npp_message += struct.pack('>I', len(ndef_message.tostring()))
            npp_message += ndef_message.tostring()
            log.debug("%d bytes to send" % len(npp_message))
            if send_request(self.socket, npp_message, self.send_miu):
                log.debug("Message sent")
        finally:
            self.__close()

