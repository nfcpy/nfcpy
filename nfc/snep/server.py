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

from threading import Thread
from struct import unpack

import nfc.llcp

class SnepServer(Thread):
    """
    """
    def __init__(self, service_name):
        super(SnepServer, self).__init__()
        self.name = service_name
        self.acceptable_length = 1024

    def run(self):
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        try:
            nfc.llcp.bind(socket, self.name)
            addr = nfc.llcp.getsockname(socket)
            log.info("snep server bound to port {0}".format(addr))
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
            nfc.llcp.listen(socket, backlog=2)
            while True:
                client_socket = nfc.llcp.accept(socket)
                client_thread = Thread(target=SnepServer.serve,
                                       args=[client_socket, self])
                client_thread.start()
        except nfc.llcp.Error as e:
            log.error(str(e))
        finally:
            nfc.llcp.close(socket)
        pass

    @staticmethod
    def serve(socket, snep_server):
        peer_sap = nfc.llcp.getpeername(socket)
        log.info("serving snep client on remote sap {0}".format(peer_sap))
        send_miu = nfc.llcp.getsockopt(socket, nfc.llcp.SO_SNDMIU)
        try:
            while True:
                snep_request = nfc.llcp.recv(socket)
                if not snep_request:
                    break # connection closed

                if len(snep_request) < 6:
                    log.debug("snep msg initial fragment too short")
                    break # bail out, this is a bad client

                version, opcode, length = unpack(">BBL", snep_request[:6])
                if (version >> 4) > 1:
                    log.debug("unsupported version {}".format(version>>4))
                    nfc.llcp.send(socket, "\x10\xE1\x00\x00\x00\x00")
                    continue

                if length > snep_server.acceptable_length:
                    log.debug("snep msg exceeds acceptable length")
                    nfc.llcp.send(socket, "\x10\xFF\x00\x00\x00\x00")
                    continue

                if len(snep_request) - 6 < length:
                    # send continue to get remaining fragments
                    nfc.llcp.send(socket, "\x10\x80\x00\x00\x00\x00")
                    while len(snep_request) - 6 < length:
                        snep_request += nfc.llcp.recv(socket)

                # message complete, now handle the request
                if opcode == 1 and len(snep_request) >= 10:
                    snep_response = snep_server._get(snep_request)
                elif opcode == 2:
                    snep_response = snep_server._put(snep_request)
                else:
                    # return a "bad request" response
                    snep_response = "\x10\xC2\x00\x00\x00\x00"

                # send the snep response, fragment if needed
                if len(snep_response) <= send_miu:
                    nfc.llcp.send(socket, snep_response)
                else:
                    nfc.llcp.send(socket, snep_response[0:send_miu])
                    if nfc.llcp.recv(socket) == "\x10\x00\x00\x00\x00\x00":
                        parts = xrange(send_miu, len(snep_response), send_miu)
                        for offset in parts:
                            fragment = snep_response[offset:offset+send_miu]
                            nfc.llcp.send(socket, fragment)

                continue # wait for next request
        except Exception as e:
            log.debug("caught exception" + str(e))
        finally:
            nfc.llcp.close(socket)

    def _get(self, snep_request):
        acceptable_length = unpack(">L", snep_request[6:10])
        response = self.get(acceptable_length, snep_request[10:])
        if type(response) == type(int()):
            response_code = chr(response)
            ndef_message = ""
        else:
            response_code = chr(0x81)
            ndef_message = response
        ndef_length = pack(">L", len(ndef_message))
        return "\x10" + response_code + ndef_length + ndef_message

    def get(self, acceptable_length, ndef_message):
        log.debug("get method called")
        print ndef_message.encode("hex")
        return 0xE0

    def _put(self, snep_request):
        response = self.put(snep_request[6:])
        response_code = chr(response)
        ndef_length = "\x00\x00\x00\x00"
        return "\x10" + chr(response) + ndef_length

    def put(self, ndef_message):
        log.debug("put method called")
        print ndef_message.encode("hex")
        return 0xE0
