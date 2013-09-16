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
# Simple NDEF Exchange Protocol (SNEP) - Server Base Class
#
import logging
log = logging.getLogger(__name__)

from threading import Thread
from struct import pack, unpack

import nfc.llcp
import nfc.ndef

class SnepServer(Thread):
    """ NFC Forum Simple NDEF Exchange Protocol server
    """
    def __init__(self, llc, service_name, max_ndef_msg_recv_size=1024):
        self.acceptable_length = max_ndef_msg_recv_size
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.bind(service_name)
        addr = socket.getsockname()
        log.info("snep server bound to port {0}".format(addr))
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        socket.listen(backlog=2)
        Thread.__init__(self, name=service_name,
                        target=self.listen, args=(socket,))

    def listen(self, socket):
        try:
            while True:
                client_socket = socket.accept()
                client_thread = Thread(target=SnepServer.serve,
                                       args=(client_socket, self))
                client_thread.start()
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            socket.close()
        pass

    @staticmethod
    def serve(socket, snep_server):
        peer_sap = socket.getpeername()
        log.info("serving snep client on remote sap {0}".format(peer_sap))
        send_miu = socket.getsockopt(nfc.llcp.SO_SNDMIU)
        try:
            while True:
                data = socket.recv()
                if not data:
                    break # connection closed

                if len(data) < 6:
                    log.debug("snep msg initial fragment too short")
                    break # bail out, this is a bad client

                version, opcode, length = unpack(">BBL", data[:6])
                if (version >> 4) > 1:
                    log.debug("unsupported version {0}".format(version>>4))
                    socket.send("\x10\xE1\x00\x00\x00\x00")
                    continue
                
                if length > snep_server.acceptable_length:
                    log.debug("snep msg exceeds acceptable length")
                    socket.send("\x10\xFF\x00\x00\x00\x00")
                    continue

                snep_request = data
                if len(snep_request) - 6 < length:
                    # request remaining fragments
                    socket.send("\x10\x80\x00\x00\x00\x00")
                    while len(snep_request) - 6 < length:
                        data = socket.recv()
                        if data: snep_request += data
                        else: break # connection closed

                # message complete, now handle the request
                if opcode == 1 and len(snep_request) >= 10:
                    snep_response = snep_server.__get(snep_request)
                elif opcode == 2:
                    snep_response = snep_server.__put(snep_request)
                else:
                    log.debug("bad request {0}".format(version & 0x0f))
                    snep_response = "\x10\xC2\x00\x00\x00\x00"

                # send the snep response, fragment if needed
                if len(snep_response) <= send_miu:
                    socket.send(snep_response)
                else:
                    socket.send(snep_response[0:send_miu])
                    if socket.recv() == "\x10\x00\x00\x00\x00\x00":
                        parts = range(send_miu, len(snep_response), send_miu)
                        for offset in parts:
                            fragment = snep_response[offset:offset+send_miu]
                            socket.send(fragment)

        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            socket.close()

    def __get(self, snep_request):
        acceptable_length = unpack(">L", snep_request[6:10])[0]
        response = self._get(acceptable_length, snep_request[10:])
        if type(response) == int:
            response_code = chr(response)
            ndef_message = ""
        else:
            response_code = chr(0x81)
            ndef_message = response
        ndef_length = pack(">L", len(ndef_message))
        return "\x10" + response_code + ndef_length + ndef_message

    def _get(self, acceptable_length, ndef_message_data):
        log.debug("SNEP GET ({0})".format(ndef_message_data.encode("hex")))
        try:
            ndef_message = nfc.ndef.Message(ndef_message_data)
        except (nfc.ndef.LengthError, nfc.ndef.FormatError) as err:
            log.error(repr(err))
            return 0xC2
        else:
            rsp = self.get(acceptable_length, ndef_message)
            return str(rsp) if isinstance(rsp, nfc.ndef.Message) else rsp
        
    def get(self, acceptable_length, ndef_message):
        """Handle Get requests. This method should be overwritten by a
        subclass of SnepServer to customize it's behavior. The default
        implementation simply returns Not Implemented.
        """
        return 0xE0

    def __put(self, snep_request):
        response = self._put(snep_request[6:])
        response_code = chr(response)
        ndef_length = "\x00\x00\x00\x00"
        return "\x10" + chr(response) + ndef_length

    def _put(self, ndef_message_data):
        log.debug("SNEP PUT ({0})".format(ndef_message_data.encode("hex")))
        try:
            ndef_message = nfc.ndef.Message(ndef_message_data)
        except (nfc.ndef.LengthError, nfc.ndef.FormatError) as err:
            log.error(repr(err))
            return 0xC2
        else:
            return self.put(ndef_message)

    def put(self, ndef_message):
        """Handle Put requests. This method should be overwritten by a
        subclass of SnepServer to customize it's behavior. The default
        implementation simply returns Not Implemented.
        """
        return 0xE0
