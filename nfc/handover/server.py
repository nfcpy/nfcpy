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
# Negotiated Connection Handover - Server Base Class
#
import logging
log = logging.getLogger(__name__)

from threading import Thread
import nfc.llcp

class HandoverServer(Thread):
    """ NFC Forum Connection Handover server
    """
    def __init__(self, llc, request_size_limit=4096, recv_miu=248, recv_buf=2):
        socket = llc.socket(nfc.llcp.DATA_LINK_CONNECTION)
        llc.setsockopt(socket, nfc.llcp.SO_RCVBUF, recv_buf)
        llc.setsockopt(socket, nfc.llcp.SO_RCVMIU, recv_miu)
        llc.bind(socket, 'urn:nfc:sn:handover')
        addr = llc.getsockname(socket)
        log.info("handover server bound to port {0}".format(addr))
        llc.listen(socket, backlog=2)
        Thread.__init__(self, name='urn:nfc:sn:handover',
                        target=self.listen, args=(llc, socket))

    def listen(self, llc, socket):
        try:
            while True:
                client_socket = llc.accept(socket)
                print "client_socket =", client_socket
                client_thread = Thread(target=HandoverServer.serve,
                                       args=[llc, client_socket, self])
                client_thread.start()
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            llc.close(socket)

    @staticmethod
    def serve(llc, socket, handover_server):
        peer_sap = llc.getpeername(socket)
        log.info("serving handover client on remote sap {0}".format(peer_sap))
        send_miu = llc.getsockopt(socket, nfc.llcp.SO_SNDMIU)
        try:
            while True:
                request_data = ''
                while llc.poll(socket, "recv"):
                    data = llc.recv(socket)
                    if data is not None:
                        request_data += data
                        try:
                            request = nfc.ndef.Message(request_data)
                            break # message complete
                        except nfc.ndef.LengthError:
                            continue # need more data
                    else: return # connection closed
                else: return # connection closed

                log.debug("<<< {0!r}".format(request_data))
                response = handover_server._process_request(request)
                response_data = str(response)
                log.debug(">>> {0!r}".format(response_data))

                while len(response_data) > 0:
                    if llc.send(socket, response_data[0:send_miu]):
                        response_data = response_data[send_miu:]
                    else:
                        return # connection closed
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            llc.close(socket)

    def _process_request(self, request):
        log.debug("rcvd handover request {0}\n{1}"
                  .format(request.type, request.pretty()))
        response = nfc.ndef.Message("\xd1\x02\x01Hs\x12")
        if not request.type == 'urn:nfc:wkt:Hr':
            log.error("received message which is not a handover request")
        else:
            try:
                request = nfc.ndef.HandoverRequestMessage(request)
            except nfc.ndef.DecodeError as e:
                log.error("error decoding 'Hr' message: {0}".format(e))
            else:
                response = self.process_request(request)
        log.debug("send handover response {0}\n{1}"
                  .format(response.type, response.pretty()))
        return response
    
    def process_request(self, request):
        """Process a handover request message. The *request* argument
        is a :class:`nfc.ndef.HandoverRequestMessage` object. The
        return value must be a :class:`nfc.ndef.HandoverSelectMessage`
        object to be sent back to the client.

        This method should be overwritten by a subclass of
        :class:`HandoverServer` to customize it's behavior. The
        default implementation returns a version ``1.2``
        :class:`nfc.ndef.HandoverSelectMessage` with no carriers.
        """
        log.warning("default process_request method should be overwritten")
        return nfc.ndef.HandoverSelectMessage(version="1.2")

