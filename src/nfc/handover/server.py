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
# Negotiated Connection Handover - Server Base Class
#
import threading
import binascii
import logging
import errno
import ndef
import nfc


log = logging.getLogger(__name__)


class HandoverServer(threading.Thread):
    """ NFC Forum Connection Handover server
    """
    def __init__(self, llc, request_size_limit=0x10000,
                 recv_miu=1984, recv_buf=15):
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        recv_miu = socket.setsockopt(nfc.llcp.SO_RCVMIU, recv_miu)
        recv_buf = socket.setsockopt(nfc.llcp.SO_RCVBUF, recv_buf)
        socket.bind('urn:nfc:sn:handover')
        log.info("handover server bound to port {0} (MIU={1}, RW={2})"
                 .format(socket.getsockname(), recv_miu, recv_buf))
        socket.listen(backlog=2)
        threading.Thread.__init__(self, name='urn:nfc:sn:handover',
                                  target=self.listen, args=(llc, socket))

    def listen(self, llc, socket):
        log.debug("handover listen thread started")
        try:
            while True:
                client_socket = socket.accept()
                client_thread = threading.Thread(target=self.serve,
                                                 args=(client_socket,))
                client_thread.start()
        except nfc.llcp.Error as error:
            (log.debug if error.errno == errno.EPIPE else log.error)(error)
        finally:
            socket.close()
            log.debug("handover listen thread terminated")

    def serve(self, socket):
        peer_sap = socket.getpeername()
        log.info("serving handover client on remote sap {0}".format(peer_sap))
        send_miu = socket.getsockopt(nfc.llcp.SO_SNDMIU)
        try:
            while socket.poll("recv"):
                request = bytearray()
                while socket.poll("recv"):
                    request += socket.recv()

                    if len(request) == 0:
                        continue  # need some data

                    try:
                        list(ndef.message_decoder(request, 'strict', {}))
                    except ndef.DecodeError:
                        continue  # need more data

                    response = self._process_request_data(request)

                    for offset in range(0, len(response), send_miu):
                        fragment = response[offset:offset + send_miu]
                        if not socket.send(fragment):
                            return  # connection closed

        except nfc.llcp.Error as error:
            (log.debug if error.errno == errno.EPIPE else log.error)(error)
        finally:
            socket.close()
            log.debug("handover serve thread terminated")

    def _process_request_data(self, octets):
        log.debug("<<< %s", binascii.hexlify(octets).decode())
        try:
            records = list(ndef.message_decoder(octets, 'relax'))
        except ndef.DecodeError as error:
            log.error(repr(error))
            return b''

        if records[0].type == 'urn:nfc:wkt:Hr':
            records = self.process_handover_request_message(records)
        else:
            log.error("received unknown request message")
            records = []

        octets = b''.join(ndef.message_encoder(records))
        log.debug(">>> %s", binascii.hexlify(octets).decode())
        return octets

    def process_handover_request_message(self, records):
        """Process a handover request message. The *records* argument holds a
        list of :class:`ndef.Record` objects decoded from the received
        handover request message octets, where the first record type is
        ``urn:nfc:wkt:Hr``. The method returns a list of :class:`ndef.Record`
        objects with the first record typ ``urn:nfc:wkt:Hs``.

        This method should be overwritten by a subclass to customize
        it's behavior. The default implementation returns a
        :class:`ndef.HandoverSelectRecord` with version ``1.2`` and no
        alternative carriers.

        """
        log.warning("default process_request method should be overwritten")
        return [ndef.HandoverSelectRecord('1.2')]
