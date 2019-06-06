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
# Simple NDEF Exchange Protocol (SNEP) - Server Base Class
#
import threading
import binascii
import logging
import struct
import errno
import ndef
import nfc


log = logging.getLogger(__name__)


class SnepServer(threading.Thread):
    """ NFC Forum Simple NDEF Exchange Protocol server
    """
    def __init__(self, llc, service_name="urn:nfc:sn:snep",
                 max_acceptable_length=0x100000,
                 recv_miu=1984, recv_buf=15):

        self.max_acceptable_length = min(max_acceptable_length, 0xFFFFFFFF)
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        recv_miu = socket.setsockopt(nfc.llcp.SO_RCVMIU, recv_miu)
        recv_buf = socket.setsockopt(nfc.llcp.SO_RCVBUF, recv_buf)
        socket.bind(service_name)
        log.info("snep server bound to port {0} (MIU={1}, RW={2}), "
                 "will accept up to {3} byte NDEF messages"
                 .format(socket.getsockname(), recv_miu, recv_buf,
                         self.max_acceptable_length))
        socket.listen(backlog=2)
        threading.Thread.__init__(self, name=service_name,
                                  target=self._listen, args=(socket,))

    def _listen(self, listen_socket):
        try:
            while True:
                client_socket = listen_socket.accept()
                client_thread = threading.Thread(target=self._serve,
                                                 args=(client_socket,))
                client_thread.start()
        except nfc.llcp.Error as error:
            (log.debug if error.errno == errno.EPIPE else log.error)(error)
        finally:
            listen_socket.close()

    def _serve(self, client_socket):
        peer_sap = client_socket.getpeername()
        log.info("serving snep client on remote sap {0}".format(peer_sap))
        send_miu = client_socket.getsockopt(nfc.llcp.SO_SNDMIU)
        try:
            while client_socket.poll('recv'):
                data = bytearray(client_socket.recv())
                if not data:
                    break  # connection closed

                if len(data) < 6:
                    log.debug("snep msg initial fragment too short")
                    break  # bail out, this is a bad client

                version, length = struct.unpack_from(">BxL", data)

                if (version >> 4) > 1:
                    log.debug("unsupported version {0}".format(version >> 4))
                    client_socket.send(b"\x10\xE1\x00\x00\x00\x00")
                    continue

                if length > self.max_acceptable_length:
                    log.debug("snep msg exceeds max acceptable length")
                    client_socket.send(b"\x10\xFF\x00\x00\x00\x00")
                    continue

                if len(data) - 6 < length:
                    # request remaining fragments
                    client_socket.send(b"\x10\x80\x00\x00\x00\x00")
                    while len(data) - 6 < length:
                        try:
                            data += client_socket.recv()
                        except TypeError:
                            break  # connection closed

                # message complete, now handle the request
                data = self.process_snep_request(data)

                # send the snep response, fragment if needed
                if len(data) <= send_miu:
                    client_socket.send(data)
                else:
                    client_socket.send(data[0:send_miu])
                    if client_socket.recv() == b"\x10\x00\x00\x00\x00\x00":
                        parts = range(send_miu, len(data), send_miu)
                        for offset in parts:
                            client_socket.send(data[offset:offset + send_miu])

        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            client_socket.close()

    def process_snep_request(self, request_data):
        assert isinstance(request_data, bytearray)
        log.debug("<<< %s", binascii.hexlify(request_data).decode())
        try:
            if request_data[1] == 1 and len(request_data) >= 10:
                acceptable_length = struct.unpack(">L", request_data[6:10])[0]
                octets = request_data[10:]
                records = list(ndef.message_decoder(octets, known_types={}))
                response = self.process_get_request(records)
                if isinstance(response, int):
                    response_code = response
                    response_data = b''
                else:
                    response_code = 0x81  # nfc.snep.Success
                    response_data = b''.join(ndef.message_encoder(response))
                if len(response_data) > acceptable_length:
                    response_code = 0xC1  # nfc.snep.ExcessData
                    response_data = b''
            elif request_data[1] == 2:
                octets = request_data[6:]
                records = list(ndef.message_decoder(octets, known_types={}))
                response_code = self.process_put_request(records)
                response_data = b''
            else:
                log.debug("bad request (0x{:02x})".format(request_data[1]))
                response_code = 0xC2  # nfc.snep.BadRequest
                response_data = b''
        except ndef.DecodeError as error:
            log.error(repr(error))
            response_code = 0xC2  # nfc.snep.BadRequest
            response_data = b''
        except ndef.EncodeError as error:
            log.error(repr(error))
            response_code = 0xC0  # nfc.snep.NotFound
            response_data = b''

        header = struct.pack(">BBL", 0x10, response_code, len(response_data))
        response_data = header + response_data
        log.debug(">>> %s", binascii.hexlify(response_data).decode())
        return response_data

    def process_get_request(self, ndef_message):
        """Handle Get requests. This method should be overwritten by a
        subclass of SnepServer to customize it's behavior. The default
        implementation simply returns nfc.snep.NotImplemented.
        """
        return 0xE0  # NotImplemented

    def process_put_request(self, ndef_message):
        """Process a SNEP Put request. This method should be overwritten by a
        subclass of SnepServer to customize it's behavior. The default
        implementation simply returns nfc.snep.Success.
        """
        return 0x81  # nfc.snep.Success
