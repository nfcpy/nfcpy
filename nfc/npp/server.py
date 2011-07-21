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
# NDEF Push Protocol (NPP) - Server Base Class
#

import logging
log = logging.getLogger(__name__)

from nfc.npp import NPP_SERVICE_NAME
from threading import Thread
from struct import unpack

import nfc.llcp

class NPPServer(Thread):
    """Simple NPP server. Can serve multiple requests in threaded mode.
    """
    def __init__(self, threaded=False):
        super(NPPServer, self).__init__()
        self.threaded = threaded

    def run(self):
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        try:
            nfc.llcp.bind(socket, NPP_SERVICE_NAME)
            addr = nfc.llcp.getsockname(socket)
            log.info("npp server bound to port {0}".format(addr))
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
            nfc.llcp.listen(socket, backlog=2 if self.threaded else 0)
            while True:
                client_socket = nfc.llcp.accept(socket)
                if self.threaded:
                    client_thread = Thread(target=NPPServer.serve,
                                           args=[client_socket, self])
                    log.debug("client connected, serving on thread {0}"
                              .format(client_thread))
                    client_thread.start()
                else:
                    log.debug("client connected, serving in main thread")
                    if NPPServer.serve(client_socket, self):
                        break
        except nfc.llcp.Error as e:
            log.error(str(e))
        finally:
            nfc.llcp.close(socket)

    @staticmethod
    def serve(socket, npp_server):
        peer_sap = nfc.llcp.getpeername(socket)
        log.info("serving npp client on remote sap {0}".format(peer_sap))

        try:
            data = nfc.llcp.recv(socket)
            if data is None:
                log.debug("connection closed, no data")
                return

            while nfc.llcp.poll(socket, "recv"):
                data += nfc.llcp.recv(socket)

            log.debug("got {0:d} octets data".format(len(data)))
            if len(data) < 10:
                log.debug("npp msg initial fragment too short")
                return # bail out, this is a bad client

            version, num_entries = unpack(">BI", data[:5])
            log.debug("version {0:d}, {1:d} entries"
                      .format(version, num_entries))
            if (version >> 4) > 1:
                log.debug("unsupported version {0:d}".format(version>>4))
                return

            if num_entries != 1:
                log.debug("npp msg has invalid length")
                return

            remaining = data[5:]
            for i in range(num_entries):
                log.debug("processing NDEF message #{0:d}".format(i+1))
                if len(remaining) < 5:
                    log.debug("insufficient data for action code and ndef size")
                    return

                action_code, length = unpack(">BI", remaining[:5])
                log.debug("action code {0:d}, ndef length {1:d} octet"
                          .format(action_code, length))

                if action_code != 1:
                    log.error("unknown action code")
                    return

                remaining = remaining[5:]
                if len(remaining) < length:
                    log.error("less data than entry size indicates")
                    return

                # message complete, now handle the request
                ndef_message_data = remaining[:length]
                log.debug("have complete ndef message, {0:d} octets"
                          .format(len(ndef_message_data)))
                npp_server.process(ndef_message_data)

                # prepare for next
                remaining = remaining[length:]
            return

        except nfc.llcp.Error as e:
            log.debug("caught exception {0}".format(e))
        except Exception, e:
            log.error(e)
            raise
        finally:
            nfc.llcp.close(socket)

    def process(self, ndef_message_data):
        """Processes NDEF messages. This method should be overwritten by a
        subclass of NPPServer to customize it's behavior. The default
        implementation prints each record.
        """
        log.debug("ndef push server process message")
        log.debug(ndef_message_data.encode("hex"))
