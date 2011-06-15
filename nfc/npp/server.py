#
# Implementation of the NDEF Push Protocol (NPP)
#

import logging
log = logging.getLogger(__name__)

from nfc.npp import NPP_SERVICE_NAME
from threading import Thread
from struct import unpack

import nfc.llcp

class NPPServer(Thread):
    """ Simple NPP server. If single_threaded is True then a new thread will not be spawned.
    """
    def __init__(self, single_threaded=False):
        super(NPPServer, self).__init__()
        self.single_threaded = single_threaded

    def run(self):
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        try:
            nfc.llcp.bind(socket, NPP_SERVICE_NAME)
            addr = nfc.llcp.getsockname(socket)
            log.info("npp server bound to port {0}".format(addr))
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
            nfc.llcp.listen(socket, backlog=2)
            while True:
                client_socket = nfc.llcp.accept(socket)
                if self.single_threaded:
                    log.debug("got client in single_threaded mode")
                    if NPPServer.serve(client_socket, self):
                        break
                else:
                    log.debug("got client, will spawn thread")
                    client_thread = Thread(target=NPPServer.serve,
                                       args=[client_socket, self])
                    client_thread.start()
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

            log.debug("got {:d} octets data".format(len(data)))
            if len(data) < 10:
                log.debug("npp msg initial fragment too short")
                return # bail out, this is a bad client

            version, num_entries = unpack(">BI", data[:5])
            log.debug("version {:d}, {:d} entries"
                      .format(version, num_entries))
            if (version >> 4) > 1:
                log.debug("unsupported version {:d}".format(version>>4))
                return

            if num_entries != 1:
                log.debug("npp msg has invalid length")
                return

            remaining = data[5:]
            for i in range(num_entries):
                log.debug("processing NDEF message #{:d}".format(i+1))
                if len(remaining) < 5:
                    log.debug("insufficient data for action code and ndef size")
                    return

                action_code, length = unpack(">BI", remaining[:5])
                log.debug("action code {:d}, ndef length {:d}"
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
                log.debug("have complete ndef message, {:d} octets"
                          .format(len(ndef_message_data)))
                if npp_server.process(ndef_message_data) and npp_server.single_threaded:
                    return True

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
        implementation prints each record. If NPP server is single threaded
        and this method returns True, the server stops processing.
        """
        log.debug("ndef push server process message")
        log.debug(ndef_message_data.encode("hex"))
