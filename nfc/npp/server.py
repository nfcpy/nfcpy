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
    """ Simple NPP server
    """
    def __init__(self):
        super(NPPServer, self).__init__()

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
            while True:
                data = nfc.llcp.recv(socket)
                if not data:
                    log.debug("no data")
                    break # connection closed

                log.debug("Got data with %d length" % len(data))
                if len(data) < 10:
                    log.debug("npp msg initial fragment too short")
                    break # bail out, this is a bad client

                version, num_entries = unpack(">BI", data[:5])
                log.debug("Got version %d and %d entries" % (version, num_entries))
                if (version >> 4) > 1:
                    log.debug("unsupported version {}".format(version>>4))
                    break

                if num_entries != 1:
                    log.debug("npp msg has invalid length")
                    break

                remaining = data[5:]
                for i in range(num_entries):
                    log.debug("Fetching NDEF %d" % i)
                    if len(remaining) < 5:
                        log.debug("Not enough data to fetch action code and NDEF length")
                        nfc.llcp.send(socket, "\x10\x80\x00\x00\x00\x00")
                        while len(remaining) < 5:
                            data = nfc.llcp.recv(socket)
                            if data:
                                remaining += data
                            else:
                                break # connection closed
                    log.debug("Got everything: %d" % len(remaining))
                    action_code, length = unpack(">BI", remaining[:5])
                    log.debug("Action code %d NDEF length %d" % (action_code, length))
                    if action_code != 1:
                        log.debug("Unsuported action code")
                        break

                    remaining = remaining[5:]
                    if len(remaining) < length:
                        log.debug("Not enough data to read entry")
                        nfc.llcp.send(socket, "\x10\x80\x00\x00\x00\x00")
                        while len(remaining) < length:
                            data = nfc.llcp.recv(socket)
                            if data:
                                remaining += data
                            else:
                                break # connection closed

                    # message complete, now handle the request
                    ndef = nfc.ndef.Message(remaining[:length])
                    log.debug("Got NDEF %s" % ndef)
                    npp_server.process(ndef)

                    # prepare for next
                    remaining = remaining[length:]

        except nfc.llcp.Error as e:
            log.debug("caught exception {0}".format(e))
        except Exception, e:
            log.error(e)
            raise
        finally:
            nfc.llcp.close(socket)

    def process(self, ndef_message):
        """Processes NDEF messages. This method should be overwritten by a
        subclass of NPPServer to customize it's behavior. The default
        implementation prints each record.
        """
        log.debug("get method called")
        log.debug(ndef_message.encode("hex"))
        for record in ndef_message:
            log.debug(record)
