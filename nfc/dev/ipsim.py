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
# ipsim.py - device abstraction for a simulated NFC link over TCP/IP
#

import logging
log = logging.getLogger(__name__)

import socket
import select
import os

def format_data(data):
    import string
    printable = string.digits + string.letters + string.punctuation + ' '
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += ''.join([c if c in printable else '.' for c in data[i:i+16]])
    return '\n'.join(s)

class device(object):
    def __init__(self):
        host = "127.0.0.1"
        port = 50000
        self.pni = 0
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if s.connect_ex((host, port)) == 0:
            self.sd = s
        else:
            # no server found, become the server side
            s.close(); del s
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host,port)); s.listen(1)
            log.info("listening on %s:%s" % s.getsockname())
            self.sd, peer = s.accept()
            s.close()
        log.info("connected to %s:%s" % self.sd.getpeername())

    def __del__(self):
        log.debug("closing connection")
        if self.sd:
            self.sd.close()

    def poll_dep(self, gb):
        log.debug("poll for dep")
        self._send("\x00\xFF\xFF\x00\x00")
        data = self._recv(timeout = 100)
        if data and len(data) == 17 and data[0] == "\x01":
            log.debug("sending attribute request")
            NFCID3 = data[1:9] + "\x00\x00"
            self._send("\xD4\x00" + NFCID3 + "\x00\x00\x00\x32" + gb)
            data = self._recv(timeout = 500)
            if data and len(data) >= 17 and data.startswith("\xD5\x01"):
                return data[17:] # return the general bytes

    def poll_tt1(self):
        return None

    def poll_tt2(self):
        return None

    def poll_tt3(self, service_code = "\x12\xFC"):
        return None

    def listen(self, gb, timeout):
        log.debug("starting listen mode for %d milliseconds" % (timeout))
        NFCID2 = "\x01\xFE" + os.urandom(6)
        data = self._recv(timeout)
        if data and data == "\x00\xFF\xFF\x00\x00":
            log.debug("sending poll response")
            self._send("\x01"+NFCID2+"\x00\x00\x00\x00\x00\x00\x00\x00")
            data = self._recv(timeout = 500)
            if data and len(data) >= 16 and data.startswith("\xD4\x00"+NFCID2):
                log.debug("sending attribute response")
                self._send("\xD5\x01"+data[2:12]+"\x00\x00\x00\x0E\x32"+gb)
                return data[16:] # return the general bytes

    ##
    ## data exchange protocol
    ##
    def dep_exchange(self, cmd, timeout, mtu):
        mtu = 251 if mtu is None else mtu
        for i in range(0, len(cmd), mtu)[0:-1]:
            self._send_dep_req_inf(cmd[i:i+mtu], more = True)
            self._recv_dep_res_ack(timeout)
        self._send_dep_req_inf(cmd[-(len(cmd)%mtu):])
        data, more = self._recv_dep_res_inf(timeout)
        while more is True:
            self._send_dep_req_ack()
            resp, more = self._recv_dep_res_inf(timeout)
            data = data + resp
        return data

    def dep_get_data(self, timeout):
        data, more = self._recv_dep_req_inf(timeout)
        while more is True:
            self._send_dep_res_ack()
            resp, more = self._recv_dep_req_inf(timeout)
            data = data + resp
        return data

    def dep_set_data(self, data, timeout, mtu):
        mtu = 251 if mtu is None else mtu
        for i in range(0, len(data), mtu)[0:-1]:
            self._send_dep_res_inf(data[i:i+mtu], more = True)
            self._recv_dep_req_ack(100)
        self._send_dep_res_inf(data[-(len(data) % mtu):])

    ##
    ## tag type (1|2|3) command/response exchange
    ##
    def tt1_exchange(self, cmd):
        pass

    def tt2_exchange(self, cmd):
        pass

    def tt3_exchange(self, cmd):
        pass

    ##
    ## initiator send functions
    ##
    def _send_dep_req_inf(self, data, more=False):
        pdu = "\xD4\x06" + chr((self.pni % 4) | int(more) << 4) + data
        self._send(pdu)

    def _send_dep_req_ack(self):
        pdu = "\xD4\x06" + chr((self.pni % 4) | 0x40)
        self._send(pdu)

    ##
    ## initiator receive functions
    ##
    def _recv_dep_res_inf(self, timeout):
        pdu = self._recv(timeout)
        if pdu and pdu.startswith("\xD5\x07") and ord(pdu[2]) % 4 == self.pni:
            self.pni = (self.pni + 1) % 4
            more = bool(ord(pdu[2]) & 0x10)
            data = pdu[3:]
            return data, more
        return (None, False)
        
    def _recv_dep_res_ack(self, timeout):
        pdu = self._recv(timeout)
        if pdu and pdu.startswith("\xD5\x07"):
            if ord(pdu[2]) & 0xE0 == 0x40 and ord(pdu[2]) % 4 == self.pni:
                self.pni = (self.pni + 1) % 4
                return ord(pdu[2]) & 0x10 == 0x00    

    ##
    ## target send functions
    ##
    def _send_dep_res_inf(self, data, more=False):
        pdu = "\xD5\x07" + chr((self.pni % 4) | int(more) << 4) + data
        self._send(pdu)
        self.pni = (self.pni + 1) % 4

    def _send_dep_res_ack(self):
        pdu = "\xD5\x07" + chr((self.pni % 4) | 0x40)
        self._send(pdu)
        self.pni = (self.pni + 1) % 4

    #
    # target receive functions
    #
    def _recv_dep_req_inf(self, timeout):
        pdu = self._recv(timeout)
        if pdu and pdu.startswith("\xD4\x06") and ord(pdu[2]) % 4 == self.pni:
            more = bool(ord(pdu[2]) & 0x10)
            data = pdu[3:]
            return data, more
        
    def _recv_dep_req_ack(self, timeout):
        pdu = self._recv(timeout)
        if pdu and pdu.startswith("\xD4\x06"):
            if ord(pdu[2]) & 0xE0 == 0x40 and ord(pdu[2]) % 4 == self.pni:
                return ord(pdu[2]) & 0x10 == 0x00
        
    ##
    ## core send and receive functions, add/remove felica framing
    ##
    def _send(self, data):
        frame = "\x00\x00\x00\x00\x00\x00\xb2\x4d" + chr(len(data) + 1) + data
        frame = frame + CRC16([len(data) + 1] + [ord(x) for x in data])
        log.debug("send " + str(len(frame)) + " byte\n" + format_data(frame))
        if self.sd.send(frame.encode("hex")) != len(frame) * 2:
            raise IOError("NOTSENT")
        return True

    def _recv(self, timeout):
        ready = select.select([self.sd], [], [], timeout/1E3)
        if not len(ready[0]):
            return None

        data = self.sd.recv(4096).decode("hex")
        log.debug("rcvd " + str(len(data)) + " byte\n" + format_data(data))

        if not data.startswith("\x00\x00\x00\x00\x00\x00\xb2\x4d"):
            raise IOError("NOSYNC")
        if not len(data) >= 11:
            raise IOError("SHORTFRAME")
        if not len(data) == ord(data[8]) + 10:
            raise IOError("LENGTH")
        if not CRC16([ord(x) for x in data[8:-2]]) == data[-2:]:
            raise IOError("CHECKSUM")
        return data[9:-2]


def CRC16(data):
    table = (
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0)

    crc = 0
    for byte in data:
        ushort = (crc << 8) & 0xff00
        crc = ((ushort) ^ table[((crc >> 8) ^ (0xff & byte))])
    return chr(crc >> 8) + chr(crc & 0xff)


