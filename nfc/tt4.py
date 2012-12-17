# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import logging
log = logging.getLogger(__name__)

import tag

ndef_app_file_v1 = bytearray("\xD2\x76\x00\x00\x85\x01\x00")
ndef_app_file_v2 = bytearray("\xD2\x76\x00\x00\x85\x01\x01")
capability_container = bytearray("\xE1\x03")

class Type4TagError(BaseException):
    errmsg = {
        (0x6A, 0x80): "Incorrect parameters in the data field",
        (0x6A, 0x81): "Function not supported",
        (0x6A, 0x82): "File not found",
        (0x6A, 0x83): "Record not found",
        (0x6A, 0x84): "Not enough memory space in the file",
        (0x6A, 0x85): "Lc inconsistent with TLV structure",
        (0x6A, 0x86): "Incorrect parameters P1-P2",
        (0x6A, 0x87): "Lc inconsistent with P1-P2",
        (0x6A, 0x88): "Referenced data not found",
        }
    def __str__(self):
        msg = Type4TagError.errmsg.get(tuple(self.args[0]), "")
        return "{sw[0]:02X} {sw[1]:02X} {m}".format(sw=self.args[0], m=msg)

class NDEF(tag.NDEF):
    def __init__(self, tag):
        self.tag = tag
        self.data = None
        for name, le in ((ndef_app_file_v2, 0), (ndef_app_file_v1, None)):
            try: tag.select_file(4, 0, name, le)
            except Type4TagError: pass
            else: break
        else:
            raise RuntimeError("ndef application file not found")
            
        try: tag.select_file(0, 0, capability_container)
        except Type4TagError:
            raise RuntimeError("capability container not found")

        self._cc = tag.read_binary(offset=0, count=15)
        log.debug("CC = {0} ({1} bytes)".format(
                str(self._cc).encode("hex"), len(self._cc)))

        if self._cc[0] == 0 and self._cc[1] < 15:
            raise RuntimeError("capability container length below 15")
        if not self._cc[2]>>4 in (1, 2):
            raise RuntimeError("unsupported version " + self.version)
        if not self._cc[7] == 4 and self._cc[8] == 6:
            raise RuntimeError("no ndef file control tlv")

        self._vmajor = self._cc[2] >> 4
        self._vminor = self._cc[2] & 0x0F
        self._max_le = self._cc[3] * 256 + self._cc[4]
        self._max_lc = self._cc[5] * 256 + self._cc[6]
        self._ndef_file_size = self._cc[11] * 256 + self._cc[12]
        ndef_file_id = self._cc[9:11]

        log.debug("Capabilities: Ver={0}.{1}, MLe={2}, MLc={3}".format(
                self._vmajor, self._vminor, self._max_le, self._max_lc))
        
        if self._max_le > 255:
            log.warning("MLe > 255 conflicts with READ_BINARY Le encoding")
            self._max_le = 255
        
        if self._max_lc > 255:
            log.warning("MLc > 255 conflicts with READ_BINARY Le encoding")
            self._max_lc = 255
        
        p2 = 0 if self._vmajor == 1 else 12
        try: tag.select_file(0, p2, ndef_file_id)
        except Type4TagError:
            raise RuntimeError("ndef file not found")

        self.message # force read ndef data

    @property
    def version(self):
        """The version of the NDEF mapping."""
        return "%d.%d" % (self._vmajor, self._vminor)

    @property
    def capacity(self):
        """The maximum number of user bytes on the NDEF tag."""
        return self._ndef_file_size - 2

    @property
    def writeable(self):
        """Is True if new data can be written to the NDEF tag."""
        return self._cc[14] == 0

    @property
    def message(self):
        """A character string containing the NDEF message data."""
        if self.data is None and self._cc[13] == 0:
            data = self.tag.read_binary(0, self._max_le)
            size = data[0] * 256 + data[1] + 2
            tail = max(0, size - len(data))
            while len(data) < size:
                count = min(self._max_lc, size - len(data))
                data += self.tag.read_binary(len(data), count)
            self.data = str(data[2:size])
        return self.data

    @message.setter
    def message(self, data):
        if not self.writeable:
            raise IOError("tag writing disabled")
        if len(data) > self.capacity:
            raise IOError("ndef message exceeds capacity")
        self.data = None
        
        data = bytearray([0,0]) + bytearray(data)
        for offset in range(0, len(data), self._max_lc):
            part = slice(offset, offset + min(self._max_lc, len(data)-offset))
            self.tag.update_binary(offset, data[part])

        ndef_size = [(len(data) - 2) / 256, (len(data) - 2) % 256]
        self.tag.update_binary(0, bytearray(ndef_size))

class Type4Tag(tag.TAG):
    def __init__(self, clf, data):
        self.clf = clf
        self.atq = data["ATQ"]
        self.sak = data["SAK"]
        self.uid = data["UID"]
        self.ats = data["ATS"]
        try: self.miu = (16,24,32,40,48,64,86,128)[self.ats[1] & 0x07]
        except IndexError: self.miu = 256
        self.pni = 0
        try: self._ndef = NDEF(self)
        except Exception as e: log.error(str(e))

    def __str__(self):
        return "Type4Tag ATQ={0:04x} SAK={1:02x} UID={2}, ATS={3}".format(
            self.atq, self.sak, str(self.uid).encode("hex"),
            str(self.ats).encode("hex"))

    def transceive(self, command):
        timeout = 0.5
        for offset in range(0, len(command), self.miu):
            more = len(command) - offset > self.miu
            pfb = (0x02 if not more else 0x12) | self.pni
            data = chr(pfb) + command[offset:offset+self.miu]
            data = self.clf.dev.transceive(data, timeout)
            while data[0] & 0b11111110 == 0b11110010: # WTX
                log.debug("ISO-DEP waiting time extension")
                data = self.clf.dev.transceive(data, timeout)
            if data[0] & 0x01 != self.pni:
                log.error("ISO-DEP protocol error: block number")
                raise IOError("ISO-DEP protocol error: block number")
            if more:
                if data[0] & 0b11111110 == 0b10100010: # ACK
                    self.pni = (self.pni + 1) % 2
                else:
                    log.error("ISO-DEP protocol error: expected ack")
                    raise IOError("ISO-DEP protocol error: expected ack")
            else:
                if data[0] & 0b11101110 == 0b00000010: # INF
                    self.pni = (self.pni + 1) % 2
                    response = data[1:]
                else:
                    log.error("ISO-DEP protocol error: expected inf")
                    raise IOError("ISO-DEP protocol error: expected inf")

        while bool(data[0] & 0b00010000):
            data = chr(0b10100010 | self.pni) # ack
            data = self.clf.dev.transceive(data, timeout)
            if data[0] & 0x01 != self.pni:
                log.error("ISO-DEP protocol error: block number")
                raise IOError("ISO-DEP protocol error: block number")
            response = response + data[1:]
            self.pni = (self.pni + 1) % 2
            
        return response
                
    @property
    def _is_present(self):
        """True if the tag is still within communication range."""
        try:
            self.read_binary(0, 2)
            return True
        except:
            return False

    def select_file(self, p1, p2, data, expected_response_length=None):
        """Select a file or directory with parameters defined in
        ISO/IEC 7816-4"""
        
        log.debug("select file")
        cmd = bytearray([0x00, 0xA4, p1, p2])
        if not data is None:
            cmd += bytearray([len(data)]) + bytearray(data)
        if not expected_response_length is None:
            cmd += bytearray([expected_response_length])
        rsp = self.transceive(cmd)
        if rsp[-2:] != "\x90\x00":
            raise Type4TagError(rsp[-2:])

    def read_binary(self, offset, count):
        """Read *count* bytes from selected file starting at *offset*"""
        log.debug("read binary {0} to {1}".format(offset, offset+count))
        cmd = bytearray([0x00, 0xB0, offset/256, offset%256, count])
        rsp = self.transceive(cmd)
        if rsp[-2:] != "\x90\x00":
            raise Type4TagError(rsp[-2:])
        return rsp[0:-2]

    def update_binary(self, offset, data):
        """Write *data* bytes to selected file starting at *offset*"""
        log.debug("write binary {0} to {1}".format(offset, offset+len(data)))
        cmd = bytearray([0x00, 0xD6, offset/256, offset%256, len(data)])
        cmd = cmd + bytearray(data)
        rsp = self.transceive(cmd)
        if rsp[-2:] != "\x90\x00":
            raise Type4TagError(rsp[-2:])
