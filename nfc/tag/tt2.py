# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import nfc.tag
import nfc.clf
import nfc.ndef

class NDEF(object):
    def __init__(self, tag):
        self._tag = tag
        self._cc = tag[12:16]
        log.debug("capability container " + str(self._cc).encode("hex"))
        self._skip = set([])
        self._msg = bytearray()
        self.changed # force initial read

    def _read_tlv(self, offset):
        read_tlv = {
            0x00: lambda x: x + 1,
            0x01: self._read_lock_tlv,
            0x02: self._read_memory_tlv,
            0x03: self._read_ndef_tlv,
            0xFE: lambda x: None
            }.get(self._tag[offset], self._read_unknown_tlv)
        return read_tlv(offset + 1)

    def _read_unknown_tlv(self, offset):
        length, offset = self._read_tlv_length(offset)
        return offset + length
        
    def _read_ndef_tlv(self, offset):
        self._ndef_tlv_offset = offset - 1
        length, offset = self._read_tlv_length(offset)
        self._capacity = 16 + self._cc[2] * 8 - offset - len(self._skip)
        if length < 255 and self._capacity >= 255:
            self._capacity -= 2 # account for three byte length format
        self._msg = bytearray()
        while length > 0:
            if not offset in self._skip:
                self._msg.append(self._tag[offset])
            offset += 1; length -= 1
        return None
    
    def _read_lock_tlv(self, offset):
        length, offset = self._read_tlv_length(offset)
        value = self._tag[offset:offset+length]
        page_offs = value[0] >> 4
        byte_offs = value[0] & 0x0F
        resv_size = ((value[1] - 1) / 8) + 1
        page_size = 2 ** (value[2] & 0x0F)
        resv_start = page_offs * page_size + byte_offs
        self._skip.update(range(resv_start, resv_start + resv_size))
        return offset + length

    def _read_memory_tlv(self, offset):
        length, offset = self._read_tlv_length(offset)
        value = self._tag[offset:offset+length]
        page_offs = value[0] >> 4
        byte_offs = value[0] & 0x0F
        resv_size = value[1]
        page_size = 2 ** (value[2] & 0x0F)
        resv_start = page_offs * page_size + byte_offs
        self._skip.update(range(resv_start, resv_start + resv_size))
        return offset + length

    def _read_tlv_length(self, offset):
        length = self._tag[offset]
        if length == 255:
            length = self._tag[offset+1] * 256 + self._tag[offset+2];
            offset = offset + 2
            if length < 256 or length == 0xFFFF:
                raise ValueError("invalid tlv lenght value")
        return length, offset + 1
        
    @property
    def version(self):
        """The version of the NDEF mapping."""
        return "%d.%d" % (self._cc[1]>>4, self._cc[1]&0x0F)

    @property
    def capacity(self):
        """The maximum number of user bytes on the NDEF tag."""
        return self._capacity

    @property
    def readable(self):
        """Is True if data can be read from the NDEF tag."""
        return self._cc[3] & 0xF0 == 0x00

    @property
    def writeable(self):
        """Is True if data can be written to the NDEF tag."""
        return self._cc[3] & 0x0F == 0x00

    @property
    def length(self):
        """NDEF message data length."""
        return len(self._msg)
        
    @property
    def changed(self):
        """True if the message has changed since the read."""
        if self.readable:
            old_msg = self._msg[:] # make a copy
            offset = 16
            while offset is not None:
                offset = self._read_tlv(offset)
            return self._msg != old_msg
        return False

    @property
    def message(self):
        """An NDEF message object (an empty record message if tag is empty)."""
        if self.readable:
            try: return nfc.ndef.Message(str(self._msg))
            except nfc.ndef.parser_error: pass
        return nfc.ndef.Message(nfc.ndef.Record())

    @message.setter
    def message(self, msg):
        if not self.writeable:
            raise nfc.tag.AccessError
        data = bytearray(str(msg))
        nlen = len(data)
        if nlen > self.capacity:
            raise nfc.tag.CapacityError
        if nlen < self.capacity:
            data = data + "\xFE"
        with self._tag as tag:
            offset = self._ndef_tlv_offset + 1
            tag[offset] = 0
            offset += 1 if len(data) < 255 else 3
            for octet in data:
                while offset in self._skip:
                    offset += 1
                tag[offset] = octet
                offset += 1
        with self._tag as tag:
            offset = self._ndef_tlv_offset + 1
            if len(data) < 255:
                tag[offset] = nlen
            else:
                tag[offset] = 255
                tag[offset+1] = nlen / 256
                tag[offset+2] = nlen % 256

class Type2Tag(object):
    type = "Type2Tag"
    
    def __init__(self, clf, target):
        clf.set_communication_mode('', check_crc='OFF')
        self.clf = clf
        self.atq = target.cfg[0] << 8 | target.cfg[1]
        self.sak = target.cfg[2]
        self.uid = target.uid
        self._mmap = dict()
        self._sync = set()
        self._page = 0
        self.ndef = None
        if self[12] == 0xE1:
            try: self.ndef = NDEF(self)
            except Exception as error:
                log.error("while reading ndef: {0!r}".format(error))

    def __str__(self):
        s = "Type2Tag ATQ={0:04x} SAK={1:02x} UID={2}"
        return s.format(self.atq, self.sak, str(self.uid).encode("hex"))

    def __getitem__(self, key):
        if type(key) is int:
            key = slice(key, key+1)
        if not type(key) is slice:
            raise TypeError("key must be of type int or slice")
        octets = bytearray(key.stop - key.start)
        for i in xrange(key.start, key.stop):
            data = self._mmap.get(i/16, None)
            if data is None:
                data = self.read((i/16)*4)
                self._mmap[i/16] = data
            octets[i-key.start] = data[i%16]
        return octets if len(octets) > 1 else octets[0]
        
    def __setitem__(self, key, value):
        if type(key) is int:
            key = slice(key, key+1)
        if type(key) is not slice:
            raise TypeError("key must be of type int or slice")
        if type(value) == int:
            value = bytearray([value])
        else:
            value = bytearray(value)
        if len(value) != key.stop - key.start:
            raise ValueError("value and slice length must be equal")
        for i in xrange(key.start, key.stop):
            data = self._mmap.get(i/16, None)
            if data is None:
                data = self.read((i/16)*4)
                self._mmap[i/16] = data
            data[i%16] = value[i-key.start]
            self._sync.add(i/4)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            for i in sorted(self._sync):
                self.write(i, self._mmap[i/4][(i*4)%16:(i*4)%16+4])
            self._sync.clear()
            self._mmap.clear()
        
    @property
    def is_present(self):
        """Returns True if the tag is still within communication range."""
        try: return bool(self.read(0))
        except nfc.clf.DigitalProtocolError: return False

    def transceive(self, data, timeout=0.1):
        return self.clf.exchange(data, timeout)

    def read(self, block):
        """Read 16-byte of data from the tag. The *block* argument
        specifies the offset in multiples of 4 bytes (i.e. block
        number 1 will return bytes 4 to 19). The data returned is a
        byte array of length 16.
        """
        log.debug("read block #{0}".format(block))
        if self._page != block / 256:
            self._page = block / 256
            rsp = self.transceive("\xC2\xFF")
            if not (len(rsp) == 1 and rsp[0] == 0x0A):
                raise nfc.clf.ProtocolError("9.8.3.1")
            try: self.transceive(chr(self._page) + 3*chr(0), timeout=0.001)
            except nfc.clf.TimeoutError: pass
            else: raise nfc.clf.ProtocolError("9.8.3.3")
            
        try:
            rsp = self.transceive("\x30" + chr(block % 256))
        except nfc.clf.TimeoutError:
            raise nfc.clf.TimeoutError("9.9.1.3")
        
        if len(rsp) == 16 or (len(rsp) == 18 and crca(rsp, 16) == rsp[16:18]):
            return rsp[0:16]
        if len(rsp) == 18:
            raise nfc.clf.TransmissionError("4.4.1.3")
        if len(rsp) == 1 and rsp[0] != 0x0A:
            raise nfc.clf.ProtocolError("9.6.2.3")
        raise nfc.clf.ProtocolError("9.6.2")

    def write(self, block, data):
        """Write 4-byte of data to the tag. The *block* argument
        specifies the offset in multiples of 4 bytes. The *data*
        argument must be a string or bytearray of length 4.
        """
        log.debug("write block #{0}".format(block))
        assert(len(data) == 4)
        assert(block > 3)
        if not self._page == block / 256:
            self._page = block / 256
            rsp = self.transceive("\xC2\xFF")
            if not (len(rsp) == 1 and rsp[0] == 0x0A):
                raise nfc.clf.ProtocolError("9.8.3.1")
            try: self.transceive(chr(self._page) + 3*chr(0), timeout=0.001)
            except nfc.clf.TimeoutError: pass
            else: raise nfc.clf.ProtocolError("9.8.3.3")

        try:
            rsp = self.transceive("\xA2" + chr(block % 256) + str(data))
        except nfc.clf.TimeoutError:
            raise nfc.clf.TimeoutError("9.9.1.3")
        
        if (len(rsp) == 1 and rsp[0] == 0x0A) or (len(rsp) == 0):
            # Case 1 is for readers who return the ack/nack.
            # Case 2 is for readers who process the response.
            return True
        if len(rsp) == 1:
            raise nfc.clf.ProtocolError("9.7.2.1")
        raise nfc.clf.ProtocolError("9.7.2")

def crca(data, size):
    reg = 0x6363
    for octet in bytearray(data[:size]):
        for pos in range(8):
            bit = (reg ^ ((octet >> pos) & 1)) & 1
            reg = reg >> 1
            if bit: reg = reg ^ 0x8408
    return bytearray([reg & 0xff, reg >> 8])
