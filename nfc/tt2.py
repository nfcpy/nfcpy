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

import logging
log = logging.getLogger(__name__)

import tag

class NDEF(tag.NDEF):
    def __init__(self, tag):
        self._tag = tag
        self._msg = None
        self._cc = tag[12:16]
        if not self._cc[0] == 0xE1:
            raise ValueError("wrong ndef magic number")
        if not self._cc[3] & 0xF0 == 0:
            raise ValueError("no read permissions for ndef container")
        log.debug("tag memory dump:\n" + format_data(tag[0:16+self._cc[2]*8]))
        self._skip = set([])
        offset = 16
        while offset is not None:
            offset = self._read_tlv(offset)

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
        if self._capacity > 254:
            # needs 2 more tlv length byte
            self._capacity -= 2
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
    def writeable(self):
        """Is True if new data can be written to the NDEF tag."""
        return self._cc[3] == 0x00

    @property
    def message(self):
        """A character string containing the NDEF message data."""
        return str(self._msg)

    @message.setter
    def message(self, data):
        if not self.writeable:
            raise IOError("tag writing disabled")
        if len(data) > self.capacity:
            raise IOError("ndef message beyond tag capacity")
        self._msg = bytearray(data)
        if len(data) < self.capacity:
            data = data + "\xFE"
        data = bytearray(data)       
        with self._tag as tag:
            offset = self._ndef_tlv_offset + 1
            tag[offset] = 0
            offset += 1 if len(self._msg) < 255 else 3
            for octet in data:
                while offset in self._skip:
                    offset += 1
                tag[offset] = octet
                offset += 1
        with self._tag as tag:
            offset = self._ndef_tlv_offset + 1
            if len(self._msg) < 255:
                tag[offset] = len(self._msg)
            else:
                tag[offset] = 255
                tag[offset+1] = len(self._msg) / 256
                tag[offset+2] = len(self._msg) % 256

class Type2Tag(tag.TAG):
    def __init__(self, dev, data):
        self.dev = dev
        self.atq = data["ATQ"]
        self.sak = data["SAK"]
        self.uid = bytearray(data["UID"])
        self._mmap = dict()
        self._sync = set()
        self._page = 0
        try: self._ndef = NDEF(self)
        except Exception as e:
            log.error("while reading ndef: " + str(e))

    def __str__(self):
        s = "Type2Tag ATQ={0:04x} SAK={1:02x} UID={2}"
        return s.format(self.atq, self.sak, str(self.uid).encode("hex"))

    def __getitem__(self, key):
        if type(key) is type(int()):
            key = slice(key, key+1)
        if not type(key) is type(slice(1)):
            raise TypeError("key must be of type int or slice")
        bytes = bytearray(key.stop - key.start)
        for i in xrange(key.start, key.stop):
            data = self._mmap.get(i/16, None)
            if data is None:
                data = self.read((i/16)*4)
                self._mmap[i/16] = data
            bytes[i-key.start] = data[i%16]
        return bytes if len(bytes) > 1 else bytes[0]
        
    def __setitem__(self, key, value):
        if type(key) is type(int()):
            key = slice(key, key+1)
        if type(key) is not type(slice(1)):
            raise TypeError("key must be of type int or slice")
        if type(value) == type(int()):
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
        
    @property
    def _is_present(self):
        """Returns True if the tag is still within communication range."""
        try: return bool(self.read(0))
        except IOError: return False

    def read(self, block):
        """Read 16-byte of data from the tag. The *block* argument
        specifies the offset in multiples of 4 bytes (i.e. block
        number 1 will return bytes 4 to 19). The data returned is a
        byte array of length 16.
        """
        log.debug("read block #{0}".format(block))
        if not self._page == block / 256:
            self._page = block / 256
            self.dev.tt2_exchange("\xC2\xFF")
            self.dev.tt2_exchange(chr(self._page) + 3 * "\x00")
            block = block % 256
        return bytearray(self.dev.tt2_exchange("\x30" + chr(block)))

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
            self.dev.tt2_exchange("\xC2\xFF")
            self.dev.tt2_exchange(chr(self._page) + 3 * "\x00")
            block = block % 256
        return self.dev.tt2_exchange("\xA2" + chr(block) + str(data))

def format_data(data):
    if type(data) is not type(str()):
        data = str(data)
    import string
    printable = string.digits + string.letters + string.punctuation + ' '
    s = []
    for i in range(0, len(data), 16):
        s.append("  {offset:04x}: ".format(offset=i))
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += ''.join([c if c in printable else '.' for c in data[i:i+16]])
    return '\n'.join(s)
