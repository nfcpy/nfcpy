# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2014 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
        log.debug("found ndef capability container "
                  + str(self._cc).encode("hex").upper())
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

    @writeable.setter
    def writeable(self, value):
        self._cc[3] = self._cc[3] & 0xF0 if value else self._cc[3] | 0x0F
        with self._tag as tag: tag[15] = self._cc[3]

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

class Type2Tag(nfc.tag.Tag):
    TYPE = "Type2Tag"
    
    def __init__(self, clf, target):
        super(Type2Tag, self).__init__(clf)
        self.atq = target.cfg[0] << 8 | target.cfg[1]
        self.sak = target.cfg[2]
        self.uid = target.uid
        self._usermem = slice(16, 16*4)
        self._mmap = dict()
        self._sync = set()
        self._page = 0

    def __str__(self):
        s = " ATQ={tag.atq:04x} SAK={tag.sak:02x}"
        return nfc.tag.Tag.__str__(self) + s.format(tag=self)

    def __getitem__(self, key):
        if type(key) is int:
            key = slice(key, key+1)
        if not type(key) is slice:
            raise TypeError("key must be of type int or slice")
        if key.start is None:
            key = slice(0, key.stop)
        if key.stop is None:
            key = slice(key.start, self._usermem.stop)

        octets = bytearray(key.stop - key.start)
        for i in xrange(key.start, key.stop):
            try:
                data = self._mmap[i/16]
            except KeyError:
                data = self.read((i/16)*4)
                if data is None:
                    raise IndexError
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
            self.synchronize()
        
    def synchronize(self):
        """Write changed blocks of the internal memory into the tag."""
        log.debug("synchronize blocks {0}".format(tuple(self._sync)))
        for i in sorted(self._sync):
            self.write(i, self._mmap[i/4][(i*4)%16:(i*4)%16+4])
        self._sync.clear()
        self._mmap.clear()
        
    def dump(self):
        ispchr = lambda x: x >= 32 and x <= 126
        oprint = lambda o: ' '.join(['%02x' % x for x in o])
        cprint = lambda o: ''.join([chr(x) if ispchr(x) else '.' for x in o])
        
        header = ("UID0-UID2, BCC0",
                  "UID3-UID6",
                  "BCC1, INT, LOCK0-LOCK1",
                  "OTP0-OTP3")
        
        s = list()
        for i in range(4):
            data = self.read(i)
            if data is None:
                s.append("{0:3}: {1} ({2})".format(
                    i, "?? ?? ?? ??", header[i]))
            else:
                s.append("{0:3}: {1} ({2})".format(
                    i, oprint(data[0:4]), header[i]))
        
        userpages = list()
        for i in range(self._usermem.start/4, self._usermem.stop/4):
            data = self.read(i)
            if data is None:
                unreadable_pages = self._usermem.stop/4 - i
                userpages.extend(["?? ?? ?? ?? |....|"] * unreadable_pages)
                break
            userpages.append("{0} |{1}|".format(
                oprint(data[0:4]), cprint(data[0:4])))

        last_page = None; same_pages = False
        for i, page in enumerate(userpages):
            if page == last_page:
                same_pages = True
                continue
            if same_pages:
                s.append("  *")
                same_pages = False
            s.append(("%3d: " % (i+4)) + page)
            last_page = page
        if same_pages:
            s.append("  *")
            s.append(("%3d: " % (i+4)) + page)
        
        return s

    def _read_ndef(self):
        if self[12] == 0xE1:
            try:
                return NDEF(self)
            except Exception as error:
                log.error("while reading ndef: {0!r}".format(error))
                
    def _is_present(self):
        try:
            return bool(self.read(0))
        except nfc.clf.DigitalProtocolError:
            return False

    def transceive(self, data, timeout=0.1, rlen=None):
        try:
            log.debug(">> " + str(data).encode("hex"))
            data = self.clf.exchange(data, timeout)
            log.debug("<< " + str(data).encode("hex"))
        except nfc.clf.TimeoutError:
            log.debug("timeout error in transceive method")
            raise nfc.clf.TimeoutError("mute tag")

        if rlen is not None and len(data) == rlen + 2:
            if crca(data, rlen) != data[rlen:rlen+2]:
                log.debug("checksum error in received data")
                raise nfc.clf.TransmissionError("wrong crc")
            return data[0:rlen]

        return data
        
    def read(self, block):
        """Read 16-byte of data from the tag. The *block* argument specifies
        the offset in multiples of 4 bytes (i.e. block number 1 will
        return bytes 4 to 19). The data returned is a byte array of
        length 16 or None if the block is outside the readable memory
        range.
        """
        log.debug("read blocks {0}-{1}".format(block, block+3))
        if self._page != block / 256:
            self._page = block / 256
            try:
                rsp = self.transceive("\xC2\xFF")
            except nfc.clf.TimeoutError:
                log.debug("sector select part 1 failed with timeout")
                return None
            if not (len(rsp) == 1 and rsp[0] == 0x0A):
                log.debug("sector select part 1 not acknowledged")
                return None
            try:
                rsp = self.transceive(chr(self._page)+"\0\0\0", timeout=0.001)
                log.debug("this block seems not be addressable")
                return None
            except nfc.clf.TimeoutError:
                pass
            
        data = self.transceive("\x30" + chr(block % 256), rlen=16)
        if len(data) != 16:
            if len(data) == 1 and data[0] == 0x00:
                log.debug("received nak response")
                self.clf.sense([nfc.clf.TTA(uid=self.uid)])
                self.clf.set_communication_mode('', check_crc='OFF')
            else:
                log.debug("invalid response " + str(data).encode("hex"))
            return None

        log.debug(' '.join([str(data[i:i+4]).encode("hex") \
                            for i in range(0, 16, 4)]))
        return data

    def write(self, block, data):
        """Write 4-byte of data to the tag. The *block* argument
        specifies the offset in multiples of 4 bytes. The *data*
        argument must be a string or bytearray of length 4.
        """
        log.debug("write {0!r} to block {1}".format(
            str(data).encode("hex"), block))
        assert(len(data) == 4)
        
        if not self._page == block / 256:
            self._page = block / 256
            rsp = self.transceive("\xC2\xFF")
            if not (len(rsp) == 1 and rsp[0] == 0x0A):
                raise nfc.clf.ProtocolError("9.8.3.1")
            try: self.transceive(chr(self._page) + 3*chr(0), timeout=0.001)
            except nfc.clf.TimeoutError: pass
            else: raise nfc.clf.ProtocolError("9.8.3.3")

        try:
            rsp = self.transceive("\xA2" + chr(block % 256) + data)
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
