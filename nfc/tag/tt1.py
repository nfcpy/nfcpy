# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011-2014
#   Stephen Tiedemann <stephen.tiedemann@gmail.com>
#   Alexander Knaub <sanyok.og@googlemail.com>
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

from struct import pack, unpack
from binascii import hexlify
import time

from nfc.tag import Tag, TagCommandError
import nfc.clf

TIMEOUT_ERROR, CHECKSUM_ERROR, RESPONSE_ERROR, ADDRESS_ERROR, \
    BLOCK_ERROR, SECTOR_ERROR = range(6)

class Type1TagCommandError(TagCommandError):
    """Type 1 Tag specific exceptions. Sets 
    :attr:`~nfc.tag.TagCommandError.errno` to one of:
    
    | 1 - CHECKSUM_ERROR
    | 2 - RESPONSE_ERROR
    | 3 - ADDRESS_ERROR
    | 4 - BLOCK_ERROR
    | 5 - SECTOR_ERROR

    """
    errno_str = {
        CHECKSUM_ERROR: "crc validation failed",
        RESPONSE_ERROR: "invalid response data",
        ADDRESS_ERROR: "invalid byte address",
        BLOCK_ERROR: "invalid block number",
        SECTOR_ERROR: "invalid sector number",
    }

def read_tlv(memory, offset, skip_bytes):
    # Unpack a Type 2 Tag TLV from tag memory and return tag type, tag
    # length and tag value. For tag type 0 there is no length field,
    # this is returned as length -1. The tlv length field can be one
    # or three bytes, if the first byte is 255 then the next two byte
    # carry the length (big endian).
    tlv_t, offset = (memory[offset], offset+1)
    if tlv_t in (0x00, 0xFE): return (tlv_t, -1, None)
    tlv_l, offset = (memory[offset], offset+1)
    if tlv_l == 0xFF:
        tlv_l, offset = (unpack(">H", memory[offset:offset+2])[0], offset+2)
    tlv_v = bytearray(tlv_l)
    for i in xrange(tlv_l):
        while (offset + i) in skip_bytes:
            offset += 1
        tlv_v[i] = memory[offset+i]
    return (tlv_t, tlv_l, tlv_v)

def get_lock_byte_range(data):
    # Extract the lock byte range indicated by a Lock Control TLV. The
    # data argument is the TLV value field.
    page_addr = data[0] >> 4
    byte_offs = data[0] & 0x0F
    rsvd_size = ((data[1] if data[1] > 0 else 256) + 7) // 8
    page_size = 2 ** (data[2] & 0x0F)
    rsvd_from = page_addr * page_size + byte_offs
    return slice(rsvd_from, rsvd_from + rsvd_size)

def get_rsvd_byte_range(data):
    # Extract the reserved memory range indicated by a Memory Control
    # TLV. The data argument is the TLV value field.
    page_addr = data[0] >> 4
    byte_offs = data[0] & 0x0F
    rsvd_size = data[1] if data[1] > 0 else 256
    page_size = 2 ** (data[2] & 0x0F)
    rsvd_from = page_addr * page_size + byte_offs
    return slice(rsvd_from, rsvd_from + rsvd_size)

def get_capacity(tag_memory_size, offset, skip_bytes):
    # The net capacity is the range of bytes from the current offset
    # until the end of user data bytes (given by the capability
    # container capacity value plus 16 header bytes), reduced by the
    # number of skip bytes (from memory and lock control TLVs) that
    # are within the usable memory range, and adjusted by the required
    # number of TLV length bytes (1 or 3) and the TLV tag byte.
    log.debug("subtract {0} skip bytes from capacity".format(len(skip_bytes)))
    capacity = len(set(range(offset, tag_memory_size)) - skip_bytes)
    # To store more than 254 byte ndef we must use three length bytes,
    # otherwise it's only one. But only if the capacity is more than
    # 256 the three length byte format will provide a higher value.
    capacity -= 4 if capacity > 256 else 2
    return capacity

class Type1Tag(Tag):
    TYPE = "Type1Tag"

    class NDEF(Tag.NDEF):
        # Type 1 Tag specific implementation of the NDEF access type
        # class that is returned by the Tag.ndef attribute.
        
        def __init__(self, tag):
            self._ndef_tlv_offset = 0
            super(Type1Tag.NDEF, self).__init__(tag)

        def _read_ndef_data(self):
            log.debug("read ndef data")
            tag_memory = Type1TagMemoryReader(self._tag)

            if tag_memory[9] >> 4 != 1:
                log.debug("unsupported ndef mapping major version")
                return bytearray()

            self._readable = bool(tag_memory[11] >> 4 == 0)
            self._writeable = bool(tag_memory[11] & 0xF == 0)
            
            tag_memory_size = (tag_memory[10] + 1) * 8
            log.debug("tag memory size is {0} byte".format(tag_memory_size))

            ndef = None
            offset = 12
            skip_bytes = set(range(104, 120 if tag_memory_size==120 else 128))
            while offset < tag_memory_size:
                tlv_t, tlv_l, tlv_v = read_tlv(tag_memory, offset, skip_bytes)
                log.debug("tlv type {0} at address {1}".format(tlv_t, offset))
                if tlv_t == 0xFE: break
                elif tlv_t == 0x01:
                    lock_bytes = get_lock_byte_range(tlv_v)
                    skip_bytes.update(range(*lock_bytes.indices(0x100000)))
                elif tlv_t == 0x02:
                    rsvd_bytes = get_rsvd_byte_range(tlv_v)
                    skip_bytes.update(range(*rsvd_bytes.indices(0x100000)))
                elif tlv_t == 0x03:
                    ndef = tlv_v; break
                else:
                    logmsg = "unknown tlv {0} at offset {0}"
                    log.debug(logmsg.format(tlv_t, offset))
                offset += tlv_l + 1 + (1 if tlv_l < 255 else 3)

            self._capacity = get_capacity(tag_memory_size, offset, skip_bytes)
            self._ndef_tlv_offset = offset
            self._tag_memory = tag_memory
            self._skip_bytes = skip_bytes
            return ndef

        def _write_ndef_data(self, data):
            log.debug("write ndef data {0}...".format(hexlify(data[:10])))
            
            if self._ndef_tlv_offset == 0:
                self._read_ndef_data()
            
            tag_memory = self._tag_memory
            skip_bytes = self._skip_bytes
            offset = self._ndef_tlv_offset
            tag_memory_size = (tag_memory[10] + 1) * 8
            
            # Set the ndef message tlv length to 0.
            tag_memory[offset+1] = 0
            tag_memory.synchronize()
            
            # Leave room for ndef message length byte(s) and write
            # ndef data into the memory image, but jump over skip
            # bytes.
            offset += 2 if len(data) < 255 else 4
            for i in xrange(len(data)):
                while offset + i in skip_bytes: offset += 1
                tag_memory[offset+i] = data[i]
            # Write a terminator tlv if space permits. We may have to
            # skip reserved and lock bytes.
            offset = offset + i + 1
            while offset < tag_memory_size:
                if offset not in skip_bytes:
                    tag_memory[offset] = 0xFE
                    break
                offset += 1
            # Write the new message data to the tag.
            tag_memory.synchronize()
            
            # Write the ndef message tlv length.
            offset = self._ndef_tlv_offset
            if len(data) < 255:
                tag_memory[offset+1] = len(data)
            else:
                tag_memory[offset+1] = 0xFF
                tag_memory[offset+2:offset+4] = pack(">H", len(data))
            tag_memory.synchronize()

    #
    # Type1Tag methods and attributes
    #
    def __init__(self, clf, target):
        super(Type1Tag, self).__init__(clf)
        self.uid = target.uid

    def dump(self):
        return self._dump(stop=None)
        
    def _dump(self, stop=None):
        ispchr = lambda x: x >= 32 and x <= 126
        oprint = lambda o: ' '.join(['??' if x < 0 else '%02x'%x for x in o])
        cprint = lambda o: ''.join([chr(x) if ispchr(x) else '.' for x in o])
        lprint = lambda fmt, d, i: fmt.format(i, oprint(d), cprint(d))
        
        lines = list()

        data = self.read_all()
        hrom, data = data[0:2], data[2:]

        txt = ["UID0-UID6, RESERVED", "RESERVED", "LOCK0-LOCK1, OTP0-OTP5"]
        
        lines.append("HR0={0:02X}h, HR1={1:02X}h".format(*hrom))
        lines.append("  0: {0} ({1})".format(oprint(data[0:8]), txt[0]))
        for i in xrange(8, 104, 8):
            lines.append(lprint("{0:3}: {1} |{2}|", data[i:i+8], i//8))
        lines.append(" 13: {0} ({1})".format(oprint(data[104:112]), txt[1]))
        lines.append(" 14: {0} ({1})".format(oprint(data[112:120]), txt[2]))

        for i in range (16):
            self.read_segment(i)

        for i in (0,): #xrange(15, 256):
            try: data = self.read_block(i)
            except Type1TagCommandError: break

        return lines
        
        header = ("UID0-UID6", "UID3-UID6",
                  "BCC1, INT, LOCK0-LOCK1", "OTP0-OTP3")

        for i, txt in enumerate(header):
            try: data = oprint(self.read(i)[0:4])
            except Type2TagCommandError: data = "?? ?? ?? ??"
            lines.append("{0:3}: {1} ({2})".format(i, data, txt))

        data_line_fmt = "{0:>3}: {1} |{2}|"
        same_line_fmt = "{0:>3}  {1} |{2}|"
        same_data = 0; this_data = last_data = None

        def dump_same_data(same_data, last_data, this_data, page):
            if same_data > 1:
                lines.append(lprint(same_line_fmt, last_data, "*"))
            if same_data > 0:
                lines.append(lprint(data_line_fmt, this_data, page))
            
        for i in xrange(4, stop if stop is not None else 0x40000):
            try:
                self.sector_select(i>>8)
                this_data = self.read(i)[0:4]
            except Type2TagCommandError:
                dump_same_data(same_data, last_data, this_data, i-1)
                if stop is not None:
                    this_data = last_data = [None, None, None, None]
                    lines.append(lprint(data_line_fmt, this_data, i))
                    dump_same_data(stop-i-1, this_data, this_data, stop-1)
                break
            
            if this_data == last_data:
                same_data += 1
            else:
                dump_same_data(same_data, last_data, last_data, i-1)
                lines.append(lprint(data_line_fmt, this_data, i))
                last_data = this_data; same_data = 0
        else:
            dump_same_data(same_data, last_data, this_data, i)

        return lines

    def _read_ndef(self):
        # Read ndef data if present. The presence of ndef data is
        # indicated by the existence of a capability container. The
        # first byte of the capability container must be 0xE1. Further
        # checks are not available, but inconsitent data may be
        # spotted when the NDEF object is initialized.
        try:
            if self.read_id()[0]>>4 == 1 and self.read_byte(8) == 0xE1:
                return self.NDEF(self)
        except Type1TagCommandError:
            pass
        except Exception as error: # should be more specific
            log.error(str(error))
                
    def _is_present(self):
        try: data = self.transceive("\x78\x00\x00"+self.uid)
        except nfc.clf.DigitalProtocolError: return False
        else: return bool(data and len(data) == 6)

    def read_id(self):
        """Read header rom and all static memory bytes (blocks 0-14).
        """
        log.debug("read identification")
        cmd = "\x78\x00\x00\x00\x00\x00\x00"
        return self.transceive(cmd)

    def read_all(self):
        """Read header rom and all static memory bytes (blocks 0-14).
        """
        log.debug("read all static memory")
        cmd = "\x00\x00\x00" + self.uid
        return self.transceive(cmd)

    def read_byte(self, addr):
        """Read a single byte from static memory area (blocks 0-14).
        """
        log.debug("read byte at address {0} ({0:02X}h)".format(addr))
        cmd = "\x01" + chr(addr) + "\x00" + self.uid
        return self.transceive(cmd)[-1]

    def read_block(self, block):
        """Read an 8-byte data block at address (block * 8).
        """
        log.debug("read block {0}".format(block))
        cmd = "\x02" + chr(block) + 8 * chr(0) + self.uid
        return self.transceive(cmd)[1:9]

    def read_segment(self, segment):
        """Read one memory segment (128 byte).
        """
        log.debug("read segment {0}".format(segment))
        if segment < 0 or segment > 15:
            raise ValueError("segment number must be 0 .. 15")
        cmd = "\x10" + chr(segment<<4) + 8 * chr(0) + self.uid
        return self.transceive(cmd)[1:129]

    def write_byte(self, addr, data, erase=True):
        """Write a single byte to static memory area (blocks 0-14).
        The target byte is zero'd first if 'erase' is True (default).
        """
        log.debug("write byte at address {0} ({0:02X}h)".format(addr))
        cmd = "\x53" if erase is True else "\x1A"
        cmd = cmd + chr(addr) + chr(data) + self.uid
        return self.transceive(cmd)

    def write_block(self, block, data, erase=True):
        """Write an 8-byte data block at address (block * 8).
        The target bytes are zero'd first if 'erase' is True (default).
        """
        log.debug("write block {0}".format(block))
        cmd = "\x54" if erase is True else "\x1B"
        cmd = cmd + chr(block) + data + self.uid
        return self.transceive(cmd)

    def transceive(self, data, timeout=0.1):
        started = time.time()
        log.debug(">> {0} ({1:f}s)".format(hexlify(data), timeout))

        try:
            data = self.clf.exchange(data, timeout)
        except nfc.clf.TimeoutError:
            raise Type1TagCommandError(TIMEOUT_ERROR)
        
        elapsed = time.time() - started
        log.debug("<< {0} ({1:f}s)".format(hexlify(data), elapsed))
        return data

class Type1TagMemoryReader(object):
    def __init__(self, tag):
        assert isinstance(tag, Type1Tag)
        self._data_from_tag = bytearray()
        self._data_in_cache = bytearray()
        self._tag = tag

    def __len__(self):
        return len(self._data_from_tag)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(0x100000)
            if stop > len(self):
                self._read_from_tag(stop)
        elif key >= len(self):
            self._read_from_tag(stop=key+1)
        return self._data_in_cache[key]

    def __setitem__(self, key, value):
        self.__getitem__(key)
        if isinstance(key, slice):
            if len(value) != len(xrange(*key.indices(0x100000))):
                msg = "{cls} requires item assignment of identical length"
                raise ValueError(msg.format(cls=self.__class__.__name__))
        self._data_in_cache[key] = value
        del self._data_in_cache[len(self):]

    def __delitem__(self, key):
        msg = "{cls} object does not support item deletion"
        raise TypeError(msg.format(cls=self.__class__.__name__))

    def _read_from_tag(self, stop):
        if len(self) < 120:
            self._data_from_tag[0:] = self._tag.read_all()[2:]
            self._data_in_cache[0:] = self._data_from_tag[0:]
        if stop > 120 and len(self) < 128:
            self._data_from_tag[120:128] = self._tag.read_block(15)
            self._data_in_cache[120:128] = self._data_from_tag[120:128]
        while len(self) < stop:
            data = self._tag.read_segment(len(self)>>7)
            if len(data) == 128:
                self._data_from_tag.extend(data)
                self._data_in_cache.extend(data)
            else: break

    def _write_to_tag(self, stop):
        try:
            hr0 = self._tag.read_id()[0]
            if hr0 >> 4 == 1 and hr0 & 0x0F != 1:
                for i in xrange(0, stop, 8):
                    data = self._data_in_cache[i:i+8]
                    if data != self._data_from_tag[i:i+8]:
                        self._tag.write_block(i//8, data)
                        self._data_from_tag[i:i+8] = data
            else:
                for i in xrange(0, stop):
                    data = self._data_in_cache[i]
                    if data != self._data_from_tag[i]:
                        self._tag.write_byte(i, data)
                        self._data_from_tag[i] = data
        except Type1TagCommandError as error:
            log.error(str(error))
            pass

    def synchronize(self):
        """Write pages that contain modified data back to tag memory."""
        self._write_to_tag(stop=len(self))

