# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011, 2017
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
import time
from binascii import hexlify
from struct import pack, unpack

from . import Tag, TagCommandError
import nfc.clf

import logging
log = logging.getLogger(__name__)


CHECKSUM_ERROR, RESPONSE_ERROR, WRITE_ERROR, \
    BLOCK_ERROR, SECTOR_ERROR = range(1, 6)


class Type1TagCommandError(TagCommandError):
    """Type 1 Tag specific exceptions. Sets
    :attr:`~nfc.tag.TagCommandError.errno` to one of:

    | 1 - CHECKSUM_ERROR
    | 2 - RESPONSE_ERROR
    | 3 - WRITE_ERROR

    """
    errno_str = {
        CHECKSUM_ERROR: "crc validation failed",
        RESPONSE_ERROR: "invalid response data",
        WRITE_ERROR: "data write failure",
    }


def read_tlv(memory, offset, skip_bytes):
    # Unpack a TLV from tag memory and return tag type, tag length and
    # tag value. For tag type 0 there is no length field, this is
    # returned as length -1. The tlv length field can be one or three
    # bytes, if the first byte is 255 then the next two byte carry the
    # length (big endian).
    try:
        tlv_t, offset = (memory[offset], offset+1)
    except Type1TagCommandError:
        return (None, None, None)

    if tlv_t in (0x00, 0xFE):
        return (tlv_t, -1, None)

    tlv_l, offset = (memory[offset], offset+1)

    if tlv_l == 0xFF:
        tlv_l, offset = (unpack(">H", memory[offset:offset+2])[0], offset+2)

    tlv_v = bytearray(tlv_l)
    for i in range(tlv_l):
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
    """Implementation of the NFC Forum Type 1 Tag Operation specification.

    The NFC Forum Type 1 Tag is based on the ISO 14443 Type A
    technology for frame structure and anticollision (detection)
    commands, and the Innovision (now Broadcom) Jewel/Topaz commands
    for accessing the tag memory.

    """
    TYPE = "Type1Tag"

    class NDEF(Tag.NDEF):
        # Type 1 Tag specific implementation of the NDEF access type
        # class that is returned by the Tag.ndef attribute.

        def __init__(self, tag):
            super(Type1Tag.NDEF, self).__init__(tag)
            self._ndef_tlv_offset = 0

        def _read_ndef_data(self):
            # Check and read ndef data from tag. Return None if the
            # tag is not ndef formatted, i.e. it can not hold ndef
            # data or does not have (valid) ndef management data.
            # Otherwise, set state variables and return the ndef
            # message data as a bytearray (may be zero length).
            log.debug("read ndef data")
            try:
                tag_memory = Type1TagMemoryReader(self.tag)

                if tag_memory._header_rom[0] >> 4 != 1:
                    log.debug("proprietary type 1 tag memory structure")
                    return None

                if tag_memory[8] != 0xE1:
                    log.debug("ndef management data is not present")
                    return None

                if tag_memory[9] >> 4 != 1:
                    log.debug("unsupported ndef mapping version")
                    return None

                self._readable = bool(tag_memory[11] >> 4 == 0)
                self._writeable = bool(tag_memory[11] & 0xF == 0)

                tag_memory_size = (tag_memory[10] + 1) * 8
                log.debug("tag memory size is %d byte" % tag_memory_size)
            except Type1TagCommandError:
                log.debug("header rom and static memory were unreadable")
                return None

            ndef = None
            offset = 12
            skip_end = 120 if tag_memory_size == 120 else 128
            skip_bytes = set(range(104, skip_end))
            while offset < tag_memory_size:
                if offset in skip_bytes:
                    offset += 1
                    continue

                tlv_t, tlv_l, tlv_v = read_tlv(tag_memory, offset, skip_bytes)
                log.debug("tlv type {0} at address {1}".format(tlv_t, offset))

                if tlv_t == 0x00:
                    pass
                elif tlv_t == 0x01:
                    lock_bytes = get_lock_byte_range(tlv_v)
                    skip_bytes.update(range(*lock_bytes.indices(0x800)))
                elif tlv_t == 0x02:
                    rsvd_bytes = get_rsvd_byte_range(tlv_v)
                    skip_bytes.update(range(*rsvd_bytes.indices(0x800)))
                elif tlv_t == 0x03:
                    ndef = tlv_v
                    break
                elif tlv_t == 0xFE or tlv_t is None:
                    break
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
            log.debug("write ndef data {0}{1}".format(
                hexlify(data[:10]).decode(), '...' if len(data) > 10 else ''))

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
            for i in range(len(data)):
                while offset + i in skip_bytes:
                    offset += 1
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
        super(Type1Tag, self).__init__(clf, target)
        self._nfcid = self.uid = target.rid_res[2:6]

    def dump(self):
        """Returns the tag memory blocks as a list of formatted strings.

        :meth:`dump` iterates over all tag memory blocks (8 bytes
        each) from block zero until the physical end of memory and
        produces a list of strings that is intended for line by line
        printing. Multiple consecutive memory block of identical
        content may be reduced to fewer lines of output, so the number
        of lines returned does not necessarily correspond to the
        number of memory blocks present.

        .. warning:: For tags with more than 120 byte memory, the
            dump() method first overwrites the data block to verify
            that it is backed by physical memory, then restores the
            original data. This is necessary because Type 1 Tags do
            not indicate an error when reading beyond the physical
            memory space. Be cautious to not remove a tag from the
            reader when using dump() as otherwise your data may be
            corrupted.

        """
        return self._dump(stop=None)

    def _dump(self, stop=None):
        # Read and print all data blocks until the non-inclusive stop
        # block number. Type 1 Tags with dynamic memory seem to return
        # data for every address, regardless of whether there is
        # memory mapped or not. To show exactly the memory blocks that
        # are physically present, blocks from 16-end are first
        # overwritten with an inverted version of the content and then
        # recovered. Because WRITE8 returns the new data content, a
        # non-existing block can be detected.

        def oprint(octets):
            return ' '.join(['??' if x < 0 else '%02x' % x for x in octets])

        def cprint(octets):
            return ''.join([chr(x) if 32 <= x <= 126 else '.' for x in octets])

        def lprint(fmt, d, i):
            return fmt.format(i, oprint(d), cprint(d))

        txt = ["UID0-UID6, RESERVED", "RESERVED", "LOCK0-LOCK1, OTP0-OTP5",
               "LOCK2-LOCK3, RESERVED"]

        lines = list()
        data = self.read_all()
        hrom, data = data[0:2], data[2:]

        lines.append("HR0={0:02X}h, HR1={1:02X}h".format(*hrom))
        lines.append("  0: {0} ({1})".format(oprint(data[0:8]), txt[0]))
        for i in range(8, 104, 8):
            lines.append(lprint("{0:3}: {1} |{2}|", data[i:i+8], i//8))
        lines.append(" 13: {0} ({1})".format(oprint(data[104:112]), txt[1]))
        lines.append(" 14: {0} ({1})".format(oprint(data[112:120]), txt[2]))

        if stop is None or stop > 15:
            try:
                data = self.read_block(15)
            except Type1TagCommandError:
                return lines
            else:
                lines.append(" 15: {0} ({1})".format(oprint(data), txt[3]))

        data_line_fmt = "{0:>3}: {1} |{2}|"
        same_line_fmt = "{0:>3}  {1} |{2}|"
        this_data = last_data = None
        same_data = 0

        def dump_same_data(same_data, last_data, this_data, page):
            if same_data > 1:
                lines.append(lprint(same_line_fmt, last_data, "*"))
            if same_data > 0:
                lines.append(lprint(data_line_fmt, this_data, page))

        for i in range(16, stop if stop is not None else 256):
            try:
                this_data = self.read_block(i)
                if stop is None:
                    test_data = bytearray([b ^ 0xFF for b in this_data])
                    self.write_block(i, test_data)
                    self.write_block(i, this_data)
            except Type1TagCommandError:
                dump_same_data(same_data, last_data, this_data, i-1)
                break

            if this_data == last_data:
                same_data += 1
            else:
                dump_same_data(same_data, last_data, last_data, i-1)
                lines.append(lprint(data_line_fmt, this_data, i))
                last_data = this_data
                same_data = 0
        else:
            dump_same_data(same_data, last_data, this_data, i)

        return lines

    def protect(self, password=None, read_protect=False, protect_from=0):
        """The implementation of :meth:`nfc.tag.Tag.protect` for a generic
        type 1 tag is limited to setting the NDEF data read-only for
        tags that are already NDEF formatted.

        """
        return super(Type1Tag, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        if password is None:
            if self.ndef is not None:
                self.write_byte(11, 0x0F, erase=False)
                return True
            else:
                log.warning("no ndef, can't set write access restriction")
        else:
            log.warning("this tag can not be protected with a password")
        return False

    def _is_present(self):
        try:
            return self.read_byte(0) == self.uid[0]
        except Type1TagCommandError:
            return False

    def read_id(self):
        """Returns the 2 byte Header ROM and 4 byte UID.
        """
        log.debug("read identification")
        cmd = b"\x78\x00\x00\x00\x00\x00\x00"
        return self.transceive(cmd)

    def read_all(self):
        """Returns the 2 byte Header ROM and all 120 byte static memory.
        """
        log.debug("read all static memory")
        cmd = b"\x00\x00\x00" + self.uid
        return self.transceive(cmd)

    def read_byte(self, addr):
        """Read a single byte from static memory area (blocks 0-14).
        """
        if addr < 0 or addr > 127:
            raise ValueError("invalid byte address")
        log.debug("read byte at address {0} ({0:02X}h)".format(addr))
        cmd = bytearray([0x01, addr, 0x00]) + self.uid
        return self.transceive(cmd)[-1]

    def read_block(self, block):
        """Read an 8-byte data block at address (block * 8).
        """
        if block < 0 or block > 255:
            raise ValueError("invalid block number")
        log.debug("read block {0}".format(block))
        cmd = bytearray([0x02, block] + [0x00 for _ in range(8)]) + self.uid
        return self.transceive(cmd)[1:9]

    def read_segment(self, segment):
        """Read one memory segment (128 byte).
        """
        log.debug("read segment {0}".format(segment))
        if segment < 0 or segment > 15:
            raise ValueError("invalid segment number")
        cmd = bytearray([0x10, segment << 4] + [0x00 for _ in range(8)]) \
            + self.uid
        rsp = self.transceive(cmd)
        if len(rsp) < 129:
            raise Type1TagCommandError(RESPONSE_ERROR)
        return rsp[1:129]

    def write_byte(self, addr, data, erase=True):
        """Write a single byte to static memory area (blocks 0-14). The
        target byte is zero'd first if *erase* is True.

        """
        if addr < 0 or addr >= 128:
            raise ValueError("invalid byte address")
        log.debug("write byte at address {0} ({0:02X}h)".format(addr))
        cmd = b"\x53" if erase is True else b"\x1A"
        cmd = cmd + bytearray([addr, data]) + self.uid
        return self.transceive(cmd)

    def write_block(self, block, data, erase=True):
        """Write an 8-byte data block at address (block * 8). The target
        bytes are zero'd first if *erase* is True.

        """
        if block < 0 or block > 255:
            raise ValueError("invalid block number")
        log.debug("write block {0}".format(block))
        cmd = b"\x54" if erase is True else b"\x1B"
        cmd = cmd + bytearray([block]) + data + self.uid
        rsp = self.transceive(cmd)
        if len(rsp) < 9:
            raise Type1TagCommandError(RESPONSE_ERROR)
        if erase is True and rsp[1:9] != data:
            raise Type1TagCommandError(WRITE_ERROR)

    def transceive(self, data, timeout=0.1):
        log.debug(">> {0} ({1:f}s)".format(hexlify(data).decode(), timeout))

        started = time.time()
        error = None
        for retry in range(3):
            try:
                data = self.clf.exchange(data, timeout)
                break
            except nfc.clf.CommunicationError as e:
                error = e
                reason = error.__class__.__name__
                log.debug("%s after %d retries" % (reason, retry))
        else:
            if type(error) is nfc.clf.TimeoutError:
                raise Type1TagCommandError(nfc.tag.TIMEOUT_ERROR)
            if type(error) is nfc.clf.TransmissionError:
                raise Type1TagCommandError(nfc.tag.RECEIVE_ERROR)
            if type(error) is nfc.clf.ProtocolError:
                raise Type1TagCommandError(nfc.tag.PROTOCOL_ERROR)
            raise RuntimeError("unexpected " + repr(error))

        elapsed = time.time() - started
        log.debug("<< {0} ({1:f}s)".format(hexlify(data).decode(), elapsed))
        return data


class Type1TagMemoryReader(object):
    def __init__(self, tag):
        assert isinstance(tag, Type1Tag)
        self._data_from_tag = bytearray()
        self._data_in_cache = bytearray()
        self._tag = tag
        self._header_rom = bytearray(0)
        # read header_rom and static memory
        self._read_from_tag(1)

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
            if len(value) != len(range(*key.indices(0x100000))):
                msg = "{cls} requires item assignment of identical length"
                raise ValueError(msg.format(cls=self.__class__.__name__))
        self._data_in_cache[key] = value
        del self._data_in_cache[len(self):]

    def __delitem__(self, key):
        msg = "{cls} object does not support item deletion"
        raise TypeError(msg.format(cls=self.__class__.__name__))

    def _read_from_tag(self, stop):
        if len(self) < 120:
            read_all_data_response = self._tag.read_all()
            self._header_rom = read_all_data_response[0:2]
            self._data_from_tag[0:] = read_all_data_response[2:]
            self._data_in_cache[0:] = self._data_from_tag[0:]

        if stop > 120 and len(self) < 128:
            read_block_response = self._tag.read_block(15)
            self._data_from_tag[120:128] = read_block_response
            self._data_in_cache[120:128] = read_block_response

        while len(self) < stop:
            data = self._tag.read_segment(len(self) >> 7)
            self._data_from_tag.extend(data)
            self._data_in_cache.extend(data)

    def _write_to_tag(self, stop):
        hr0 = self._header_rom[0]
        if hr0 >> 4 == 1 and hr0 & 0x0F != 1:
            for i in range(0, stop, 8):
                data = self._data_in_cache[i:i+8]
                if data != self._data_from_tag[i:i+8]:
                    self._tag.write_block(i//8, data)
                    self._data_from_tag[i:i+8] = data
        else:
            for i in range(0, stop):
                data = self._data_in_cache[i]
                if data != self._data_from_tag[i]:
                    self._tag.write_byte(i, data)
                    self._data_from_tag[i] = data

    def synchronize(self):
        """Write pages that contain modified data back to tag memory."""
        self._write_to_tag(stop=len(self))


def activate(clf, target):
    import nfc.tag.tt1_broadcom
    tag = nfc.tag.tt1_broadcom.activate(clf, target)
    return tag if tag is not None else Type1Tag(clf, target)
