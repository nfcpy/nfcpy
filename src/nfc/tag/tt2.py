# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# Licensed under the EUPL, Version 1.1 or - as soon they
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


def hexdump(octets, sep=""):
    return sep.join(
        ("??" if x is None else ("%02x" % x)) for x in octets)


def chrdump(octets, sep=""):
    return sep.join(
            (("{:c}".format(x) if 32 <= x <= 126 else ".")
             if x is not None
             else ".")
            for x in octets)


def pagedump(page, octets, info=None):
    info = ("|%s|" % chrdump(octets)) if info is None else ("(%s)" % info)
    page = "  * " if page is None else "{0:03X}:".format(page)
    return "{0} {1} {2}".format(page, hexdump(octets, sep=" "), info)


TIMEOUT_ERROR, INVALID_SECTOR_ERROR, \
    INVALID_PAGE_ERROR, INVALID_RESPONSE_ERROR = range(4)


class Type2TagCommandError(TagCommandError):
    """Type 2 Tag specific exceptions. Sets
    :attr:`~nfc.tag.TagCommandError.errno` to one of:

    | 1 - INVALID_SECTOR_ERROR
    | 2 - INVALID_PAGE_ERROR
    | 3 - INVALID_RESPONSE_ERROR

    """
    errno_str = {
        INVALID_SECTOR_ERROR: "invalid sector number",
        INVALID_PAGE_ERROR: "invalid page number",
        INVALID_RESPONSE_ERROR: "invalid response data",
    }


def read_tlv(memory, offset, skip_bytes):
    # Unpack a Type 2 Tag TLV from tag memory and return tag type, tag
    # length and tag value. For tag type 0 there is no length field,
    # this is returned as length -1. The tlv length field can be one
    # or three bytes, if the first byte is 255 then the next two byte
    # carry the length (big endian).
    tlv_t, offset = (memory[offset], offset+1)
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


def get_capacity(capacity, offset, skip_bytes):
    # The net capacity is the range of bytes from the current offset
    # until the end of user data bytes (given by the capability
    # container capacity value plus 16 header bytes), reduced by the
    # number of skip bytes (from memory and lock control TLVs) that
    # are within the usable memory range, and adjusted by the required
    # number of TLV length bytes (1 or 3) and the TLV tag byte.
    capacity = len(set(range(offset, capacity + 16)) - skip_bytes)
    # To store more than 254 byte ndef we must use three length bytes,
    # otherwise it's only one. But only if the capacity is more than
    # 256 the three length byte format will provide a higher value.
    capacity -= 4 if capacity > 256 else 2
    return capacity


class Type2Tag(Tag):
    """Implementation of the NFC Forum Type 2 Tag Operation specification.

    The NFC Forum Type 2 Tag is based on the ISO 14443 Type A
    technology for frame structure and anticollision (detection)
    commands, and the NXP Mifare commands for accessing the tag
    memory.

    """
    TYPE = "Type2Tag"

    class NDEF(Tag.NDEF):
        # Type 2 Tag specific implementation of the NDEF access type
        # class that is returned by the Tag.ndef attribute.

        def __init__(self, tag):
            super(Type2Tag.NDEF, self).__init__(tag)
            self._ndef_tlv_offset = 0

        def _read_capability_data(self, tag_memory):
            try:
                if tag_memory[12] != 0xE1:
                    log.debug("ndef management data is not present")
                    return False
                if tag_memory[13] >> 4 != 1:
                    log.debug("unsupported ndef mapping major version")
                    return False
                self._readable = bool(tag_memory[15] >> 4 == 0)
                self._writeable = bool(tag_memory[15] & 0xF == 0)
                return True
            except Type2TagCommandError:
                log.debug("first four memory pages were unreadable")
                return False

        def _read_ndef_data(self):
            log.debug("read ndef data")
            tag_memory = Type2TagMemoryReader(self.tag)

            if not self._read_capability_data(tag_memory):
                return None

            raw_capacity = tag_memory[14] * 8
            log.debug("raw capacity is {0} byte".format(raw_capacity))

            offset = 16
            ndef = None
            skip_bytes = set()
            data_area_size = raw_capacity
            while offset < data_area_size + 16:
                while (offset) in skip_bytes:
                    offset += 1

                try:
                    tlv = read_tlv(tag_memory, offset, skip_bytes)
                    tlv_t, tlv_l, tlv_v = tlv
                except Type2TagCommandError:
                    return None
                else:
                    logmsg = "tlv type {0} length {1} at offset {2}"
                    log.debug(logmsg.format(tlv_t, tlv_l, offset))

                if tlv_t == 0:
                    pass
                elif tlv_t == 1:
                    if tlv_l == 3:
                        lock_bytes = get_lock_byte_range(tlv_v)
                        skip_bytes.update(range(*lock_bytes.indices(0x100000)))
                    else:
                        log.debug("lock tlv has wrong length")
                elif tlv_t == 2:
                    if tlv_l == 3:
                        rsvd_bytes = get_rsvd_byte_range(tlv_v)
                        skip_bytes.update(range(*rsvd_bytes.indices(0x100000)))
                    else:
                        log.debug("memory tlv has wrong length")
                elif tlv_t == 3:
                    ndef = tlv_v
                    break
                elif tlv_t == 254:
                    break
                else:
                    logmsg = "unknown tlv {0} at offset {0}"
                    log.debug(logmsg.format(tlv_t, offset))

                offset += tlv_l + 1 + (1 if tlv_l < 255 else 3)

            self._capacity = get_capacity(raw_capacity, offset, skip_bytes)
            self._ndef_tlv_offset = offset
            self._tag_memory = tag_memory
            self._skip_bytes = skip_bytes
            return ndef

        def _write_ndef_data(self, data):
            # Write new ndef data to the tag memory. Despite the
            # tag memory is rather easy to handle, the extremely
            # generic NFC Forum TLV structure makes this rather
            # complicated. The precondition is that we have already
            # processed the memory structure in _read_ndef_data(), if
            # not we'll do it first. We'll then have a tag memory
            # image, know which bytes need to be to skipped as told by
            # memory or control tlv data, and where the ndef message
            # tlv starts. We first set the ndef message tlv length to
            # zero (synchronize cause that to be actually written),
            # then write all new data into the memory image (skipping
            # bytes as needed) and let that be written to the tag, and
            # finally write the new ndef message tlv length.
            log.debug("write ndef data {0}{1}".format(
                hexlify(data[:10]).decode(), '...' if len(data) > 10 else ''))

            tag_memory = self._tag_memory
            skip_bytes = self._skip_bytes
            offset = self._ndef_tlv_offset

            # Set the ndef message tlv length to 0.
            tag_memory[offset+1] = 0
            tag_memory.synchronize()

            # Leave room for ndef message length byte(s) and write
            # ndef data into the memory image, but jump over skip
            # bytes. If space permits, write a terminator tlv.
            offset += 2 if len(data) < 255 else 4
            for index, octet in enumerate(data):
                while offset + index in skip_bytes:
                    offset += 1
                tag_memory[offset+index] = octet
            offset = offset + index + 1
            while offset in skip_bytes:
                offset += 1
            if offset < tag_memory[14] * 8 + 16:
                tag_memory[offset] = 0xFE
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
    # Type2Tag methods and attributes
    #
    def __init__(self, clf, target):
        super(Type2Tag, self).__init__(clf, target)
        self._nfcid = bytearray(target.sdd_res)
        self._current_sector = 0

    def dump(self):
        """Returns the tag memory pages as a list of formatted strings.

        :meth:`dump` iterates over all tag memory pages (4 bytes
        each) from page zero until an error response is received and
        produces a list of strings that is intended for line by line
        printing. Note that multiple consecutive memory pages of
        identical content may be reduced to fewer lines of output, so
        the number of lines returned does not necessarily correspond
        to the number of memory pages.

        """
        return self._dump(stop=None)

    def _dump(self, stop=None):
        lines = list()
        header = ("UID0-UID2, BCC0", "UID3-UID6",
                  "BCC1, INT, LOCK0-LOCK1", "OTP0-OTP3")

        for i, info in enumerate(header):
            try:
                data = self.read(i)[0:4]
            except Type2TagCommandError:
                data = [None, None, None, None]
            lines.append(pagedump(i, data, info))

        this_data = last_data = None
        same_data = 0

        def dump_same_data(same_data, last_data, this_data, page):
            if same_data > 1:
                lines.append(pagedump(None, this_data))
            if same_data > 0:
                lines.append(pagedump(page, this_data))

        for i in range(4, stop if stop is not None else 0x40000):
            try:
                self.sector_select(i >> 8)
                this_data = self.read(i)[0:4]
            except Type2TagCommandError:
                dump_same_data(same_data, last_data, this_data, i-1)
                if stop is not None:
                    this_data = last_data = [None, None, None, None]
                    lines.append(pagedump(i, this_data))
                    dump_same_data(stop-i-1, this_data, this_data, stop-1)
                break

            if this_data == last_data:
                same_data += 1
            else:
                dump_same_data(same_data, last_data, last_data, i-1)
                lines.append(pagedump(i, this_data))
                last_data = this_data
                same_data = 0
        else:
            dump_same_data(same_data, last_data, this_data, i)

        return lines

    def _is_present(self):
        # Verify that the tag is still present. This is implemented as
        # reading page 0-3 (from whatever sector is currently active).
        try:
            data = self.transceive(b"\x30\x00")
        except Type2TagCommandError as error:
            if error.errno != TIMEOUT_ERROR:
                log.warning("unexpected error in presence check: %s" % error)
            return False
        else:
            return bool(data and len(data) == 16)

    def format(self, version=None, wipe=None):
        """Erase the NDEF message on a Type 2 Tag.

        The :meth:`format` method will reset the length of the NDEF
        message on a type 2 tag to zero, thus the tag will appear to
        be empty. Additionally, if the *wipe* argument is set to some
        integer then :meth:`format` will overwrite all user date that
        follows the NDEF message TLV with that integer (mod 256). If
        an NDEF message TLV is not present it will be created with a
        length of zero.

        Despite it's name, the :meth:`format` method can not format a
        blank tag to make it NDEF compatible. This is because the user
        data are of a type 2 tag can not be safely determined, also
        reading all memory pages until an error response yields only
        the total memory size which includes an undetermined number of
        special pages at the end of memory.

        It is also not possible to change the NDEF mapping version,
        located in a one-time-programmable area of the tag memory.

        """
        return super(Type2Tag, self).format(version, wipe)

    def _format(self, version, wipe):
        if self.ndef and self.ndef.is_writeable:
            memory = self.ndef._tag_memory
            offset = self.ndef._ndef_tlv_offset
            memory[offset+1:offset+3] = b"\x00\xFE"
            if wipe is not None:
                memory_size = memory[14] * 8 + 16
                skip_bytes = self.ndef._skip_bytes
                for offset in range(offset + 3, memory_size):
                    if offset not in skip_bytes:
                        memory[offset] = wipe & 0xFF
            memory.synchronize()
            return True
        return False

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Protect the tag against write access, i.e. make it read-only.

        :meth:`Type2Tag.protect` switches an NFC Forum Type 2 Tag to
        read-only state by setting all lock bits to 1. This operation
        can not be reversed. If the tag is not an NFC Forum Tag,
        i.e. it is not formatted with an NDEF Capability Container,
        the :meth:`protect` method simply returns :const:`False`.

        A generic Type 2 Tag can not be protected with a password. If
        the *password* argument is provided, the :meth:`protect`
        method does nothing else than return :const:`False`. The
        *read_protect* and *protect_from* arguments are safely
        ignored.

        """
        return super(Type2Tag, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        if password is not None:
            log.debug("this tag can not be protected with password")
            return False

        if self.ndef is None:
            log.debug("can not protect a non-ndef tag")
            return False

        # Set the ndef capability container write flag. We must
        # synchronize to have this written before lock bits are set.
        tag_memory = self.ndef._tag_memory
        tag_memory[15] |= 0x0F
        tag_memory.synchronize()

        # Set the static lock bits.
        tag_memory[10] = 0xFF
        tag_memory[11] = 0xFF

        # Search for all lock control tlv and store the first lock
        # byte address and the number of lock bits in lock_control.
        offset = 16
        lock_control = []
        data_area_size = tag_memory[14] * 8
        while offset < data_area_size + 16:  # pragma: no branch
            tlv_t, tlv_l, tlv_v = read_tlv(tag_memory, offset, set())
            log.debug("tlv type {0} at offset {1}".format(tlv_t, offset))
            if tlv_t in (0x03, 0xFE, None):
                break
            if tlv_t == 0x01:
                log.debug("lock control tlv %s", hexlify(tlv_v).decode())
                page_addr = tlv_v[0] >> 4
                byte_offs = tlv_v[0] & 0x0F
                page_size = 2 ** (tlv_v[2] & 0x0F)  # BytesPerPage
                lock_byte_addr = page_addr * page_size + byte_offs
                lock_bits_size = tlv_v[1] if tlv_v[1] > 0 else 256
                lock_control.append((lock_byte_addr, lock_bits_size))
            offset += tlv_l + 1 + (1 if tlv_l < 255 else 3)

        # If the tag has a dynamic memory layout and we did not find
        # any lock control tlv, then add default dynamic lock bits.
        if tag_memory[14] > 6 and len(lock_control) == 0:
            # use default dynamic lock bits layout
            data_area_size = tag_memory[14] * 8
            lock_byte_addr = 16 + data_area_size
            lock_bits_size = (data_area_size - 48 + 7)//8
            lock_control.append((lock_byte_addr, lock_bits_size))

        # For any lock control entry set the referenced lock bytes to
        # zero and then set the lock bits to one.
        log.debug("processing lock byte list {0}".format(lock_control))
        for lock_byte_addr, lock_bits_size in lock_control:
            log.debug("{0} lock bits at 0x{1:02x}".format(
                lock_bits_size, lock_byte_addr))
            lock_byte_size = (lock_bits_size + 7) // 8
            for i in range(lock_byte_size):
                tag_memory[lock_byte_addr+i] = 0
            for i in range(lock_bits_size):
                tag_memory[lock_byte_addr+(i >> 3)] |= 1 << (i & 7)

        # Synchronize to write all lock bits to the tag.
        tag_memory.synchronize()
        return True

    def read(self, page):
        """Send a READ command to retrieve data from the tag.

        The *page* argument specifies the offset in multiples of 4
        bytes (i.e. page number 1 will return bytes 4 to 19). The data
        returned is a byte array of length 16 or None if the block is
        outside the readable memory range.

        Command execution errors raise :exc:`Type2TagCommandError`.

        """
        log.debug("read pages {0} to {1}".format(page, page+3))

        data = self.transceive(bytearray([0x30, page % 256]), timeout=0.005)

        if len(data) == 1 and data[0] & 0xFA == 0x00:
            log.debug("received nak response")
            self.target.sel_req = self.target.sdd_res[:]
            self._target = self.clf.sense(self.target)
            raise Type2TagCommandError(
                INVALID_PAGE_ERROR if self.target else nfc.tag.RECEIVE_ERROR)

        if len(data) != 16:
            log.debug("invalid response %s", hexlify(data).decode())
            raise Type2TagCommandError(INVALID_RESPONSE_ERROR)

        return data

    def write(self, page, data):
        """Send a WRITE command to store data on the tag.

        The *page* argument specifies the offset in multiples of 4
        bytes. The *data* argument must be a string or bytearray of
        length 4.

        Command execution errors raise :exc:`Type2TagCommandError`.

        """
        if len(data) != 4:
            raise ValueError("data must be a four byte string or array")

        log.debug("write %s to page %s", hexlify(data).decode(), page)
        rsp = self.transceive(bytearray([0xA2, page % 256]) + data)

        if len(rsp) != 1:
            log.debug("invalid response %s", hexlify(data).decode())
            raise Type2TagCommandError(INVALID_RESPONSE_ERROR)

        if rsp[0] != 0x0A:  # NAK
            log.debug("invalid page, received nak")
            raise Type2TagCommandError(INVALID_PAGE_ERROR)

        return True

    def sector_select(self, sector):
        """Send a SECTOR_SELECT command to switch the 1K address sector.

        The command is only send to the tag if the *sector* number is
        different from the currently selected sector number (set to 0
        when the tag instance is created). If the command was
        successful, the currently selected sector number is updated
        and further :meth:`read` and :meth:`write` commands will be
        relative to that sector.

        Command execution errors raise :exc:`Type2TagCommandError`.

        """
        if sector != self._current_sector:
            log.debug("select sector {0} (pages {1} to {2})".format(
                sector, sector << 10, ((sector+1) << 8) - 1))

            sector_select_1 = b'\xC2\xFF'
            sector_select_2 = pack('Bxxx', sector)

            rsp = self.transceive(sector_select_1)
            if len(rsp) == 1 and rsp[0] == 0x0A:
                try:
                    # command is passively ack'd, i.e. there's no response
                    # and we must make sure there's no retries attempted
                    self.transceive(sector_select_2, timeout=0.001, retries=0)
                except Type2TagCommandError as error:
                    assert int(error) == TIMEOUT_ERROR  # passive ack
                else:
                    log.debug("sector {0} does not exist".format(sector))
                    raise Type2TagCommandError(INVALID_SECTOR_ERROR)
            else:
                log.debug("sector select is not supported for this tag")
                raise Type2TagCommandError(INVALID_SECTOR_ERROR)

            log.debug("sector {0} is now selected".format(sector))
            self._current_sector = sector
        return self._current_sector

    def transceive(self, data, timeout=0.1, retries=2):
        """Send a Type 2 Tag command and receive the response.

        :meth:`transceive` is a type 2 tag specific wrapper around the
        :meth:`nfc.ContactlessFrontend.exchange` method. It can be
        used to send custom commands as a sequence of *data* bytes to
        the tag and receive the response data bytes. If *timeout*
        seconds pass without a response, the operation is aborted and
        :exc:`~nfc.tag.TagCommandError` raised with the TIMEOUT_ERROR
        error code.

        Command execution errors raise :exc:`Type2TagCommandError`.

        """
        log.debug(">> {0} ({1:f}s)".format(hexlify(data).decode(), timeout))

        if not self.target:
            # Sometimes we have to (re)sense the target during
            # communication. If that failed (tag gone) then any
            # further attempt to transceive() is the same as
            # "unrecoverable timeout error".
            raise Type2TagCommandError(nfc.tag.TIMEOUT_ERROR)

        started = time.time()
        error = None
        for retry in range(1 + retries):
            try:
                data = self.clf.exchange(data, timeout)
                break
            except nfc.clf.CommunicationError as e:
                error = e
                reason = error.__class__.__name__
                log.debug("%s after %d retries" % (reason, retry))
        else:
            if type(error) is nfc.clf.TimeoutError:
                raise Type2TagCommandError(nfc.tag.TIMEOUT_ERROR)
            if type(error) is nfc.clf.TransmissionError:
                raise Type2TagCommandError(nfc.tag.RECEIVE_ERROR)
            if type(error) is nfc.clf.ProtocolError:
                raise Type2TagCommandError(nfc.tag.PROTOCOL_ERROR)
            raise RuntimeError("unexpected " + repr(error))

        elapsed = time.time() - started
        log.debug("<< {0} ({1:f}s)".format(hexlify(data).decode(), elapsed))
        return data


class Type2TagMemoryReader(object):
    """The memory reader provides a convenient way to read and write
    :class:`Type2Tag` memory. Once instantiated with a proper type
    2 *tag* object the tag memory can then be accessed as a linear
    sequence of bytes, without any considerations of sector or
    page boundaries. Modified bytes can be written to tag memory
    with :meth:`synchronize`. ::

        clf = nfc.ContactlessFrontend(...)
        tag = clf.connect(rdwr={'on-connect': None})
        if isinstance(tag, nfc.tag.tt2.Type2Tag):
            tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
            tag_memory[16:19] = [0x03, 0x00, 0xFE]
            tag_memory.synchronize()

    """
    def __init__(self, tag):
        assert isinstance(tag, Type2Tag)
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
            if len(value) != len(range(*key.indices(0x100000))):
                msg = "{cls} requires item assignment of identical length"
                raise ValueError(msg.format(cls=self.__class__.__name__))
        self._data_in_cache[key] = value
        del self._data_in_cache[len(self):]

    def __delitem__(self, key):
        msg = "{cls} object does not support item deletion"
        raise TypeError(msg.format(cls=self.__class__.__name__))

    def _read_from_tag(self, stop):
        index = (len(self) >> 4) << 4
        while index < stop:
            self._tag.sector_select(index >> 10)
            data = self._tag.read(index >> 2)
            self._data_from_tag[index:] = data
            self._data_in_cache[index:] = data
            index += 16

    def _write_to_tag(self, stop):
        index = 0
        while index < stop:
            data = self._data_in_cache[index:index+4]
            if data != self._data_from_tag[index:index+4]:
                self._tag.sector_select(index >> 10)
                self._tag.write(index >> 2, data)
                self._data_from_tag[index:index+4] = data
            index += 4

    def synchronize(self):
        """Write pages that contain modified data back to tag memory."""
        self._write_to_tag(stop=len(self))


def activate(clf, target):
    # Type 2 Tags go mute when they receive an unsupported command. It
    # is then necessary to sense again and by copying sdd_res to
    # sel_req we ensure that only the same tag will be found.
    target.sel_req = target.sdd_res[:]
    if target.sdd_res[0] == 0x04:  # NXP
        import nfc.tag.tt2_nxp
        tag = nfc.tag.tt2_nxp.activate(clf, target)
        if tag is not None:
            return tag
        else:
            # make sure the tag is still alive
            target = clf.sense(target)
    if target:
        return Type2Tag(clf, target)
