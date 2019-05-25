# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import nfc.tag
import nfc.clf

import math
import time
import itertools
from binascii import hexlify
from struct import pack, unpack

import logging
log = logging.getLogger(__name__)


RSP_LENGTH_ERROR, RSP_CODE_ERROR, TAG_IDM_ERROR, DATA_SIZE_ERROR = range(1, 5)


class Type3TagCommandError(nfc.tag.TagCommandError):
    errno_str = {
        RSP_LENGTH_ERROR: "invalid response length",
        RSP_CODE_ERROR: "invalid response code",
        TAG_IDM_ERROR: "answer from wrong tag",
        DATA_SIZE_ERROR: "insufficient data received",
        # FeliCa Lite specific error codes
        0x01A6: "invalid service code number or attribute",
        0x01B1: "authentication required to read (first block in list)",
        0x02B1: "authentication required to read (second block in list)",
        0x04B1: "authentication required to read (third block in list)",
        0x08B1: "authentication required to read (fourth block in list)",
        0x02B2: "verification failure for write with mac operation",
    }


class ServiceCode:
    """A service code provides access to a group of data blocks located on
    the card file system. A service code is a 16-bit structure
    composed of a 10-bit service number and a 6-bit service
    attribute. The service attribute determines the service type and
    whether authentication is required.

    """
    def __init__(self, number, attribute):
        self.number = number
        self.attribute = attribute

    def __repr__(self):
        return "ServiceCode({0}, {1})".format(self.number, self.attribute)

    def __str__(self):
        attribute_map = {
            0b001000: "Random RW with key",
            0b001001: "Random RW w/o key",
            0b001010: "Random RO with key",
            0b001011: "Random RO w/o key",
            0b001100: "Cyclic RW with key",
            0b001101: "Cyclic RW w/o key",
            0b001110: "Cyclic RO with key",
            0b001111: "Cyclic RO w/o key",
            0b010000: "Purse Direct with key",
            0b010001: "Purse Direct w/o key",
            0b010010: "Purse Cashback with key",
            0b010011: "Purse Cashback w/o key",
            0b010100: "Purse Decrement with key",
            0b010101: "Purse Decrement w/o key",
            0b010110: "Purse Read Only with key",
            0b010111: "Purse Read Only w/o key",
        }
        try:
            attribute_string = attribute_map[self.attribute]
        except KeyError:
            attribute_string = "Type {0:06b}b".format(self.attribute)
        return "Service Code {0:04X}h (Service {1} {2!s})".format(
            int(self), self.number, attribute_string)

    def __int__(self):
        return self.number << 6 | self.attribute

    def pack(self):
        """Pack the service code for transmission. Returns a 2 byte string."""
        sn, sa = self.number, self.attribute
        return pack("<H", (sn & 0x3ff) << 6 | (sa & 0x3f))

    @classmethod
    def unpack(cls, s):
        """Unpack and return a ServiceCode from a byte string."""
        v = unpack("<H", s[0:2])[0]
        return cls(v >> 6, v & 0x3f)


class BlockCode:
    """A block code indicates a data block within a service. A block code
    is a 16-bit or 24-bit structure composed of a length bit (1b if
    the block number is less than 256), a 3-bit access mode, a 4-bit
    service list index and an 8-bit or 16-bit block number.

    """
    def __init__(self, number, access=0, service=0):
        self.number = number
        self.access = access
        self.service = service

    def __repr__(self):
        return "BlockCode({0}, {1}, {2})".format(
            self.number, self.access, self.service)

    def __str__(self):
        s = "BlockCode(number={0}, access={1:03b}, service={2})"
        return s.format(self.number, self.access, self.service)

    def __bytes__(self):
        return str(self).encode()

    def pack(self):
        """Pack the block code for transmission. Returns a 2-3 byte string."""
        bn, am, sx = self.number, self.access, self.service
        return bytes(
                bytearray([bool(bn < 256) << 7 | (am & 0x7) << 4 | (sx & 0xf)])
                + (bytearray([bn]) if bn < 256 else pack("<H", bn)))


class Type3Tag(nfc.tag.Tag):
    """Implementation of the NFC Forum Type 3 Tag specification.

    The NFC Forum Type 3 Tag is based on the Sony FeliCa protocol and
    command specification. An NFC Forum compliant Type 3 Tag responds
    to a FeliCa polling command with system code 0x12FC and was
    configured to support service code 0x000B for NDEF data read and
    service code 0x0009 for NDEF data write (the latter may not be
    present if the tag is read-only) without encryption.

    """
    TYPE = "Type3Tag"

    class NDEF(nfc.tag.Tag.NDEF):
        # Type 3 Tag specific implementation of the NDEF access type
        # class that is returned by the Tag.ndef attribute.

        def _read_attribute_data(self):
            try:
                data = self._tag.read_from_ndef_service(0)
            except Type3TagCommandError:
                return None

            if sum(data[0:14]) != unpack(">H", data[14:16])[0]:
                log.debug("ndef attribute data checksum error")
                return None

            ver, nbr, nbw, nmaxb = unpack(">BBBH", data[0:5])
            writef, rwflag = unpack(">BB", data[9:11])
            length = unpack(">I", b"\x00" + data[11:14])[0]
            self._capacity = nmaxb * 16
            self._writeable = rwflag != 0 and nbw > 0
            self._readable = writef == 0 and nbr > 0
            attributes = {
                'ver': ver, 'nbr': nbr, 'nbw': nbw, 'nmaxb': nmaxb,
                'writef': writef, 'rwflag': rwflag, 'ln': length}
            log.debug("got ndef attributes {0}".format(attributes))
            return attributes

        def _write_attribute_data(self, attributes):
            log.debug("set ndef attributes {0}".format(attributes))
            attribute_data = bytearray(16)
            attribute_data[0] = attributes['ver']
            attribute_data[1] = attributes['nbr']
            attribute_data[2] = attributes['nbw']
            attribute_data[3:5] = pack('>H', attributes['nmaxb'])
            attribute_data[9] = attributes['writef']
            attribute_data[10] = attributes['rwflag']
            attribute_data[11:14] = pack('>I', attributes['ln'])[1:4]
            attribute_data[14:16] = pack('>H', sum(attribute_data[0:14]))
            self._tag.write_to_ndef_service(attribute_data, 0)

        def _read_ndef_data(self):
            if self.tag.sys != 0x12FC:
                try:
                    self.tag.idm, self.tag.pmm = self._tag.polling(0x12FC)
                    self.tag.sys = 0x12FC
                except Type3TagCommandError:
                    return None

            attributes = self._read_attribute_data()
            if attributes is None:
                log.debug("found no attribute data (maybe checksum error)")
                return None
            if attributes['ver'] >> 4 != 1:
                log.debug("unsupported ndef mapping major version")
                return None

            last_block_number = 1 + (attributes['ln'] + 15) // 16
            data = bytearray()

            for i in range(1, last_block_number, attributes['nbr']):
                last_block = min(i + attributes['nbr'], last_block_number)
                block_list = range(i, last_block)
                try:
                    data += self.tag.read_from_ndef_service(*block_list)
                except Type3TagCommandError:
                    return None

            data = data[0:attributes['ln']]
            log.debug("got {0} byte ndef data {1}{2}".format(
                    len(data),
                    hexlify(data[0:32]).decode(),
                    ('', '...')[len(data) > 32]))

            return data

        def _write_ndef_data(self, data):
            attributes = self._read_attribute_data()
            attributes['writef'] = 0x0F
            self._write_attribute_data(attributes)

            log.debug("set {0} byte ndef data {1}{2}".format(
                    len(data),
                    hexlify(data[0:32]).decode(),
                    ('', '...')[len(data) > 32]))

            last_block_number = 1 + (len(data) + 15) // 16
            attributes['ln'] = len(data)  # because we may need to pad zeros
            data = data + bytearray(-len(data) % 16)  # adjust to block size

            for i in range(1, last_block_number, attributes['nbw']):
                last_block = min(i + attributes['nbw'], last_block_number)
                block_data = data[(i-1)*16:(last_block-1)*16]
                self._tag.write_to_ndef_service(
                    block_data, *range(i, last_block))

            attributes['writef'] = 0x00
            self._write_attribute_data(attributes)
            return True

    def __init__(self, clf, target):
        super(Type3Tag, self).__init__(clf, target)
        self.idm = target.sensf_res[1:9]
        self.pmm = target.sensf_res[9:17]
        self.sys = 0xFFFF
        if len(target.sensf_res) > 17:
            self.sys = unpack(">H", target.sensf_res[17:19])[0]
        self._nfcid = bytearray(self.idm)

    def __str__(self):
        s = " PMM={pmm} SYS={sys:04X}"
        return nfc.tag.Tag.__str__(self) + s.format(
            pmm=hexlify(self.pmm).decode().upper(), sys=self.sys)

    def _is_present(self):
        # Check if the card still responds to the acquired system code
        # and the returned identifier (IDm) matches. This is called
        # from nfc.tag.Tag for the 'is_present' attribute.
        try:
            idm, pmm = self.polling(self.sys)
            return idm == self.identifier
        except Type3TagCommandError:
            return False

    def dump(self):
        """Read all data blocks of an NFC Forum Tag.

        For an NFC Forum Tag (system code 0x12FC) :meth:`dump` reads
        all data blocks from service 0x000B (NDEF read service) and
        returns a list of strings suitable for printing. The number of
        strings returned does not necessarily reflect the number of
        data blocks because a range of data blocks with equal content
        is reduced to fewer lines of output.

        """
        if self.sys == 0x12FC:
            ndef_read_service = ServiceCode(0, 0b01011)
            return self.dump_service(ndef_read_service)
        else:
            return ["This is not an NFC Forum Tag."]

    def dump_service(self, sc):
        """Read all data blocks of a given service.

        :meth:`dump_service` reads all data blocks from the service
        with service code *sc* and returns a list of strings suitable
        for printing. The number of strings returned does not
        necessarily reflect the number of data blocks because a range
        of data blocks with equal content is reduced to fewer lines of
        output.

        """
        def lprint(fmt, data, index):
            ispchr = lambda x: x >= 32 and x <= 126  # noqa: E731

            def print_bytes(octets):
                return ' '.join(['%02x' % x for x in octets])

            def print_chars(octets):
                return ''.join([chr(x) if ispchr(x) else '.' for x in octets])

            return fmt.format(index, print_bytes(data), print_chars(data))

        data_line_fmt = "{0:04X}: {1} |{2}|"
        same_line_fmt = "{0:<4s}  {1} |{2}|"

        lines = list()
        last_data = None
        same_data = 0

        for i in itertools.count():  # pragma: no branch
            assert i < 0x10000
            try:
                this_data = self.read_without_encryption([sc], [BlockCode(i)])
            except Type3TagCommandError:
                i = i - 1
                break

            if this_data == last_data:
                same_data += 1
            else:
                if same_data > 1:
                    lines.append(lprint(same_line_fmt, last_data, "*"))
                lines.append(lprint(data_line_fmt, this_data, i))
                last_data = this_data
                same_data = 0

        if same_data > 1:
            lines.append(lprint(same_line_fmt, last_data, "*"))
        if same_data > 0:
            lines.append(lprint(data_line_fmt, this_data, i))

        return lines

    def format(self, version=None, wipe=None):
        """Format and blank an NFC Forum Type 3 Tag.

        A generic NFC Forum Type 3 Tag can be (re)formatted if it is
        in either one of blank, initialized or readwrite state. By
        formatting, all contents of the attribute information block is
        overwritten with values determined. The number of user data
        blocks is determined by reading all memory until an error
        response. Similarily, the maximum number of data block that
        can be read or written with a single command is determined by
        sending successively increased read and write commands. The
        current data length is set to zero. The NDEF mapping version
        is set to the latest known version number (1.0), unless the
        *version* argument is provided and it's major version number
        corresponds to one of the known major version numbers.

        By default, no data other than the attribute block is
        modified. To overwrite user data the *wipe* argument must be
        set to an integer value. The lower 8 bits of that value are
        written to all data bytes that follow the attribute block.

        """
        return super(Type3Tag, self).format(version, wipe)

    def _format(self, version, wipe):
        assert version is None or type(version) is int
        assert wipe is None or type(wipe) is int

        if self.sys != 0x12FC:
            log.warning("not an ndef tag and can not be made compatible")
            return False
        if version and version >> 4 != 1:
            log.warning("Type 3 Tag NDEF mapping major version must be 1")
            return False

        try:
            self.read_from_ndef_service(0)
        except Type3TagCommandError:
            log.warning("this tag does not have any usable data blocks")
            return False

        # To determine the total number of data blocks we start with
        # the assumption that it must be between 0 and 2**16, then try
        # reading in the middle and adjust the range depending on
        # whether the read was successful or not. So in each round we
        # have the smallest number that worked and the largest number
        # that didn't, obviously the end is when that difference is 1.
        """
        nmaxb = [0, 0x10000]
        while nmaxb[1] - nmaxb[0] > 1:
            block = nmaxb[0] + (nmaxb[1] - nmaxb[0]) // 2 - 1
            try:
                self.read_from_ndef_service(block)
            except Type3TagCommandError:
                nmaxb[1] = block + 1
            else:
                nmaxb[0] = block + 1
        """
        nmaxb = [0, 0x10000]
        while nmaxb[1] - nmaxb[0] > 1:
            print(nmaxb)
            block = nmaxb[0] + (nmaxb[1] - nmaxb[0]) // 2
            try:
                self.read_from_ndef_service(block)
            except Type3TagCommandError:
                nmaxb[1] = block
            else:
                nmaxb[0] = block

        nmaxb = nmaxb[0]

        # To get the number of blocks that can be read in one command
        # we just try to read with an increasing number of blocks.
        for nbr in range(1, 16):
            try:
                self.read_from_ndef_service(*(nbr*[0]))
            except Type3TagCommandError:
                nbr -= 1
                break

        # To get the number of blocks that can be written in one
        # command we do essentially the same as for nbr, just that to
        # preserve existing data we first read and then write it back.
        data = self.read_from_ndef_service(0)
        for nbw in range(1, 14):
            try:
                self.write_to_ndef_service(nbw*data, *(nbw*[0]))
            except Type3TagCommandError:
                nbw -= 1
                break

        # Tags with more than 4K memory require 3-byte block number
        # format. This reduces the maximum number of blocks in write.
        if nbw == 13 and nmaxb > 255:
            nbw = 12

        # We now have all information needed to create and write the
        # new attribute data to block number 0.
        attribute_data = bytearray(16)
        attribute_data[0:5] = pack(">BBBH", version, nbr, nbw, nmaxb)
        attribute_data[10] = 0x01 if nbw > 0 else 0x00
        attribute_data[14:16] = pack(">H", sum(attribute_data[0:14]))
        log.debug("set ndef attributes %s", hexlify(attribute_data).decode())
        self.write_to_ndef_service(attribute_data, 0)

        # If required, we will also overwrite the memory with the
        # 8-bit integer provided. This could take a while.
        if wipe is not None:
            data = bytearray([wipe]) * 16
            while nmaxb > 0:
                self.write_to_ndef_service(data, nmaxb)
                nmaxb = nmaxb - 1

        return True

    def polling(self, system_code=0xffff, request_code=0, time_slots=0):
        """Aquire and identify a card.

        The Polling command is used to detect the Type 3 Tags in the
        field. It is also used for initialization and anti-collision.

        The *system_code* identifies the card system to acquire. A
        card can have multiple systems. The first system that matches
        *system_code* will be activated. A value of 0xff for any of
        the two bytes works as a wildcard, thus 0xffff activates the
        very first system in the card. The card identification data
        returned are the Manufacture ID (IDm) and Manufacture
        Parameter (PMm).

        The *request_code* tells the card whether it should return
        additional information. The default value 0 requests no
        additional information. Request code 1 means that the card
        shall also return the system code, so polling for system code
        0xffff with request code 1 can be used to identify the first
        system on the card. Request code 2 asks for communication
        performance data, more precisely a bitmap of possible
        communication speeds. Not all cards provide that information.

        The number of *time_slots* determines whether there's a chance
        to receive a response if multiple Type 3 Tags are in the
        field. For the reader the number of time slots determines the
        amount of time to wait for a response. Any Type 3 Tag in the
        field, i.e. powered by the field, will choose a random time
        slot to respond. With the default *time_slots* value 0 there
        will only be one time slot available for all responses and
        multiple responses would produce a collision. More time slots
        reduce the chance of collisions (but may result in an
        application working with a tag that was just accidentially
        close enough). Only specific values should be used for
        *time_slots*, those are 0, 1, 3, 7, and 15. Other values may
        produce unexpected results depending on the tag product.

        :meth:`polling` returns either the tuple (IDm, PMm) or the
        tuple (IDm, PMm, *additional information*) depending on the
        response lengt, all as bytearrays.

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """

        log.debug("polling for system 0x{0:04x}".format(system_code))
        if time_slots not in (0, 1, 3, 7, 15):
            log.debug("invalid number of time slots: {0}".format(time_slots))
            raise ValueError("invalid number of time slots")
        if request_code not in (0, 1, 2):
            log.debug("invalid request code value: {0}".format(request_code))
            raise ValueError("invalid request code for polling")

        timeout = 0.003625 + time_slots * 0.001208
        data = pack(">HBB", system_code, request_code, time_slots)
        data = self.send_cmd_recv_rsp(0x00, data, timeout, send_idm=False)
        if len(data) != (16 if request_code == 0 else 18):
            log.debug("unexpected polling response length")
            raise Type3TagCommandError(DATA_SIZE_ERROR)

        return (data[0:8], data[8:16]) if len(data) == 16 else \
            (data[0:8], data[8:16], data[16:18])

    def read_without_encryption(self, service_list, block_list):
        """Read data blocks from unencrypted services.

        This method sends a Read Without Encryption command to the
        tag. The data blocks to read are indicated by a sequence of
        :class:`~nfc.tag.tt3.BlockCode` objects in *block_list*. Each
        block code must reference a :class:`~nfc.tag.tt3.ServiceCode`
        object from the iterable *service_list*. If any of the blocks
        and services do not exist, the tag will stop processing at
        that point and return a two byte error status. The status
        bytes become the :attr:`~nfc.tag.TagCommandError.errno` value
        of the :exc:`~nfc.tag.TagCommandError` exception.

        As an example, the following code reads block 5 from service
        16 (service type 'random read-write w/o key') and blocks 0 to
        1 from service 80 (service type 'random read-only w/o key')::

            sc1 = nfc.tag.tt3.ServiceCode(16, 0x09)
            sc2 = nfc.tag.tt3.ServiceCode(80, 0x0B)
            bc1 = nfc.tag.tt3.BlockCode(5, service=0)
            bc2 = nfc.tag.tt3.BlockCode(0, service=1)
            bc3 = nfc.tag.tt3.BlockCode(1, service=1)
            try:
                data = tag.read_without_encryption([sc1, sc2], [bc1, bc2, bc3])
            except nfc.tag.TagCommandError as e:
                if e.errno > 0x00FF:
                    print("the tag returned an error status")
                else:
                    print("command failed with some other error")

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        a, b, e = self.pmm[5] & 7, self.pmm[5] >> 3 & 7, self.pmm[5] >> 6
        timeout = 302.1E-6 * ((b + 1) * len(block_list) + a + 1) * 4**e

        data = bytearray([
            len(service_list)]) \
            + b''.join([sc.pack() for sc in service_list]) \
            + bytearray([len(block_list)]) \
            + b''.join([bc.pack() for bc in block_list])

        log.debug("read w/o encryption service/block list: {0} / {1}".format(
            ' '.join([hexlify(sc.pack()).decode() for sc in service_list]),
            ' '.join([hexlify(bc.pack()).decode() for bc in block_list])))

        data = self.send_cmd_recv_rsp(0x06, data, timeout)

        if len(data) != 1 + len(block_list) * 16:
            log.debug("insufficient data received from tag")
            raise Type3TagCommandError(DATA_SIZE_ERROR)

        return data[1:]

    def read_from_ndef_service(self, *blocks):
        """Read block data from an NDEF compatible tag.

        This is a convinience method to read block data from a tag
        that has system code 0x12FC (NDEF). For other tags this method
        simply returns :const:`None`. All arguments are block numbers
        to read. To actually pass a list of block numbers requires
        unpacking. The following example calls would have the same
        effect of reading 32 byte data from from blocks 1 and 8.::

            data = tag.read_from_ndef_service(1, 8)
            data = tag.read_from_ndef_service(*list(1, 8))

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        if self.sys == 0x12FC:
            sc_list = [ServiceCode(0, 0b001011)]
            bc_list = [BlockCode(n) for n in blocks]
            return self.read_without_encryption(sc_list, bc_list)

    def write_without_encryption(self, service_list, block_list, data):
        """Write data blocks to unencrypted services.

        This method sends a Write Without Encryption command to the
        tag. The data blocks to overwrite are indicated by a sequence
        of :class:`~nfc.tag.tt3.BlockCode` objects in the parameter
        *block_list*. Each block code must reference one of the
        :class:`~nfc.tag.tt3.ServiceCode` objects in the iterable
        *service_list*. If any of the blocks or services do not exist,
        the tag will stop processing at that point and return a two
        byte error status. The status bytes become the
        :attr:`~nfc.tag.TagCommandError.errno` value of the
        :exc:`~nfc.tag.TagCommandError` exception. The *data* to write
        must be a byte string or array of length ``16 *
        len(block_list)``.

        As an example, the following code writes ``16 * "\\xAA"`` to
        block 5 of service 16, ``16 * "\\xBB"`` to block 0 of service
        80 and ``16 * "\\xCC"`` to block 1 of service 80 (all services
        are writeable without key)::

            sc1 = nfc.tag.tt3.ServiceCode(16, 0x09)
            sc2 = nfc.tag.tt3.ServiceCode(80, 0x09)
            bc1 = nfc.tag.tt3.BlockCode(5, service=0)
            bc2 = nfc.tag.tt3.BlockCode(0, service=1)
            bc3 = nfc.tag.tt3.BlockCode(1, service=1)
            sc_list = [sc1, sc2]
            bc_list = [bc1, bc2, bc3]
            data = 16 * "\\xAA" + 16 * "\\xBB" + 16 * "\\xCC"
            try:
                data = tag.write_without_encryption(sc_list, bc_list, data)
            except nfc.tag.TagCommandError as e:
                if e.errno > 0x00FF:
                    print("the tag returned an error status")
                else:
                    print("command failed with some other error")

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        a, b, e = self.pmm[6] & 7, self.pmm[6] >> 3 & 7, self.pmm[6] >> 6
        timeout = 302.1E-6 * ((b + 1) * len(block_list) + a + 1) * 4**e

        data = bytearray([
            len(service_list)]) \
            + b"".join([sc.pack() for sc in service_list]) \
            + bytearray([len(block_list)]) \
            + b"".join([bc.pack() for bc in block_list]) \
            + bytearray(data)

        log.debug("write w/o encryption service/block list: {0} / {1}".format(
            ' '.join([hexlify(sc.pack()).decode() for sc in service_list]),
            ' '.join([hexlify(bc.pack()).decode() for bc in block_list])))

        self.send_cmd_recv_rsp(0x08, data, timeout)

    def write_to_ndef_service(self, data, *blocks):
        """Write block data to an NDEF compatible tag.

        This is a convinience method to write block data to a tag that
        has system code 0x12FC (NDEF). For other tags this method
        simply does nothing. The *data* to write must be a string or
        bytearray with length equal ``16 * len(blocks)``. All
        parameters following *data* are interpreted as block numbers
        to write. To actually pass a list of block numbers requires
        unpacking. The following example calls would have the same
        effect of writing 32 byte zeros into blocks 1 and 8.::

            tag.write_to_ndef_service(32 * "\\0", 1, 8)
            tag.write_to_ndef_service(32 * "\\0", *list(1, 8))

        Command execution errors raise :exc:`~nfc.tag.TagCommandError`.

        """
        if self.sys == 0x12FC:
            sc_list = [ServiceCode(0, 0b001001)]
            bc_list = [BlockCode(n) for n in blocks]
            self.write_without_encryption(sc_list, bc_list, data)

    def send_cmd_recv_rsp(self, cmd_code, cmd_data, timeout,
                          send_idm=True, check_status=True):
        """Send a command and receive a response.

        This low level method sends an arbitrary command with the
        8-bit integer *cmd_code*, followed by the captured tag
        identifier (IDm) if *send_idm* is :const:`True` and the byte
        string or bytearray *cmd_data*. It then waits *timeout*
        seconds for a response, verifies that the response is
        correctly formatted and, if *check_status* is :const:`True`,
        that the status flags do not indicate an error.

        All errors raise a :exc:`~nfc.tag.TagCommandError`
        exception. Errors from response status flags produce an
        :attr:`~nfc.tag.TagCommandError.errno` that is greater than
        255, all other errors are below 256.

        """
        idm = self.idm if send_idm else bytearray()
        cmd = bytearray([2+len(idm)+len(cmd_data), cmd_code]) + idm + cmd_data
        log.debug(">> {0:02x} {1:02x} {2} {3} ({4}s)".format(
                cmd[0], cmd[1], hexlify(cmd[2:10]).decode(),
                hexlify(cmd[10:]).decode(), timeout))

        started = time.time()
        error = None
        for retry in range(3):
            try:
                rsp = self.clf.exchange(cmd, timeout)
                break
            except nfc.clf.CommunicationError as e:
                error = e
                reason = error.__class__.__name__
                log.debug("%s after %d retries" % (reason, retry))
        else:
            if type(error) is nfc.clf.TimeoutError:
                raise Type3TagCommandError(nfc.tag.TIMEOUT_ERROR)
            if type(error) is nfc.clf.TransmissionError:
                raise Type3TagCommandError(nfc.tag.RECEIVE_ERROR)
            if type(error) is nfc.clf.ProtocolError:  # pragma: no branch
                raise Type3TagCommandError(nfc.tag.PROTOCOL_ERROR)

        if rsp[0] != len(rsp):
            log.debug("incorrect response length {0:02x}".format(rsp[0]))
            raise Type3TagCommandError(RSP_LENGTH_ERROR)
        if rsp[1] != cmd_code + 1:
            log.debug("incorrect response code {0:02x}".format(rsp[1]))
            raise Type3TagCommandError(RSP_CODE_ERROR)
        if send_idm and rsp[2:10] != self.idm:
            log.debug("wrong tag or transaction id {}".format(
                    hexlify(rsp[2:10]).decode()))
            raise Type3TagCommandError(TAG_IDM_ERROR)
        if not send_idm:
            log.debug("<< {0:02x} {1:02x} {2}".format(
                rsp[0], rsp[1], hexlify(rsp[2:]).decode()))
            return rsp[2:]
        if check_status and rsp[10] != 0:
            log.debug("tag returned error status {}".format(
                    hexlify(rsp[10:12]).decode()))
            raise Type3TagCommandError(unpack(">H", rsp[10:12])[0])
        if not check_status:
            log.debug("<< {0:02x} {1:02x} {2} {3}".format(
                rsp[0], rsp[1], hexlify(rsp[2:10]).decode(),
                hexlify(rsp[10:]).decode()))
            return rsp[10:]
        log.debug("<< {0:02x} {1:02x} {2} {3} {4} ({elapsed:f}s)".format(
            rsp[0], rsp[1], hexlify(rsp[2:10]).decode(),
            hexlify(rsp[10:12]).decode(), hexlify(rsp[12:]).decode(),
            elapsed=time.time()-started))
        return rsp[12:]


class Type3TagEmulation(nfc.tag.TagEmulation):
    """Framework for Type 3 Tag emulation.

    """
    def __init__(self, clf, target):
        self.services = dict()
        self.target = target
        self.cmd = bytearray([len(target.tt3_cmd)+1]) + target.tt3_cmd
        self.idm = target.sensf_res[1:9]
        self.pmm = target.sensf_res[9:17]
        self.sys = target.sensf_res[17:19]
        self.clf = clf

    def __str__(self):
        """x.__str__() <==> str(x)"""
        return "Type3TagEmulation IDm={id} PMm={pmm} SYS={sys}".format(
            id=hexlify(self.idm).decode(),
            pmm=hexlify(self.pmm).decode(),
            sys=hexlify(self.sys).decode())

    def add_service(self, service_code, block_read_func, block_write_func):
        def default_block_read(block_number, rb, re):
            return None

        def default_block_write(block_number, block_data, wb, we):
            return False

        if block_read_func is None:
            block_read_func = default_block_read

        if block_write_func is None:
            block_write_func = default_block_write

        self.services[service_code] = (block_read_func, block_write_func)

    def process_command(self, cmd):
        log.debug("cmd: %s", hexlify(cmd).decode() if cmd else str(cmd))
        if len(cmd) != cmd[0]:
            log.error("tt3 command length error")
            return None
        if tuple(cmd[0:4]) in [(6, 0, 255, 255), (6, 0) + tuple(self.sys)]:
            log.debug("process 'polling' command")
            rsp = self.polling(cmd[2:])
            return bytearray([2 + len(rsp), 0x01]) + rsp
        if cmd[2:10] == self.idm:
            if cmd[1] == 0x04:
                log.debug("process 'request response' command")
                rsp = self.request_response(cmd[10:])
                return bytearray([10 + len(rsp), 0x05]) + self.idm + rsp
            if cmd[1] == 0x06:
                log.debug("process 'read without encryption' command")
                rsp = self.read_without_encryption(cmd[10:])
                return bytearray([10 + len(rsp), 0x07]) + self.idm + rsp
            if cmd[1] == 0x08:
                log.debug("process 'write without encryption' command")
                rsp = self.write_without_encryption(cmd[10:])
                return bytearray([10 + len(rsp), 0x09]) + self.idm + rsp
            if cmd[1] == 0x0C:
                log.debug("process 'request system code' command")
                rsp = self.request_system_code(cmd[10:])
                return bytearray([10 + len(rsp), 0x0D]) + self.idm + rsp

    def send_response(self, rsp, timeout):
        log.debug("rsp: {}".format(hexlify(rsp).decode()
                                   if rsp is not None
                                   else 'None'))
        return self.clf.exchange(rsp, timeout)

    def polling(self, cmd_data):
        if cmd_data[2] == 1:
            rsp = self.idm + self.pmm + self.sys
        else:
            rsp = self.idm + self.pmm
        return rsp

    def request_response(self, cmd_data):
        return bytearray([0])

    def read_without_encryption(self, cmd_data):
        service_list = cmd_data.pop(0) * [[None, None]]
        for i in range(len(service_list)):
            service_code = cmd_data[1] << 8 | cmd_data[0]
            if service_code not in self.services.keys():
                return bytearray([0xFF, 0xA1])
            service_list[i] = [service_code, 0]
            del cmd_data[0:2]

        service_block_list = cmd_data.pop(0) * [None]
        if len(service_block_list) > 15:
            return bytearray([0xFF, 0xA2])
        for i in range(len(service_block_list)):
            try:
                service_list_item = service_list[cmd_data[0] & 0x0F]
                service_code = service_list_item[0]
                service_list_item[1] += 1
            except IndexError:
                return bytearray([1 << (i % 8), 0xA3])
            if cmd_data[0] >= 128:
                block_number = cmd_data[1]
                del cmd_data[0:2]
            else:
                block_number = cmd_data[2] << 8 | cmd_data[1]
                del cmd_data[0:3]
            service_block_list[i] = [service_code, block_number, 0]

        service_block_count = dict(service_list)
        for service_block_list_item in service_block_list:
            service_code = service_block_list_item[0]
            service_block_list_item[2] = service_block_count[service_code]

        block_data = bytearray()
        for i, service_block_list_item in enumerate(service_block_list):
            service_code, block_number, block_count = service_block_list_item
            # rb (read begin) and re (read end) mark an atomic read
            rb = bool(block_count == service_block_count[service_code])
            service_block_count[service_code] -= 1
            re = bool(service_block_count[service_code] == 0)
            read_func, write_func = self.services[service_code]
            one_block_data = read_func(block_number, rb, re)
            if one_block_data is None:
                return bytearray([1 << (i % 8), 0xA2])
            block_data.extend(one_block_data)

        return bytearray([0, 0, int(math.floor(len(block_data)/16))]) \
            + block_data

    def write_without_encryption(self, cmd_data):
        service_list = cmd_data.pop(0) * [[None, None]]
        for i in range(len(service_list)):
            service_code = cmd_data[1] << 8 | cmd_data[0]
            if service_code not in self.services.keys():
                return bytearray([255, 0xA1])
            service_list[i] = [service_code, 0]
            del cmd_data[0:2]

        service_block_list = cmd_data.pop(0) * [None]
        for i in range(len(service_block_list)):
            try:
                service_list_item = service_list[cmd_data[0] & 0x0F]
                service_code = service_list_item[0]
                service_list_item[1] += 1
            except IndexError:
                return bytearray([1 << (i % 8), 0xA3])
            if cmd_data[0] >= 128:
                block_number = cmd_data[1]
                del cmd_data[0:2]
            else:
                block_number = cmd_data[2] << 8 | cmd_data[1]
                del cmd_data[0:3]
            service_block_list[i] = [service_code, block_number, 0]

        service_block_count = dict(service_list)
        for service_block_list_item in service_block_list:
            service_code = service_block_list_item[0]
            service_block_list_item[2] = service_block_count[service_code]

        block_data = cmd_data[0:]
        if len(block_data) % 16 != 0:
            return bytearray([255, 0xA2])

        for i, service_block_list_item in enumerate(service_block_list):
            service_code, block_number, block_count = service_block_list_item
            # wb (write begin) and we (write end) mark an atomic write
            wb = bool(block_count == service_block_count[service_code])
            service_block_count[service_code] -= 1
            we = bool(service_block_count[service_code] == 0)
            read_func, write_func = self.services[service_code]
            if not write_func(block_number, block_data[i*16:(i+1)*16], wb, we):
                return bytearray([1 << (i % 8), 0xA2])

        return bytearray([0, 0])

    def request_system_code(self, cmd_data):
        return b'\x01' + self.sys


def activate(clf, target):
    if not target.sensf_res[1:3] == b"\x01\xFE":
        import nfc.tag.tt3_sony
        tag = nfc.tag.tt3_sony.activate(clf, target)
        return tag if tag else Type3Tag(clf, target)
