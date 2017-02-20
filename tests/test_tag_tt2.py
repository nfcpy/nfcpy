# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import sys
import pytest
from mock import MagicMock, call
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.DEBUG)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.tag.tt2").setLevel(logging_level)

sys.modules['usb1'] = MagicMock

import nfc          # noqa: E402
import nfc.tag      # noqa: E402
import nfc.tag.tt2  # noqa: E402

import nfc.ndef
import ndef


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    return clf


@pytest.fixture()
def target():
    target = nfc.clf.RemoteTarget("106A")
    #target.sens_res = HEX("000C")
    return target


def crca(data, size):
    reg = 0x6363
    for octet in data[:size]:
        for pos in range(8):
            bit = (reg ^ ((octet >> pos) & 1)) & 1
            reg = reg >> 1
            if bit: reg = reg ^ 0x8408
    return bytearray([reg & 0xff, reg >> 8])

class Type2TagSimulator(nfc.clf.ContactlessFrontend):
    pass

###############################################################################
#
# TEST TYPE 2 TAG MEMORY READER
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestMemoryReader:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "01 6F D5 36  11 12 7A 00  79 C8 00 00  00 00 00 00"
        )
        #self.clf = Type2TagSimulator(tag_memory)
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_getitem_byte(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == self.clf.memory[0]
        assert tag_memory[1] == self.clf.memory[1]
        
    def test_getitem_slice(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0:8] == self.clf.memory[0:8]
        assert tag_memory[0:4] == self.clf.memory[0:4]
        assert tag_memory[4:8] == self.clf.memory[4:8]
        
    def test_setitem_byte(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0] = 0xFF
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0xFF

    def test_setitem_slice(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:2] = bytearray("\x11\x22")
        tag_memory.synchronize()
        assert self.clf.memory[0:2] == bytearray("\x11\x22")

    #pytest.raises(ValueError)
    def test_setitem_slice_is_shorter(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:3] = bytearray("\x11\x22")

    #pytest.raises(ValueError)
    def test_setitem_slice_is_longer(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:1] = bytearray("\x11\x22")

    #pytest.raises(TypeError)
    def test_delitem(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == 0x01
        del tag_memory[0]

    #pytest.raises(IndexError)
    def test_read_from_mute_tag(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        self.clf.tag_is_present = False
        value = tag_memory[0]

    def test_write_to_mute_tag(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == 0x01
        self.clf.tag_is_present = False
        tag_memory[0] = 0x00
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0x01


################################################################################
#
# TEST TYPE 2 TAG COMMANDS
#
################################################################################
@pytest.mark.skip(reason="not yet converted")
class TestTagCommands:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "01 6F D5 36  11 12 7A 00  79 C8 00 00  00 00 00 00"
        ) + bytearray(2048 - 16)
        self.clf = Type2TagSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_read_with_args_keyword(self):
        assert self.tag.read(page=0) == self.clf.memory[0:16]

    def test_read_with_args_positional(self):
        assert self.tag.read(0) == self.clf.memory[0:16]

    def __test_read_with_nak_response(self):
        for nak in (0, 1, 4, 5):
            yield self.check_read_with_nak_response, nak

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def check_read_with_nak_response(self, nak):
        self.clf.return_response = bytearray([nak])
        try: self.tag.read(0)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_PAGE_ERROR
            raise

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def test_read_with_invalid_response(self):
        self.clf.return_response = bytearray(15)
        try: self.tag.read(0)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_RESPONSE_ERROR
            raise

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def test_read_with_checksum_error(self):
        self.clf.return_response = bytearray(18)
        try: self.tag.read(0)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.CHECKSUM_ERROR
            raise

    def test_write_with_args_keyword(self):
        self.tag.write(page=0, data=bytearray(4))
        assert self.clf.memory[0:4] == bytearray(4)

    def test_write_with_args_positional(self):
        self.tag.write(0, bytearray(4))
        assert self.clf.memory[0:4] == bytearray(4)

    #pytest.raises(ValueError)
    def test_write_with_args_error(self):
        self.tag.write(0, data=bytearray(3))

    def __test_write_with_nak_response(self):
        for nak in (0, 1, 4, 5):
            yield self.check_write_with_nak_response, nak

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def check_write_with_nak_response(self, nak):
        self.clf.return_response = bytearray([nak])
        try: self.tag.write(0, bytearray(4))
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_PAGE_ERROR
            raise

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def test_write_with_invalid_response(self):
        self.clf.return_response = bytearray(2)
        try: self.tag.write(0, bytearray(4))
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_RESPONSE_ERROR
            raise

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def test_write_to_mute_tag(self):
        self.clf.tag_is_present = False
        try: self.tag.write(0, bytearray(4))
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.TIMEOUT_ERROR
            raise

    def test_sector_select_same_sector(self):
        assert self.tag.sector_select(0) == 0

    def test_sector_select(self):
        assert self.tag.sector_select(1) == 1

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def test_sector_select_not_supported(self):
        self.clf.return_response = bytearray([0x00])
        try: self.tag.sector_select(1)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_SECTOR_ERROR
            raise

    #pytest.raises(nfc.tag.tt2.Type2TagCommandError)
    def test_sector_select_invalid_sector(self):
        try: self.tag.sector_select(2)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_SECTOR_ERROR
            raise


################################################################################
#
# TEST TYPE 2 TAG PROCEDURES
#
################################################################################
@pytest.mark.skip(reason="not yet converted")
class TestTagProcedures:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "01 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 FE 00"
            "02 03 82 04  02 00 00 00  03 03 D0 00  00 FE 00 00"
        ) + bytearray(2048 - 32)
        #self.clf = Type2TagSimulator(tag_memory)
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_dump_args_default(self):
        lines = self.tag.dump()
        assert len(lines) == 11
        assert lines[-1] == "511: 00 00 00 00 |....|"

    def test_dump_args_stop(self):
        lines = self.tag._dump(4)
        assert len(lines) == 4
        assert lines[3] == "  3: e1 10 fe 00 (OTP0-OTP3)"

    def test_dump_unreadable(self):
        self.clf.return_response = bytearray([0x00])
        lines = self.tag._dump(8)
        assert len(lines) == 7
        assert lines[3] == "  3: ?? ?? ?? ?? (OTP0-OTP3)"
        assert lines[6] == "  7: ?? ?? ?? ?? |....|"

    def test_is_present_if_present(self):
        assert self.tag.is_present is True

    def test_is_present_if_gone(self):
        self.clf.tag_is_present = False
        assert self.tag.is_present is False

    def test_is_present_if_error(self):
        self.clf.return_response = bytearray(18)
        assert self.tag.is_present is False

    def test_format_wrong_ndef_magic(self):
        self.clf.memory[12] = 0
        assert self.tag.format() is False

    def test_format_wrong_ndef_version(self):
        self.clf.memory[13] = 0
        assert self.tag.format() is False

    def test_format_no_user_data_area(self):
        self.clf.memory[14] = 0
        assert self.tag.format() is False

    def test_format_ndef_readonly(self):
        self.clf.memory[15] = 0xFF
        assert self.tag.format() is False

    def test_format_args_default(self):
        assert self.clf.memory[24:32] == "0303D00000FE0000".decode("hex")
        assert self.tag.format() is True
        assert self.clf.memory[24:32] == "0300FE0000FE0000".decode("hex")

    def test_format_wipe_ndef_data(self):
        assert self.clf.memory[24:32] == "0303D00000FE0000".decode("hex")
        assert self.tag.format(wipe=1) is True
        assert self.clf.memory[24:32] == "0300FE0101010101".decode("hex")
        assert self.clf.memory[32:40] == "0101000000000101".decode("hex")
        assert self.clf.memory[40:2048] == (2048-40) * "\x01"

    def test_protect_with_default_lock_bits(self):
        self.clf.memory += bytearray(32)
        assert self.tag.protect() is True
        assert self.clf.memory[   8:  16] == "79C8FFFFE110FE0F".decode("hex")
        assert self.clf.memory[  16:  24] == "0203820402000000".decode("hex")
        assert self.clf.memory[  24:  32] == "0303d00000FE0000".decode("hex")
        assert self.clf.memory[  32:2048] == 2016 * "\x00"
        assert self.clf.memory[2048:2082] == bytearray(31*"\xFF") + "\x00"
        assert self.tag.ndef.is_writeable is False

    def test_protect_with_lock_tlv_lock_bits(self):
        self.clf.memory[16:21] = bytearray.fromhex("01 03 82 1F 62")
        assert self.tag.protect() is True
        assert self.clf.memory[ 8:16] == "79C8FFFFE110FE0F".decode("hex")
        assert self.clf.memory[16:24] == "0103821F62000000".decode("hex")
        assert self.clf.memory[24:32] == "0303d00000FE0000".decode("hex")
        assert self.clf.memory[32:40] == "0000FFFFFF7F0000".decode("hex")
        assert self.tag.ndef.is_writeable is False

    def test_protect_with_password_argument(self):
        assert self.tag.protect("abcdefg") is False

    def test_protect_without_ndef_magic_byte(self):
        self.clf.memory[12] = 0
        assert self.tag.protect() is False


###############################################################################
#
# TEST TYPE 1 TAG NDEF
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestNdef:
    def setup(self):
        tag_memory = (bytearray.fromhex(
            "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 FE 00" # 000-003
            "00 00 00 01  03 50 10 24  FF 01 00 02  03 52 0E 04" # 004-007
            "03 FF 07 CC  C1 01 00 00  07 C5 55 01  6E 66 63 2E" # 008-011
            "63 6F 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 012-015
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 016-019
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 024-027
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 028-031
        ) + bytearray(1904 * "\x6D") + bytearray.fromhex(        # 012-509
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  2E 63 6F 6D" # 508-511
        ))
        uri = "http://www.nfc.co{0}.com".format((2010-32) * "m")
        self.ndef_message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        self.ndef_capacity = 2048 - 52
        self.ndef_length = 2048 - 52

        #self.clf = Type2TagSimulator(tag_memory)
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_ndef_read(self):
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == self.ndef_length
        print self.tag.ndef.message.pretty()
        assert self.tag.ndef.message == self.ndef_message

    def test_ndef_read_no_ndef_magic_byte(self):
        self.clf.memory[12] = 0
        assert self.tag.ndef is None

    def test_ndef_read_unknown_major_version(self):
        self.clf.memory[13] = 0
        assert self.tag.ndef is None

    def test_ndef_read_unknown_minor_version(self):
        self.clf.memory[13] = 0x1F
        assert self.tag.ndef is not None

    def __test_ndef_read_all_data_set_to(self):
        for value in (0, 1, 2, 4, 254, 255):
            yield self.check_ndef_read_all_data_set_to, value

    def check_ndef_read_all_data_set_to(self, value):
        self.clf.memory[16:2048] = bytearray(2032*chr(value))
        assert self.tag.ndef is None

    def test_ndef_write_before_skip_bytes(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(1 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 16
        assert self.clf.memory[34:51] == "\xD1\x01\x0C\x55\x01nfc.com.com\xFE"

    def test_ndef_write_after_skip_bytes(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(33 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 48
        assert self.clf.memory[32:40] == "\x03\x30\xD1\x01\x2C\x55\x01n"
        assert self.clf.memory[40:80] == "fc.co" + (33 * "m") + ".c"
        assert self.clf.memory[80:96] == bytearray(16)
        assert self.clf.memory[96:99] == "om\xFE"

    def test_ndef_write_long_ndef_message(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format((33+208) * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 48+208
        assert self.clf.memory[32:40] == "\x03\xFF\x01\x00\xD1\x01\xFC\x55"
        assert self.clf.memory[40:80] == "\x01nfc.co" + (33 * "m")
        assert self.clf.memory[80:96] == bytearray(16)
        assert self.clf.memory[96:309] == (208 * "m") + ".com\xFE"

    def test_ndef_write_without_terminator(self):
        self.clf.memory[14] = 0x0A
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(31 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.length == 46
        assert self.clf.memory[32:40] == "\x03\x2E\xD1\x01\x2A\x55\x01n"
        assert self.clf.memory[40:80] == "fc.co" + (31 * "m") + ".com"
        assert self.clf.memory[80:96] == bytearray(16)


@pytest.mark.skip(reason="not yet converted")
class TestActivation:
    def test_activation_with_digital_error_for_authenticate(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.crc_error_after = 1
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag

    def test_activation_with_digital_error_for_get_version(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.crc_error_after = 2
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag
        
    def test_activation_with_unknown_version_for_get_version(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.return_response = bytearray(8)
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag
