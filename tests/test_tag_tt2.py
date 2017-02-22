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


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()
def target():
    target = nfc.clf.RemoteTarget("106A")
    target.sens_res = HEX("4400")
    target.sel_res = HEX("00")
    target.sdd_res = HEX("0102030405060708")
    return target


@pytest.fixture()  # noqa: F811
def clf(mocker, target):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch.object(clf, 'sense', autospec=True)
    clf.sense.return_value = target
    return clf


@pytest.fixture()
def tag(clf, target):
    tag = nfc.tag.activate(clf, target)
    assert type(tag) == nfc.tag.tt2.Type2Tag
    return tag


def crca(data, size):
    reg = 0x6363
    for octet in data[:size]:
        for pos in range(8):
            bit = (reg ^ ((octet >> pos) & 1)) & 1
            reg = reg >> 1
            if bit:
                reg = reg ^ 0x8408
    return bytearray([reg & 0xff, reg >> 8])


class Type2TagSimulator(nfc.clf.ContactlessFrontend):
    pass


###############################################################################
#
# TYPE 2 TAG COMMANDS
#
###############################################################################
class TestTagCommands:
    @pytest.mark.parametrize("page", [0, 1, 255, 256])
    def test_read_with_page_number(self, tag, page):
        commands = [
            (HEX('30 %02x' % (page % 256)), 0.005),
        ]
        responses = [
            bytearray(range(16)),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.read(page) == bytearray(range(16))
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_read_with_invalid_response_error(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            bytearray(range(15)),
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.read(0)
        assert excinfo.value.errno == nfc.tag.tt2.INVALID_RESPONSE_ERROR
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_read_with_invalid_page_error(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            bytearray(range(1)),
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.read(0)
        assert excinfo.value.errno == nfc.tag.tt2.INVALID_PAGE_ERROR
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_read_with_receive_error(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            bytearray(range(1)),
        ]
        tag.clf.sense.return_value = None
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.read(0)
        assert excinfo.value.errno == nfc.tag.RECEIVE_ERROR
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    @pytest.mark.parametrize("page, data", [
        (0, '01020304'), (1, '05060708'), (255, '090a0b0c'), (256, '0d0e0f00'),
    ])
    def test_write_with_page_and_data(self, tag, page, data):
        commands = [
            (HEX('a2 %02x %s' % (page % 256, data)), 0.1),
        ]
        responses = [
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.write(page, HEX(data)) is True
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_write_with_invalid_response_error(self, tag):
        commands = [
            (HEX('a2 00 01020304'), 0.1),
        ]
        responses = [
            HEX('0a0b'),
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.write(0, HEX('01020304'))
        assert excinfo.value.errno == nfc.tag.tt2.INVALID_RESPONSE_ERROR
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_write_with_invalid_page_error(self, tag):
        commands = [
            (HEX('a2 00 01020304'), 0.1),
        ]
        responses = [
            HEX('00'),
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.write(0, HEX('01020304'))
        assert excinfo.value.errno == nfc.tag.tt2.INVALID_PAGE_ERROR
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    @pytest.mark.parametrize("data", ['', '010203', '0405060708'])
    def test_write_with_invalid_data(self, tag, data):
        with pytest.raises(ValueError) as excinfo:
            tag.write(0, HEX(data))
        assert str(excinfo.value) == "data must be a four byte string or array"

    @pytest.mark.parametrize("sector", [1, 2, 255])
    def test_sector_select(self, tag, sector):
        commands = [
            (HEX('c2 ff'), 0.1),
            (HEX('%02x000000' % sector), 0.001),
        ]
        responses = [
            HEX('0a'),
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.sector_select(sector) == sector
        assert tag.sector_select(sector) == sector
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_sector_select_not_exists(self, tag):
        commands = [
            (HEX('c2 ff'), 0.1),
            (HEX('01000000'), 0.001),
        ]
        responses = [
            HEX('0a'),
            HEX('00'),
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.sector_select(1)
        assert excinfo.value.errno == nfc.tag.tt2.INVALID_SECTOR_ERROR
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    @pytest.mark.parametrize("sector_select_1_response", [
        '00', '', '0a00'
    ])
    def test_sector_select_not_supported(self, tag, sector_select_1_response):
        commands = [
            (HEX('c2 ff'), 0.1),
        ]
        responses = [
            HEX(sector_select_1_response),
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.sector_select(1)
        assert excinfo.value.errno == nfc.tag.tt2.INVALID_SECTOR_ERROR
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    @pytest.mark.parametrize("timeout_value", [0.1, 0.01])
    def test_transceive_timeout_value(self, tag, timeout_value):
        commands = [
            (HEX('01'), 0.1),
            (HEX('02'), timeout_value),
            (HEX('03'), timeout_value),
        ]
        responses = [
            HEX('10'),
            HEX('20'),
            HEX('30'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.transceive(HEX('01')) == HEX('10')
        assert tag.transceive(HEX('02'), timeout_value) == HEX('20')
        assert tag.transceive(HEX('03'), timeout=timeout_value) == HEX('30')
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    @pytest.mark.parametrize("number_of_retries", range(4))
    def test_transceive_number_of_retries(self, tag, number_of_retries):
        commands = number_of_retries * [
            (HEX('01'), 0.1),
        ] + [
            (HEX('01'), 0.1),
        ]
        responses = number_of_retries * [
            nfc.clf.CommunicationError
        ] + [
            HEX('10'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.transceive(b'\x01', retries=number_of_retries) == b'\x10'
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.transceive(b'\x01', 0.1, number_of_retries) == b'\x10'
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    @pytest.mark.parametrize("clf_error, tag_error", [
        (nfc.clf.TimeoutError, nfc.tag.TIMEOUT_ERROR),
        (nfc.clf.TransmissionError, nfc.tag.RECEIVE_ERROR),
        (nfc.clf.ProtocolError, nfc.tag.PROTOCOL_ERROR),
    ])
    def test_transceive_communication_errors(self, tag, clf_error, tag_error):
        commands = [
            (HEX('01'), 0.1),
        ]
        responses = [
            clf_error,
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.transceive(b'\x01', 0.1, 0)
        assert excinfo.value.errno == tag_error

    def test_transceive_with_runtime_error(self, tag):
        commands = [
            (HEX('01'), 0.1),
        ]
        responses = [
            nfc.clf.CommunicationError,
        ]
        tag.clf.exchange.side_effect = responses
        with pytest.raises(RuntimeError) as excinfo:
            tag.transceive(b'\x01', 0.1, 0)
        assert repr(excinfo.value) == \
            "RuntimeError('unexpected CommunicationError()',)"

    def test_transceive_target_gone(self, tag):
        tag._target = None
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.transceive(HEX('00'))
        assert excinfo.value.errno == nfc.tag.TIMEOUT_ERROR


###############################################################################
#
# TEST TYPE 2 TAG PROCEDURES
#
###############################################################################
class TestTagProcedures:
    def test_dump(self, tag):
        responses = [
            HEX("28292a2b 2c2d2e2f 30313233 34353637"),
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX("30313233 34353637 38393a3b 3c3d3e3f"),
            HEX("34353637 38393a3b 3c3d3e3f 40414243"),
            HEX("38393a3b 3c3d3e3f 40414243 44454647"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("3c3d3e3f 40414243 44454647 48494a4b"),
            HEX("40414243 44454647 48494a4b 4c4d4e4f"),
            HEX("44454647 48494a4b 4c4d4e4f 28292a2b"),
            HEX("48494a4b 4c4d4e4f 28292a2b 2c2d2e2f"),
            HEX("4c4d4e4f 28292a2b 2c2d2e2f 30313233"),
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.dump() == [
            "000: 28 29 2a 2b (UID0-UID2, BCC0)",
            "001: ?? ?? ?? ?? (UID3-UID6)",
            "002: 30 31 32 33 (BCC1, INT, LOCK0-LOCK1)",
            "003: 34 35 36 37 (OTP0-OTP3)",
            "004: 38 39 3a 3b |89:;|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "007: 00 00 00 00 |....|",
            "008: 3c 3d 3e 3f |<=>?|",
            "009: 40 41 42 43 |@ABC|",
            "00A: 44 45 46 47 |DEFG|",
            "00B: 48 49 4a 4b |HIJK|",
            "00C: 4c 4d 4e 4f |LMNO|",
        ]
        tag.clf.exchange.side_effect = responses
        assert tag._dump(13) == [
            "000: 28 29 2a 2b (UID0-UID2, BCC0)",
            "001: ?? ?? ?? ?? (UID3-UID6)",
            "002: 30 31 32 33 (BCC1, INT, LOCK0-LOCK1)",
            "003: 34 35 36 37 (OTP0-OTP3)",
            "004: 38 39 3a 3b |89:;|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "007: 00 00 00 00 |....|",
            "008: 3c 3d 3e 3f |<=>?|",
            "009: 40 41 42 43 |@ABC|",
            "00A: 44 45 46 47 |DEFG|",
            "00B: 48 49 4a 4b |HIJK|",
            "00C: 4c 4d 4e 4f |LMNO|",
        ]
        tag.clf.exchange.side_effect = responses
        assert tag._dump(14) == [
            "000: 28 29 2a 2b (UID0-UID2, BCC0)",
            "001: ?? ?? ?? ?? (UID3-UID6)",
            "002: 30 31 32 33 (BCC1, INT, LOCK0-LOCK1)",
            "003: 34 35 36 37 (OTP0-OTP3)",
            "004: 38 39 3a 3b |89:;|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "007: 00 00 00 00 |....|",
            "008: 3c 3d 3e 3f |<=>?|",
            "009: 40 41 42 43 |@ABC|",
            "00A: 44 45 46 47 |DEFG|",
            "00B: 48 49 4a 4b |HIJK|",
            "00C: 4c 4d 4e 4f |LMNO|",
            "00D: ?? ?? ?? ?? |....|",
        ]

    def test_is_present(self, tag):
        commands = [
            (HEX('30 00'), 0.1),
            (HEX('30 00'), 0.1),
        ] + 3 * [
            (HEX('30 00'), 0.1),
        ] + 3 * [
            (HEX('30 00'), 0.1),
        ]
        responses = [
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000"),
        ] + 3 * [
            nfc.clf.TimeoutError,
        ] + 3 * [
            nfc.clf.TransmissionError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.is_present is True
        assert tag.is_present is False
        assert tag.is_present is False
        assert tag.is_present is False
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_format_default(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100100"),
            HEX("0305d500 023132fe 00000000 00000000"),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def _test_format_with_wipe(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 05 020300fe'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100100"),
#           HEX("0305d500 023132fe 00000000 00000000"),
            HEX("02036302 020305d5 000231ff 32000000"),
            HEX('0a'), HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format(wipe=0) is True
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 00000000"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is False
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]



    def __test_format_wrong_ndef_magic(self):
        self.clf.memory[12] = 0
        assert self.tag.format() is False

    def __test_format_wrong_ndef_version(self):
        self.clf.memory[13] = 0
        assert self.tag.format() is False

    def __test_format_no_user_data_area(self):
        self.clf.memory[14] = 0
        assert self.tag.format() is False

    def __test_format_ndef_readonly(self):
        self.clf.memory[15] = 0xFF
        assert self.tag.format() is False

    def __test_format_args_default(self):
        assert self.clf.memory[24:32] == "0303D00000FE0000".decode("hex")
        assert self.tag.format() is True
        assert self.clf.memory[24:32] == "0300FE0000FE0000".decode("hex")

    def __test_format_wipe_ndef_data(self):
        assert self.clf.memory[24:32] == "0303D00000FE0000".decode("hex")
        assert self.tag.format(wipe=1) is True
        assert self.clf.memory[24:32] == "0300FE0101010101".decode("hex")
        assert self.clf.memory[32:40] == "0101000000000101".decode("hex")
        assert self.clf.memory[40:2048] == (2048-40) * "\x01"

    def __test_protect_with_default_lock_bits(self):
        self.clf.memory += bytearray(32)
        assert self.tag.protect() is True
        assert self.clf.memory[   8:  16] == "79C8FFFFE110FE0F".decode("hex")
        assert self.clf.memory[  16:  24] == "0203820402000000".decode("hex")
        assert self.clf.memory[  24:  32] == "0303d00000FE0000".decode("hex")
        assert self.clf.memory[  32:2048] == 2016 * "\x00"
        assert self.clf.memory[2048:2082] == bytearray(31*"\xFF") + "\x00"
        assert self.tag.ndef.is_writeable is False

    def __test_protect_with_lock_tlv_lock_bits(self):
        self.clf.memory[16:21] = bytearray.fromhex("01 03 82 1F 62")
        assert self.tag.protect() is True
        assert self.clf.memory[ 8:16] == "79C8FFFFE110FE0F".decode("hex")
        assert self.clf.memory[16:24] == "0103821F62000000".decode("hex")
        assert self.clf.memory[24:32] == "0303d00000FE0000".decode("hex")
        assert self.clf.memory[32:40] == "0000FFFFFF7F0000".decode("hex")
        assert self.tag.ndef.is_writeable is False

    def __test_protect_with_password_argument(self):
        assert self.tag.protect("abcdefg") is False

    def __test_protect_without_ndef_magic_byte(self):
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

    def __test_ndef_read(self):
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == self.ndef_length
        print self.tag.ndef.message.pretty()
        assert self.tag.ndef.message == self.ndef_message

    def __test_ndef_read_no_ndef_magic_byte(self):
        self.clf.memory[12] = 0
        assert self.tag.ndef is None

    def __test_ndef_read_unknown_major_version(self):
        self.clf.memory[13] = 0
        assert self.tag.ndef is None

    def __test_ndef_read_unknown_minor_version(self):
        self.clf.memory[13] = 0x1F
        assert self.tag.ndef is not None

    def __test_ndef_read_all_data_set_to(self):
        for value in (0, 1, 2, 4, 254, 255):
            yield self.check_ndef_read_all_data_set_to, value

    def check_ndef_read_all_data_set_to(self, value):
        self.clf.memory[16:2048] = bytearray(2032*chr(value))
        assert self.tag.ndef is None

    def __test_ndef_write_before_skip_bytes(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(1 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 16
        assert self.clf.memory[34:51] == "\xD1\x01\x0C\x55\x01nfc.com.com\xFE"

    def __test_ndef_write_after_skip_bytes(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(33 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 48
        assert self.clf.memory[32:40] == "\x03\x30\xD1\x01\x2C\x55\x01n"
        assert self.clf.memory[40:80] == "fc.co" + (33 * "m") + ".c"
        assert self.clf.memory[80:96] == bytearray(16)
        assert self.clf.memory[96:99] == "om\xFE"

    def __test_ndef_write_long_ndef_message(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format((33+208) * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 48+208
        assert self.clf.memory[32:40] == "\x03\xFF\x01\x00\xD1\x01\xFC\x55"
        assert self.clf.memory[40:80] == "\x01nfc.co" + (33 * "m")
        assert self.clf.memory[80:96] == bytearray(16)
        assert self.clf.memory[96:309] == (208 * "m") + ".com\xFE"

    def __test_ndef_write_without_terminator(self):
        self.clf.memory[14] = 0x0A
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(31 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.length == 46
        assert self.clf.memory[32:40] == "\x03\x2E\xD1\x01\x2A\x55\x01n"
        assert self.clf.memory[40:80] == "fc.co" + (31 * "m") + ".com"
        assert self.clf.memory[80:96] == bytearray(16)


###############################################################################
#
# TYPE 2 TAG MEMORY READER
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

    def __test_getitem_byte(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == self.clf.memory[0]
        assert tag_memory[1] == self.clf.memory[1]
        
    def __test_getitem_slice(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0:8] == self.clf.memory[0:8]
        assert tag_memory[0:4] == self.clf.memory[0:4]
        assert tag_memory[4:8] == self.clf.memory[4:8]
        
    def __test_setitem_byte(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0] = 0xFF
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0xFF

    def __test_setitem_slice(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:2] = bytearray("\x11\x22")
        tag_memory.synchronize()
        assert self.clf.memory[0:2] == bytearray("\x11\x22")

    #pytest.raises(ValueError)
    def __test_setitem_slice_is_shorter(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:3] = bytearray("\x11\x22")

    #pytest.raises(ValueError)
    def __test_setitem_slice_is_longer(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:1] = bytearray("\x11\x22")

    #pytest.raises(TypeError)
    def __test_delitem(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == 0x01
        del tag_memory[0]

    #pytest.raises(IndexError)
    def __test_read_from_mute_tag(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        self.clf.tag_is_present = False
        value = tag_memory[0]

    def __test_write_to_mute_tag(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == 0x01
        self.clf.tag_is_present = False
        tag_memory[0] = 0x00
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0x01
