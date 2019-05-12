# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.tag
import nfc.tag.tt2

import mock
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.tag.tt2").setLevel(logging_level)


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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.transceive(b'\x01', 0.1, number_of_retries) == b'\x10'
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    @pytest.mark.parametrize("clf_error, tag_error", [
        (nfc.clf.TimeoutError, nfc.tag.TIMEOUT_ERROR),
        (nfc.clf.TransmissionError, nfc.tag.RECEIVE_ERROR),
        (nfc.clf.ProtocolError, nfc.tag.PROTOCOL_ERROR),
    ])
    def test_transceive_communication_errors(self, tag, clf_error, tag_error):
        tag.clf.exchange.side_effect = clf_error
        with pytest.raises(nfc.tag.tt2.Type2TagCommandError) as excinfo:
            tag.transceive(b'\x01')
        assert excinfo.value.errno == tag_error
        tag.clf.exchange.assert_called_with(HEX('01'), 0.1)
        assert tag.clf.exchange.call_count == 3

    def test_transceive_with_runtime_error(self, tag):
        tag.clf.exchange.side_effect = nfc.clf.CommunicationError
        with pytest.raises(RuntimeError) as excinfo:
            tag.transceive(b'\x01')
        assert repr(excinfo.value) == \
            "RuntimeError('unexpected CommunicationError()',)"
        tag.clf.exchange.assert_called_with(HEX('01'), 0.1)
        assert tag.clf.exchange.call_count == 3

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

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
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_with_wipe(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 05 020300fe'), 0.1),
            (HEX('a2 06 000000ff'), 0.1),
            (HEX('a2 07 ff000000'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100200"),
            HEX("02036302 020305d5 000231ff ff320000"),
            HEX('0a'), HEX('0a'), HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == HEX('d500023132')
        assert tag.format(wipe=0) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 00000000"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_blank_tag(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 00000000"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect() is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_static_default_lockbits(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 03 e110020f'), 0.1),
            (HEX('a2 02 0000ffff'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100200"),
            HEX("000300fe 00000000 00000000 00000000"),
            HEX("0a"), HEX("0a"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == b''
        assert tag.ndef.is_writeable is True
        assert tag.ndef.is_readable is True
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_dynamic_default_lockbits(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 03 e110080f'), 0.1),
            (HEX('30 08'), 0.005),
            (HEX('30 0c'), 0.005),
            (HEX('30 10'), 0.005),
            (HEX('30 14'), 0.005),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('a2 14 03000000'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100800"),
            HEX("000300fe 00000000 00000000 00000000"),
            HEX("0a"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("0a"),
            HEX("0a"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == b''
        assert tag.ndef.is_writeable is True
        assert tag.ndef.is_readable is True
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_dynamic_locktlv_lockbits(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 03 e110080f'), 0.1),
            (HEX('30 08'), 0.005),
            (HEX('30 0c'), 0.005),
            (HEX('30 10'), 0.005),
            (HEX('30 14'), 0.005),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('a2 14 ffff0000'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100800"),
            HEX("00000103 a0102300 0300fe00 00000000"),
            HEX("0a"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("00000000 00000000 00000000 00000000"),
            HEX("0a"),
            HEX("0a"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == b''
        assert tag.ndef.is_writeable is True
        assert tag.ndef.is_readable is True
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_password(self, tag):
        assert tag.protect(b'') is False


###############################################################################
#
# TEST TYPE 1 TAG NDEF
#
###############################################################################
class TestNdef:
    def test_read_unreadable_tag(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 00'), 0.005),
            (HEX('30 00'), 0.005),
        ]
        responses = [
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    @pytest.mark.parametrize("cc", ['E0100100', 'E1200100'])
    def test_read_unsupported_cc(self, tag, cc):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 " + cc),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_until_memory_end(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100100"),
            HEX("00000000 00000000 ffffffff ffffffff"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_until_terminator(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100100"),
            HEX("feffffff ffffffff ffffffff ffffffff"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_over_unknown_tlv(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100100"),
            HEX("f0000303 d0000000 ffffffff ffffffff"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == HEX('d00000')
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_excessive_length_tlv(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('30 08'), 0.005),
            (HEX('30 08'), 0.005),
            (HEX('30 08'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100100"),
            HEX("03ffd000 00000000 ffffffff ffffffff"),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_invalid_lock_rsvd_tlv(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100200"),
            HEX("0104ffff ffff0202 ffff0303 d00000fe"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == HEX('d00000')
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_with_all_tlv_types(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('30 08'), 0.005),
            (HEX('30 0c'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E110060f"),
            HEX("000103c0 10220203 70040200 ffffffff"),
            HEX("0313d500 10000102 03040506 0708090a"),
            HEX("ffff0b0c 0d0e0f00 fe000000 00000000"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == HEX('d50010000102030405060708090a0b0c0d0e0f')
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_with_all_tlv_types(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('30 08'), 0.005),
            (HEX('30 0c'), 0.005),
            (HEX('a2 08 0300d500'), 0.1),
            (HEX('a2 09 11010203'), 0.1),
            (HEX('a2 0a 04050607'), 0.1),
            (HEX('a2 0b 08090a0b'), 0.1),
            (HEX('a2 0c ffff0c0d'), 0.1),
            (HEX('a2 0d 0e0f1011'), 0.1),
            (HEX('a2 0f fe000000'), 0.1),
            (HEX('a2 08 0314d500'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100600"),
            HEX("000103c0 10220203 e0040200 fd020000"),
            HEX("0313d500 10000102 03040506 0708090a"),
            HEX("ffff0b0c 0d0e0ffe ffffffff 00000000"),
            HEX("0a"), HEX("0a"), HEX("0a"), HEX("0a"),
            HEX("0a"), HEX("0a"), HEX("0a"), HEX("0a"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == HEX('d50010000102030405060708090a0b0c0d0e0f')
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        tag.ndef.octets = HEX('d500110102030405060708090a0b0c0d0e0f1011')
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_without_terminator(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 04 0300d500'), 0.1),
            (HEX('a2 05 03313233'), 0.1),
            (HEX('a2 04 0306d500'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100100"),
            HEX("0305d500 023132fe 00000000 00000000"),
            HEX("0a"), HEX("0a"), HEX("0a"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == HEX('d500023132')
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        tag.ndef.octets = HEX('d50003313233')
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_long_length_field(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 04 0300d000'), 0.1),
            (HEX('30 08'), 0.005),
            (HEX('30 0c'), 0.005),
            (HEX('30 10'), 0.005),
            (HEX('30 14'), 0.005),
            (HEX('30 18'), 0.005),
            (HEX('30 1c'), 0.005),
            (HEX('30 20'), 0.005),
            (HEX('30 24'), 0.005),
            (HEX('30 28'), 0.005),
            (HEX('30 2c'), 0.005),
            (HEX('30 30'), 0.005),
            (HEX('30 34'), 0.005),
            (HEX('30 38'), 0.005),
            (HEX('30 3c'), 0.005),
            (HEX('30 40'), 0.005),
            (HEX('30 44'), 0.005),
            (HEX('a2 05 d500fc00'), 0.1),
            (HEX('a2 44 000000fe'), 0.1),
            (HEX('a2 04 03ff00ff'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1102100"),
            HEX("0303d000 00000000 00000000 00000000"),
            HEX("0a"),
        ] + 16 * [
            HEX("00000000 00000000 00000000 00000000"),
        ] + [
            HEX("0a"), HEX("0a"), HEX("0a"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.octets == HEX('d00000')
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        tag.ndef.octets = HEX('d500fc') + bytearray(252)
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# TYPE 2 TAG MEMORY READER
#
###############################################################################
class TestMemoryReader:
    def test_getitem(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100200"),
            HEX("0303d000 00000000 00000000 00000000"),
        ]
        tag.clf.exchange.side_effect = responses
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
        assert tag_memory[16] == 0x03
        assert tag_memory[17] == 0x03
        assert tag_memory[18] == 0xd0
        assert tag_memory[19] == 0x00
        assert tag_memory[16:20] == HEX('0303d000')
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_setitem(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 04 fe03d000'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100200"),
            HEX("0303d000 00000000 00000000 00000000"),
            HEX("0a"),
        ]
        tag.clf.exchange.side_effect = responses
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
        tag_memory[16] = 0xfe
        tag_memory.synchronize()
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
        tag_memory[16:17] = [0xfe]
        tag_memory.synchronize()
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        commands = commands[:-1]
        responses = responses[:-1]
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
        with pytest.raises(ValueError) as excinfo:
            tag_memory[16:17] = []
        assert str(excinfo.value) == \
            "Type2TagMemoryReader requires item assignment of identical length"
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_delitem(self, tag):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
        with pytest.raises(TypeError) as excinfo:
            del tag_memory[0]
        assert str(excinfo.value) == \
            "Type2TagMemoryReader object does not support item deletion"

    def test_read_error(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('30 04'), 0.005),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100200"),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
        with pytest.raises(nfc.tag.TagCommandError) as excinfo:
            tag_memory[16] = 0xfe
        assert str(excinfo.value) == "unrecoverable timeout error"
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_error(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
            (HEX('a2 04 fe03d000'), 0.1),
            (HEX('a2 04 fe03d000'), 0.1),
            (HEX('a2 04 fe03d000'), 0.1),
        ]
        responses = [
            HEX("01020304 05060708 00000000 E1100200"),
            HEX("0303d000 00000000 00000000 00000000"),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(tag)
        tag_memory[16] = 0xfe
        with pytest.raises(nfc.tag.TagCommandError) as excinfo:
            tag_memory.synchronize()
        assert str(excinfo.value) == "unrecoverable timeout error"
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
