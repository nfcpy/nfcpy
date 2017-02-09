# -*- coding: latin-1 -*-

import nfc
import nfc.tag
import nfc.tag.tt1
import ndef

import pytest
import mock

from pytest_mock import mocker  # noqa: F401


def fromhex(s):
    return bytearray.fromhex(s)


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    return clf


@pytest.fixture()
def target():
    target = nfc.clf.RemoteTarget("106A")
    target.sens_res = fromhex("000C")
    target.rid_res = fromhex("000001020304")
    return target


@pytest.fixture()
def tag(clf, target):
    tag = nfc.tag.activate(clf, target)
    assert isinstance(tag, nfc.tag.tt1.Type1Tag)
    return tag


###############################################################################
#
# TEST TYPE 1 TAG NDEF
#
###############################################################################
class TestStaticMemoryTagNdef:
    @pytest.fixture()
    def mmap(self):
        return fromhex(
            "01 02 03 04  05 06 07 00  E1 1F 0E 00  03 2A D1 01"
            "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
            "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
            "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
            "01 60 00 00  00 00 00 00")

    @pytest.fixture()
    def tag(self, clf, target, mmap):
        target.rid_res = fromhex("110001020304")
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt1.Type1Tag)
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:120],
        ]
        return tag

    @pytest.fixture()
    def ndef_octets(self):
        uri = 'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'
        return b''.join(ndef.message_encoder([ndef.UriRecord(uri)]))

    def test_read_from_static_memory(self, tag, ndef_octets):
        assert tag.ndef is not None
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        assert tag.ndef.capacity == 90
        assert tag.ndef.length == 42
        assert tag.ndef.octets == ndef_octets

    def test_read_proprietary_memory(self, tag, mmap):
        tag.clf.exchange.side_effect = [fromhex("0000") + mmap]
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),  # RALL
        ]

    def test_read_unformatted_memory(self, tag, mmap):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:8] + bytearray(112),
        ]
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),  # RALL
        ]

    def test_read_unknown_ndef_version(self, tag, mmap):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:9] + bytearray(111),
        ]
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),  # RALL
        ]

    def test_read_with_read_failure(self, tag):
        tag.clf.exchange.side_effect = 3 * [nfc.clf.TimeoutError]
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == 3 * [
            mock.call(fromhex("00 00 00 01020304"), 0.1),  # RALL
        ]

    def test_read_ndef_after_null_tlv(self, tag, mmap, ndef_octets):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:12] + b'\x00' + mmap[12:-1]
        ]
        assert tag.ndef is not None
        assert tag.ndef.message == ndef_octets

    def test_read_ndef_after_unknown_tlv(self, tag, mmap, ndef_octets):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:12] + b'\xFD\x01\x00' + mmap[12:-3]
        ]
        assert tag.ndef is not None
        assert tag.ndef.message == ndef_octets

    def test_read_until_terminator_tlv(self, tag, mmap):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:12] + fromhex('FE') + mmap[12:-1]
        ]
        assert tag.ndef is None

    def test_read_beyond_end_of_memory(self, tag, mmap):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:8]
            + fromhex("E1100E00 02032157 03") + mmap[12:-9],
        ] + 3 * [nfc.clf.TimeoutError]
        assert tag.ndef is None

    def test_write_new_ndef_data(self, tag, mmap, ndef_octets):
        assert tag.ndef is not None
        assert tag.ndef.octets == ndef_octets
        tag.clf.exchange.side_effect = [
            fromhex("0d 00"),
            fromhex("0e d0"),
            fromhex("0f 00"),
            fromhex("0d 03"),
            fromhex("10 00"),
            fromhex("11 fe"),
            fromhex("0d 03"),
        ]
        tag.ndef.records = [ndef.Record()]
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex('00 00 00 01020304'), 0.1),
            mock.call(fromhex('53 0d 00 01020304'), 0.1),
            mock.call(fromhex('53 0e d0 01020304'), 0.1),
            mock.call(fromhex('53 0f 00 01020304'), 0.1),
            mock.call(fromhex('53 10 00 01020304'), 0.1),
            mock.call(fromhex('53 11 fe 01020304'), 0.1),
            mock.call(fromhex('53 0d 03 01020304'), 0.1),
        ]
        assert tag.ndef.octets == fromhex("D00000")

    def test_write_without_terminator_tlv(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + fromhex(
                "01 02 03 04  05 06 07 00  e1 10 02 00  03 09 d1 01"
                "05 54 02 65  6e 61 62 FE"
            ),
            fromhex("0d 00"),
            fromhex("10 06"),
            fromhex("17 63"),
            fromhex("0d 0a"),
        ]
        assert tag.ndef is not None
        assert tag.ndef.records == [ndef.TextRecord("ab")]
        tag.ndef.records = [ndef.TextRecord("abc")]
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex('00 00 00 01020304'), 0.1),
            mock.call(fromhex('53 0d 00 01020304'), 0.1),
            mock.call(fromhex('53 10 06 01020304'), 0.1),
            mock.call(fromhex('53 17 63 01020304'), 0.1),
            mock.call(fromhex('53 0d 0a 01020304'), 0.1),
        ]


class TestDynamicMemoryTagNdef:
    @pytest.fixture()
    def mmap(self):
        return fromhex(
            "00 11 22 33  44 55 66 77  E1 1F 3F 00  01 03 F2 30"
            "33 02 03 F0  02 03 03 FF  01 CD C1 01  00 00 01 C6"
            "55 01 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
            "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
            "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
            "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
            "6B 6C 6D 6E  6F 70 71 72  55 55 AA AA  12 49 06 00"
            "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 1
            "73 74 75 76  77 78 79 7A  61 62 63 64  65 66 67 68"
            "69 6A 6B 6C  6D 6E 6F 70  71 72 73 74  75 76 77 78"
            "79 7A 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
            "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
            "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
            "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
            "6B 6C 6D 6E  6F 70 71 72  73 74 75 76  77 78 79 7A"
            "61 62 63 64  65 66 67 68  69 6A 6B 6C  6D 6E 6F 70"
            # Segment 2
            "71 72 73 74  75 76 77 78  79 7A 61 62  63 64 65 66"
            "67 68 69 6A  6B 6C 6D 6E  6F 70 71 72  73 74 75 76"
            "77 78 79 7A  61 62 63 64  65 66 67 68  69 6A 6B 6C"
            "6D 6E 6F 70  71 72 73 74  75 76 77 78  79 7A 61 62"
            "63 64 65 66  67 68 69 6A  6B 6C 6D 6E  6F 70 71 72"
            "73 74 75 76  77 78 79 7A  61 62 63 64  65 66 67 68"
            "69 6A 6B 6C  6D 6E 6F 70  71 72 73 74  75 76 77 78"
            "79 7A 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
            # Segment 3
            "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
            "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
            "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
            "6B 6C 6D 6E  6F 70 71 72  73 74 75 76  77 78 79 7A"
            "61 62 63 64  65 66 67 68  69 6A 6B 6C  6D 6E 6F 70"
            "71 72 73 74  75 76 77 78  79 7A 61 62  63 64 65 66"
            "67 68 69 6A  6B 6C 6D 6E  6F 70 71 72  73 74 75 76"
            "77 78 79 7A  61 62 63 64  65 66 67 2E  63 6F 6D FE")

    @pytest.fixture()
    def tag(self, clf, target, mmap):
        target.rid_res = fromhex("120001020304")
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt1.Type1Tag)
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:120],  # RALL
            fromhex("0F") + mmap[120:128],  # READ8(15)
            fromhex("10") + mmap[128:256],  # RSEG(1)
            fromhex("20") + mmap[256:384],  # RSEG(2)
            fromhex("30") + mmap[384:512],  # RSEG(3)
        ]
        return tag

    @pytest.fixture()
    def ndef_octets(self):
        uri = "http://www." + 17 * "abcdefghijklmnopqrstuvwxyz" + "abcdefg.com"
        return b''.join(ndef.message_encoder([ndef.UriRecord(uri)]))

    def test_read_from_dynamic_memory(self, tag, ndef_octets):
        assert tag.ndef is not None
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        assert tag.ndef.capacity == 462
        assert tag.ndef.length == 461
        assert tag.ndef.octets == ndef_octets

    def test_write_to_dynamic_memory(self, tag, mmap, ndef_octets):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + mmap[:23] + bytearray(489),
            fromhex("54 0000c101000001c6"),  # WRITE-E8
        ] + [
            fromhex("54") + mmap[i*8:i*8+8] for i in range(4, 13)
        ] + [
            fromhex("54") + mmap[i*8:i*8+8] for i in range(16, 64)
        ] + [
            fromhex("54 330203f0020303ff"),  # WRITE-E8
            fromhex("54 01cdc101000001c6"),  # WRITE-E8
        ]
        assert tag.ndef is not None
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        assert tag.ndef.capacity == 462
        assert tag.ndef.length == 0
        assert tag.ndef.octets == b''
        tag.ndef.octets = ndef_octets
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex('00 00 00 01020304'), 0.1),
            mock.call(fromhex('54 03 0000c101000001c6 01020304'), 0.1),
        ] + [
            mock.call(bytearray([84, i]) + mmap[i*8:i*8+8] + b'\1\2\3\4', 0.1)
            for i in range(4, 13)
        ] + [
            mock.call(bytearray([84, i]) + mmap[i*8:i*8+8] + b'\1\2\3\4', 0.1)
            for i in range(16, 64)
        ] + [
            mock.call(fromhex('54 02 330203f0020303ff 01020304'), 0.1),
            mock.call(fromhex('54 03 01cdc101000001c6 01020304'), 0.1),
        ]

    def test_write_terminator_after_skip(self, tag):
        assert tag.ndef is not None
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            fromhex("54 330203f002030300"),  # WRITE-E8(2)
            fromhex("54 d5004d0000000000"),  # WRITE-E8(3)
            fromhex("54 0000000000000000"),  # WRITE-E8(4)
            fromhex("54 0000000000000000"),  # WRITE-E8(5)
            fromhex("54 0000000000000000"),  # WRITE-E8(6)
            fromhex("54 0000000000000000"),  # WRITE-E8(7)
            fromhex("54 0000000000000000"),  # WRITE-E8(8)
            fromhex("54 0000000000000000"),  # WRITE-E8(9)
            fromhex("54 0000000000000000"),  # WRITE-E8(10)
            fromhex("54 0000000000000000"),  # WRITE-E8(11)
            fromhex("54 0000000000000000"),  # WRITE-E8(12)
            fromhex("54 fe7475767778797a"),  # WRITE-E8(16)
            fromhex("54 330203f002030350"),  # WRITE-E8(2)
        ]
        tag.ndef.records = [ndef.Record('unknown', data=bytearray(5+9*8))]
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex('54 02 330203f002030300 01020304'), 0.1),
            mock.call(fromhex('54 03 d5004d0000000000 01020304'), 0.1),
            mock.call(fromhex('54 04 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 05 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 06 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 07 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 08 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 09 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 0a 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 0b 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 0c 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 10 fe7475767778797a 01020304'), 0.1),
            mock.call(fromhex('54 02 330203f002030350 01020304'), 0.1),
        ]


###############################################################################
#
# TEST TYPE 1 TAG COMMANDS
#
###############################################################################
class TestTagCommands:
    mmap = fromhex(
        "31 32 33 34  35 36 37 00  E1 10 3F 00  01 03 F2 30"
        "33 02 03 F0  02 03 03 FE  D1 01 FA 55  01 61 62 63"
        "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
        "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
        "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
        "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
        "70 71 72 73  74 75 76 77  55 55 AA AA  12 49 06 00"
        "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        # Segment 1
        "78 79 7A 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
        "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
        "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
        "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
        "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
        "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
        "70 71 72 73  74 75 76 77  78 79 7A 61  62 63 64 65"
        "66 67 68 69  6A 6B 6C 6D  6E 6F 70 71  72 73 74 75"
        # Segment 2
        "76 77 78 79  7A 61 62 63  64 65 66 67  68 69 6A 6B"
        "6C 6D 6E 6F  70 71 72 73  74 75 76 77  78 79 7A 61"
        "62 63 64 65  66 67 68 69  6A 6B 2E 63  6F 6D FE 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        # Segment 3
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    )

    def test_read_id(self, tag):
        cmd = fromhex("78 00 00 00000000")
        rsp = fromhex("0000 01020304")
        tag.clf.exchange.return_value = rsp
        assert tag.read_id() == rsp
        tag.clf.exchange.assert_called_once_with(cmd, 0.1)

    def test_read_all(self, tag):
        cmd = fromhex("00 00 00 01020304")
        rsp = fromhex("0000") + self.mmap[:120]
        tag.clf.exchange.return_value = rsp
        assert tag.read_all() == rsp
        tag.clf.exchange.assert_called_once_with(cmd, 0.1)

    def test_read_byte(self, tag):
        cmd = fromhex("01 08 00 01020304")
        rsp = fromhex("08 E1")
        tag.clf.exchange.return_value = rsp
        assert tag.read_byte(8) == 0xE1
        tag.clf.exchange.assert_called_once_with(cmd, 0.1)

        with pytest.raises(ValueError) as excinfo:
            tag.read_byte(128)
        assert str(excinfo.value) == "invalid byte address"

    def test_read_block(self, tag):
        cmd = fromhex("02 01 0000000000000000 01020304")
        rsp = fromhex("02") + self.mmap[8:16]
        tag.clf.exchange.return_value = rsp
        assert tag.read_block(1) == self.mmap[8:16]
        tag.clf.exchange.assert_called_once_with(cmd, 0.1)

        with pytest.raises(ValueError) as excinfo:
            tag.read_block(256)
        assert str(excinfo.value) == "invalid block number"

    def test_read_segment(self, tag):
        cmd = fromhex("10 10 0000000000000000 01020304")
        rsp = fromhex("02") + self.mmap[128:256]
        tag.clf.exchange.return_value = rsp
        assert tag.read_segment(1) == self.mmap[128:256]
        tag.clf.exchange.assert_called_once_with(cmd, 0.1)

        with pytest.raises(ValueError) as excinfo:
            tag.read_segment(16)
        assert str(excinfo.value) == "invalid segment number"

        tag.clf.exchange.return_value = rsp[:-1]
        with pytest.raises(nfc.tag.tt1.Type1TagCommandError) as excinfo:
            tag.read_segment(1)
        assert str(excinfo.value) == "invalid response data"

    def test_write_byte(self, tag):
        cmd = fromhex("53 08 E0 01020304")
        rsp = fromhex("08 E0")
        tag.clf.exchange.return_value = rsp
        tag.write_byte(8, 0xE0)
        tag.clf.exchange.assert_called_with(cmd, 0.1)

        cmd = fromhex("1A 08 E0 01020304")
        tag.write_byte(8, 0xE0, erase=False)
        tag.clf.exchange.assert_called_with(cmd, 0.1)

        with pytest.raises(ValueError) as excinfo:
            tag.write_byte(128, 0xFF)
        assert str(excinfo.value) == "invalid byte address"

    def test_write_block(self, tag):
        cmd = fromhex("54 01 0000000000000000 01020304")
        rsp = fromhex("54 0000000000000000")
        tag.clf.exchange.return_value = rsp
        tag.write_block(1, bytearray(8))
        tag.clf.exchange.assert_called_with(cmd, 0.1)

        cmd = fromhex("1B 01 0000000000000000 01020304")
        tag.write_block(1, bytearray(8), erase=False)
        tag.clf.exchange.assert_called_with(cmd, 0.1)

        with pytest.raises(ValueError) as excinfo:
            tag.write_block(256, bytearray(8))
        assert str(excinfo.value) == "invalid block number"

        tag.clf.exchange.return_value = rsp[:-1]
        with pytest.raises(nfc.tag.tt1.Type1TagCommandError) as excinfo:
            tag.write_block(1, bytearray(8))
        assert str(excinfo.value) == "invalid response data"

        cmd = fromhex("54 01 0000000000000000 01020304")
        rsp = fromhex("54 FFFFFFFFFFFFFFFF")
        tag.clf.exchange.return_value = rsp
        with pytest.raises(nfc.tag.tt1.Type1TagCommandError) as excinfo:
            tag.write_block(1, bytearray(8))
        assert str(excinfo.value) == "data write failure"

    @pytest.mark.parametrize("exception, message", [
        (nfc.clf.TimeoutError, "unrecoverable timeout error"),
        (nfc.clf.TransmissionError, "unrecoverable transmission error"),
        (nfc.clf.ProtocolError, "unrecoverable protocol error"),
    ])
    def test_transceive_error(self, tag, exception, message):
        tag.clf.exchange.side_effect = exception
        with pytest.raises(nfc.tag.tt1.Type1TagCommandError) as excinfo:
            tag.transceive(bytearray(8))
        assert str(excinfo.value) == message
        assert tag.clf.exchange.call_count == 3


###############################################################################
#
# TEST TYPE 1 TAG PROCEDURES
#
###############################################################################
class TestTagProcedures:
    mmap = fromhex(
        "01 02 03 04  05 06 07 00  E1 10 3F 00  01 03 F2 30"
        "33 02 03 F0  02 03 03 FE  D1 01 FA 55  01 61 62 63"
        "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
        "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
        "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
        "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
        "70 71 72 73  74 75 76 77  55 55 AA AA  12 49 06 00"
        "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        # Segment 1
        "78 79 7A 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
        "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
        "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
        "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
        "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
        "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
        "70 71 72 73  74 75 76 77  78 79 7A 61  62 63 64 65"
        "66 67 68 69  6A 6B 6C 6D  6E 6F 70 71  72 73 74 75"
        # Segment 2
        "76 77 78 79  7A 61 62 63  64 65 66 67  68 69 6A 6B"
        "6C 6D 6E 6F  70 71 72 73  74 75 76 77  78 79 7A 61"
        "62 63 64 65  66 67 68 69  6A 6B 2E 63  6F 6D FE 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        # Segment 3
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    )

    def test_tag_is_present(self, tag):
        cmd = fromhex("01 00 00 01020304")
        rsp = fromhex("00 01")
        tag.clf.exchange.return_value = rsp
        assert tag.is_present is True
        tag.clf.exchange.assert_called_once_with(cmd, 0.1)

        tag.clf.exchange.side_effect = nfc.clf.TimeoutError
        assert tag.is_present is False
        assert tag.clf.exchange.call_count == 4

    def test_dump_tag_with_15_blocks(self, tag):
        tag.clf.exchange.side_effect = [               # Response
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        assert tag.dump() == [
            "HR0=00h, HR1=00h",
            "  0: 01 02 03 04 05 06 07 00 (UID0-UID6, RESERVED)",
            "  1: e1 10 3f 00 01 03 f2 30 |..?....0|",
            "  2: 33 02 03 f0 02 03 03 fe |3.......|",
            "  3: d1 01 fa 55 01 61 62 63 |...U.abc|",
            "  4: 64 65 66 67 68 69 6a 6b |defghijk|",
            "  5: 6c 6d 6e 6f 70 71 72 73 |lmnopqrs|",
            "  6: 74 75 76 77 78 79 7a 61 |tuvwxyza|",
            "  7: 62 63 64 65 66 67 68 69 |bcdefghi|",
            "  8: 6a 6b 6c 6d 6e 6f 70 71 |jklmnopq|",
            "  9: 72 73 74 75 76 77 78 79 |rstuvwxy|",
            " 10: 7a 61 62 63 64 65 66 67 |zabcdefg|",
            " 11: 68 69 6a 6b 6c 6d 6e 6f |hijklmno|",
            " 12: 70 71 72 73 74 75 76 77 |pqrstuvw|",
            " 13: 55 55 aa aa 12 49 06 00 (RESERVED)",
            " 14: 01 e0 00 00 00 00 00 00 (LOCK0-LOCK1, OTP0-OTP5)",
        ]

    def test_dump_tag_with_16_blocks(self, tag):
        tag.clf.exchange.side_effect = [               # Response
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            fromhex("0F") + self.mmap[120:128],        # READ8(15)
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        assert tag.dump() == [
            "HR0=00h, HR1=00h",
            "  0: 01 02 03 04 05 06 07 00 (UID0-UID6, RESERVED)",
            "  1: e1 10 3f 00 01 03 f2 30 |..?....0|",
            "  2: 33 02 03 f0 02 03 03 fe |3.......|",
            "  3: d1 01 fa 55 01 61 62 63 |...U.abc|",
            "  4: 64 65 66 67 68 69 6a 6b |defghijk|",
            "  5: 6c 6d 6e 6f 70 71 72 73 |lmnopqrs|",
            "  6: 74 75 76 77 78 79 7a 61 |tuvwxyza|",
            "  7: 62 63 64 65 66 67 68 69 |bcdefghi|",
            "  8: 6a 6b 6c 6d 6e 6f 70 71 |jklmnopq|",
            "  9: 72 73 74 75 76 77 78 79 |rstuvwxy|",
            " 10: 7a 61 62 63 64 65 66 67 |zabcdefg|",
            " 11: 68 69 6a 6b 6c 6d 6e 6f |hijklmno|",
            " 12: 70 71 72 73 74 75 76 77 |pqrstuvw|",
            " 13: 55 55 aa aa 12 49 06 00 (RESERVED)",
            " 14: 01 e0 00 00 00 00 00 00 (LOCK0-LOCK1, OTP0-OTP5)",
            " 15: 00 00 00 00 00 00 00 00 (LOCK2-LOCK3, RESERVED)",
        ]

    def test_dump_tag_with_17_blocks(self, tag):
        tag.clf.exchange.side_effect = [               # Response
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            fromhex("0F") + self.mmap[120:128],        # READ8(15)
            fromhex("10") + self.mmap[128:136],        # READ8(16)
            fromhex("54 8786859e9d9c9b9a"),            # WRITE-E8(16)
            fromhex("54 78797A6162636465"),            # WRITE-E8(16)
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        assert tag.dump() == [
            "HR0=00h, HR1=00h",
            "  0: 01 02 03 04 05 06 07 00 (UID0-UID6, RESERVED)",
            "  1: e1 10 3f 00 01 03 f2 30 |..?....0|",
            "  2: 33 02 03 f0 02 03 03 fe |3.......|",
            "  3: d1 01 fa 55 01 61 62 63 |...U.abc|",
            "  4: 64 65 66 67 68 69 6a 6b |defghijk|",
            "  5: 6c 6d 6e 6f 70 71 72 73 |lmnopqrs|",
            "  6: 74 75 76 77 78 79 7a 61 |tuvwxyza|",
            "  7: 62 63 64 65 66 67 68 69 |bcdefghi|",
            "  8: 6a 6b 6c 6d 6e 6f 70 71 |jklmnopq|",
            "  9: 72 73 74 75 76 77 78 79 |rstuvwxy|",
            " 10: 7a 61 62 63 64 65 66 67 |zabcdefg|",
            " 11: 68 69 6a 6b 6c 6d 6e 6f |hijklmno|",
            " 12: 70 71 72 73 74 75 76 77 |pqrstuvw|",
            " 13: 55 55 aa aa 12 49 06 00 (RESERVED)",
            " 14: 01 e0 00 00 00 00 00 00 (LOCK0-LOCK1, OTP0-OTP5)",
            " 15: 00 00 00 00 00 00 00 00 (LOCK2-LOCK3, RESERVED)",
            " 16: 78 79 7a 61 62 63 64 65 |xyzabcde|",
        ]
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),
            mock.call(fromhex('02 0f 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('02 10 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('54 10 8786859e9d9c9b9a 01020304'), 0.1),
            mock.call(fromhex('54 10 78797A6162636465 01020304'), 0.1),
            mock.call(fromhex('02 11 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('02 11 0000000000000000 01020304'), 0.1),
            mock.call(fromhex('02 11 0000000000000000 01020304'), 0.1),
        ]

    def test_protect_default(self, tag):
        tag.clf.exchange.side_effect = [
            fromhex("1200") + self.mmap[:120],   # RALL
            fromhex("0F") + self.mmap[120:128],  # READ8(15)
            fromhex("10") + self.mmap[128:256],  # RSEG(1)
            fromhex("20") + self.mmap[256:384],  # RSEG(2)
            fromhex("30") + self.mmap[384:512],  # RSEG(3)
            fromhex("0B 0F"),                    # WRITE-NE(11)
        ]
        assert tag.protect() is True
        tag.clf.exchange.assert_called_with(fromhex("1A 0B 0F 01020304"), 0.1)

    def test_protect_password(self, tag):
        assert tag.protect("abcdefg") is False

    def test_protect_not_ndef(self, tag):
        tag.clf.exchange.side_effect = [
            fromhex("1200") + self.mmap[:8] + b"\0" + self.mmap[9:120],
        ]
        assert tag.protect() is False

    def test_format_tag(self, tag):
        assert tag.format() is None


###############################################################################
#
# TEST TYPE 1 TAG TOPAZ
#
###############################################################################
class TestTopaz:
    mmap = fromhex(
        "01 02 03 04  05 06 07 00  E1 10 0E 00  03 2A D1 01"
        "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
        "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
        "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
        "01 60 00 00  00 00 00 00"
    )

    @pytest.fixture()
    def tag(self, clf, target):
        target.rid_res = fromhex("1148 01020304")
        topaz_120 = nfc.tag.activate(clf, target)
        assert topaz_120.product == "Topaz (BCM20203T96)"
        return topaz_120

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
        ]
        assert tag.dump() == [
            "HR0=11h, HR1=48h",
            "  0: 01 02 03 04 05 06 07 00 (UID0-UID6, RESERVED)",
            "  1: e1 10 0e 00 03 2a d1 01 |.....*..|",
            "  2: 26 55 01 61 62 63 64 65 |&U.abcde|",
            "  3: 66 67 68 69 6a 6b 6c 6d |fghijklm|",
            "  4: 6e 6f 70 71 72 73 74 75 |nopqrstu|",
            "  5: 76 77 78 79 7a 61 62 63 |vwxyzabc|",
            "  6: 64 65 66 67 2e 63 6f 6d |defg.com|",
            "  7: fe 00 00 00 00 00 00 00 |........|",
            "  8: 00 00 00 00 00 00 00 00 |........|",
            "  9: 00 00 00 00 00 00 00 00 |........|",
            " 10: 00 00 00 00 00 00 00 00 |........|",
            " 11: 00 00 00 00 00 00 00 00 |........|",
            " 12: 00 00 00 00 00 00 00 00 |........|",
            " 13: 55 55 aa aa 00 00 00 00 (RESERVED)",
            " 14: 01 60 00 00 00 00 00 00 (LOCK0-LOCK1, OTP0-OTP5)",
        ]

    def test_format_with_version_one_dot_two(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            fromhex("09 12"),  # WRITE-E
            fromhex("0d 00"),  # WRITE-E
        ]
        assert tag.format(version=0x12) is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),
            mock.call(fromhex("53 09 12 01020304"), 0.1),
            mock.call(fromhex("53 0d 00 01020304"), 0.1),
        ]

    def test_format_invalid_version_number(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
        ]
        assert tag.format(version=0xFF) is False

    def test_format_with_wipe_all_zero(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
        ] + [bytearray([addr, 0]) for addr in range(13, 57)]  # WRITE-E
        assert tag.format(wipe=0) is True
        commands = [mock.call(fromhex("00 00 00 01020304"), 0.1)]
        for addr in range(13, 57):
            cmd = bytearray([0x53, addr, 0, 1, 2, 3, 4])
            commands.append(mock.call(cmd, 0.1))
        assert tag.clf.exchange.mock_calls == commands

    def test_protect_with_defaults(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            fromhex("0b 0f"),  # WRITE-E
            fromhex("70 ff"),  # WRITE-E
            fromhex("71 ff"),  # WRITE-E
        ]
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),  # RALL
            mock.call(fromhex("1a 0b 0f 01020304"), 0.1),  # WRITE-E
            mock.call(fromhex("1a 70 ff 01020304"), 0.1),  # WRITE-E
            mock.call(fromhex("1a 71 ff 01020304"), 0.1),  # WRITE-E
        ]

    def test_protect_with_password(self, tag):
        assert tag.protect("abcdefg") is False


###############################################################################
#
# TEST TYPE 1 TAG TOPAZ 512
#
###############################################################################
class TestTopaz512:
    mmap = bytearray.fromhex(
        "31 32 33 34  35 36 37 00  E1 10 3F 00  01 03 F2 30"
        "33 02 03 F0  02 03 03 FE  D1 01 FA 55  01 61 62 63"
        "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
        "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
        "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
        "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
        "70 71 72 73  74 75 76 77  55 55 AA AA  12 49 06 00"
        "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        # Segment 1
        "78 79 7A 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
        "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
        "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
        "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
        "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
        "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
        "70 71 72 73  74 75 76 77  78 79 7A 61  62 63 64 65"
        "66 67 68 69  6A 6B 6C 6D  6E 6F 70 71  72 73 74 75"
        # Segment 2
        "76 77 78 79  7A 61 62 63  64 65 66 67  68 69 6A 6B"
        "6C 6D 6E 6F  70 71 72 73  74 75 76 77  78 79 7A 61"
        "62 63 64 65  66 67 68 69  6A 6B 2E 63  6F 6D FE 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        # Segment 3
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    )

    @pytest.fixture()
    def tag(self, clf, target):
        target.rid_res = fromhex("124c 01020304")
        topaz_512 = nfc.tag.activate(clf, target)
        assert topaz_512.product == "Topaz 512 (BCM20203T512)"
        return topaz_512

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
        ] + [
            (bytearray([x]) + self.mmap[8*x:8*x+8]) for x in range(15, 64)
        ]
        assert tag.dump() == [
            "HR0=12h, HR1=4Ch",
            "  0: 31 32 33 34 35 36 37 00 (UID0-UID6, RESERVED)",
            "  1: e1 10 3f 00 01 03 f2 30 |..?....0|",
            "  2: 33 02 03 f0 02 03 03 fe |3.......|",
            "  3: d1 01 fa 55 01 61 62 63 |...U.abc|",
            "  4: 64 65 66 67 68 69 6a 6b |defghijk|",
            "  5: 6c 6d 6e 6f 70 71 72 73 |lmnopqrs|",
            "  6: 74 75 76 77 78 79 7a 61 |tuvwxyza|",
            "  7: 62 63 64 65 66 67 68 69 |bcdefghi|",
            "  8: 6a 6b 6c 6d 6e 6f 70 71 |jklmnopq|",
            "  9: 72 73 74 75 76 77 78 79 |rstuvwxy|",
            " 10: 7a 61 62 63 64 65 66 67 |zabcdefg|",
            " 11: 68 69 6a 6b 6c 6d 6e 6f |hijklmno|",
            " 12: 70 71 72 73 74 75 76 77 |pqrstuvw|",
            " 13: 55 55 aa aa 12 49 06 00 (RESERVED)",
            " 14: 01 e0 00 00 00 00 00 00 (LOCK0-LOCK1, OTP0-OTP5)",
            " 15: 00 00 00 00 00 00 00 00 (LOCK2-LOCK3, RESERVED)",
            " 16: 78 79 7a 61 62 63 64 65 |xyzabcde|",
            " 17: 66 67 68 69 6a 6b 6c 6d |fghijklm|",
            " 18: 6e 6f 70 71 72 73 74 75 |nopqrstu|",
            " 19: 76 77 78 79 7a 61 62 63 |vwxyzabc|",
            " 20: 64 65 66 67 68 69 6a 6b |defghijk|",
            " 21: 6c 6d 6e 6f 70 71 72 73 |lmnopqrs|",
            " 22: 74 75 76 77 78 79 7a 61 |tuvwxyza|",
            " 23: 62 63 64 65 66 67 68 69 |bcdefghi|",
            " 24: 6a 6b 6c 6d 6e 6f 70 71 |jklmnopq|",
            " 25: 72 73 74 75 76 77 78 79 |rstuvwxy|",
            " 26: 7a 61 62 63 64 65 66 67 |zabcdefg|",
            " 27: 68 69 6a 6b 6c 6d 6e 6f |hijklmno|",
            " 28: 70 71 72 73 74 75 76 77 |pqrstuvw|",
            " 29: 78 79 7a 61 62 63 64 65 |xyzabcde|",
            " 30: 66 67 68 69 6a 6b 6c 6d |fghijklm|",
            " 31: 6e 6f 70 71 72 73 74 75 |nopqrstu|",
            " 32: 76 77 78 79 7a 61 62 63 |vwxyzabc|",
            " 33: 64 65 66 67 68 69 6a 6b |defghijk|",
            " 34: 6c 6d 6e 6f 70 71 72 73 |lmnopqrs|",
            " 35: 74 75 76 77 78 79 7a 61 |tuvwxyza|",
            " 36: 62 63 64 65 66 67 68 69 |bcdefghi|",
            " 37: 6a 6b 2e 63 6f 6d fe 00 |jk.com..|",
            " 38: 00 00 00 00 00 00 00 00 |........|",
            "  *  00 00 00 00 00 00 00 00 |........|",
            " 63: 00 00 00 00 00 00 00 00 |........|",
        ]

    def test_format_with_version_one_dot_two(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],
            fromhex("54 e1123f000103f230"),
            fromhex("54 330203f002030300"),
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError
        ]
        assert tag.format(version=0x12) is True
        print(tag.clf.exchange.mock_calls)
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),
            mock.call(fromhex("54 01 e1123f000103f230 01020304"), 0.1),
            mock.call(fromhex("54 02 330203f002030300 01020304"), 0.1),
        ]

    def test_format_invalid_version_number(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],
        ]
        assert tag.format(version=0xFF) is False

    def test_format_with_wipe_all_zero(self, tag):
        tag.clf.exchange.side_effect = [               # Responses
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            fromhex("0F") + self.mmap[120:128],        # READ8(15)
            fromhex("10") + self.mmap[128:256],        # RSEG(1)
            fromhex("20") + self.mmap[256:384],        # RSEG(2)
            fromhex("30") + self.mmap[384:512],        # RSEG(3)
            fromhex("54 330203f002030300"),            # WRITE-E8(2)
        ] + [
            fromhex("54 0000000000000000") for _ in range(3, 38)
        ]
        assert tag.format(wipe=0) is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),
            mock.call(fromhex("02 0f 0000000000000000 01020304"), 0.1),
            mock.call(fromhex("10 10 0000000000000000 01020304"), 0.1),
            mock.call(fromhex("10 20 0000000000000000 01020304"), 0.1),
            mock.call(fromhex("10 30 0000000000000000 01020304"), 0.1),
            mock.call(fromhex("54 02 330203f002030300 01020304"), 0.1),
        ] + [
            mock.call(fromhex("54 %02x 0000000000000000 01020304" % b), 0.1)
            for b in range(3, 13)
        ] + [
            mock.call(fromhex("54 %02x 0000000000000000 01020304" % b), 0.1)
            for b in range(16, 38)
        ]

    def test_protect_with_defaults(self, tag):
        tag.clf.exchange.side_effect = [               # Responses
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            fromhex("0F") + self.mmap[120:128],        # READ8(15)
            fromhex("10") + self.mmap[128:256],        # RSEG(1)
            fromhex("20") + self.mmap[256:384],        # RSEG(2)
            fromhex("0b 0f"),                          # WRITE-NE(11)
            fromhex("70 ff"),                          # WRITE-NE(112)
            fromhex("71 ff"),                          # WRITE-NE(113)
            fromhex("78 ff"),                          # WRITE-NE(120)
            fromhex("79 ff"),                          # WRITE-NE(121)
        ] + 30 * [nfc.clf.TimeoutError]
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(fromhex("00 00 00 01020304"), 0.1),
            mock.call(fromhex("02 0f 0000000000000000 01020304"), 0.1),
            mock.call(fromhex("10 10 0000000000000000 01020304"), 0.1),
            mock.call(fromhex("10 20 0000000000000000 01020304"), 0.1),
            mock.call(fromhex("1a 0b 0f 01020304"), 0.1),
            mock.call(fromhex("1a 70 ff 01020304"), 0.1),
            mock.call(fromhex("1a 71 ff 01020304"), 0.1),
            mock.call(fromhex("1a 78 ff 01020304"), 0.1),
            mock.call(fromhex("1a 79 ff 01020304"), 0.1),
        ]

    def test_protect_with_password(self, tag):
        assert tag.protect("abcdefg") is False


###############################################################################
#
# TEST TYPE 1 TAG MEMORY READER
#
###############################################################################
class TestMemoryReader:
    mmap = fromhex(
        "01 02 03 04  05 06 07 00  E1 10 1F 00  03 2A D1 01"
        "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
        "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
        "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
        "01 60 00 00  00 00 00 00  12 00 00 00  00 00 00 00"
        # Segment 1
        "34 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    )

    @pytest.mark.parametrize("offset", [0, 1, 120, 121, 128, 129, 255])
    def test_byte_access_at_offset(self, tag, offset):
        tag.clf.exchange.side_effect = [
            fromhex("1200") + self.mmap[:120],   # RALL
            fromhex("0F") + self.mmap[120:128],  # READ8(15)
            fromhex("10") + self.mmap[128:256],  # RSEG(1)
        ]
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        assert tag_memory[offset] == self.mmap[offset]
        assert tag.clf.exchange.mock_calls[0] == \
            mock.call(fromhex('00 00 00 01020304'), 0.1)
        if offset >= 120:
            read8 = fromhex('02 0f 00000000 00000000 01020304')
            assert tag.clf.exchange.mock_calls[1] == mock.call(read8, 0.1)
        if offset >= 128:
            rseg = fromhex('10 10 00000000 00000000 01020304')
            assert tag.clf.exchange.mock_calls[2] == mock.call(rseg, 0.1)

    @pytest.mark.parametrize("offset", [0, 1, 120, 121, 128, 129, 255])
    def test_slice_access_at_offset(self, tag, offset):
        tag.clf.exchange.side_effect = [
            fromhex("1200") + self.mmap[:120],   # RALL
            fromhex("0F") + self.mmap[120:128],  # READ8(15)
            fromhex("10") + self.mmap[128:256],  # RSEG(1)
        ]
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        assert tag_memory[offset:offset+1] == self.mmap[offset:offset+1]
        assert tag.clf.exchange.mock_calls[0] == \
            mock.call(fromhex('00 00 00 01020304'), 0.1)
        if offset >= 120:
            read8 = fromhex('02 0f 00000000 00000000 01020304')
            assert tag.clf.exchange.mock_calls[1] == mock.call(read8, 0.1)
        if offset >= 128:
            rseg = fromhex('10 10 00000000 00000000 01020304')
            assert tag.clf.exchange.mock_calls[2] == mock.call(rseg, 0.1)

    def test_synchronize_with_small_tag(self, tag):
        tag.clf.exchange.side_effect = [
            b"\x11\x00" + self.mmap[:120],  # RALL
            b"\x00" + b'\xA5',              # WRITE-E
            b"\x0F" + b'\x5A',              # WRITE-E
        ]
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        tag_memory[0] = 0xA5
        tag_memory[15] = 0x5A
        tag_memory.synchronize()
        assert tag.clf.exchange.mock_calls[0] == \
            mock.call(fromhex('00 00 00 01020304'), 0.1)
        assert tag.clf.exchange.mock_calls[1] == \
            mock.call(fromhex('53 00 A5 01020304'), 0.1)
        assert tag.clf.exchange.mock_calls[2] == \
            mock.call(fromhex('53 0F 5A 01020304'), 0.1)

    def test_synchronize_with_large_tag(self, tag):
        tag.clf.exchange.side_effect = [
            b"\x12\x00" + self.mmap[:120],           # RALL
            b"\x0F" + self.mmap[120:128],            # READ8(15)
            b"\x10" + self.mmap[128:256],            # RSEG(1)
            b"\x54" + b'\xFF' + self.mmap[1:8],      # WRITE-E8
            b"\x54" + b'\xFF' + self.mmap[129:136],  # WRITE-E8
        ]
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        assert tag_memory[0:256] == self.mmap  # force read all memory
        tag_memory[0] = 0xFF
        tag_memory[128] = 0xFF
        tag_memory.synchronize()
        tag.clf.exchange.assert_has_calls([
            mock.call(fromhex('00 00 00 01020304'), 0.1),
            mock.call(fromhex('02 0f 00000000 00000000 01020304'), 0.1),
            mock.call(fromhex('10 10 00000000 00000000 01020304'), 0.1),
            mock.call(fromhex('54 00 FF020304 05060700 01020304'), 0.1),
            mock.call(fromhex('54 10 FF000000 00000000 01020304'), 0.1),
        ])

    def test_byte_delete_raises_error(self, tag):
        tag.clf.exchange.return_value = b"\x11\x00" + self.mmap[:120]  # RALL
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        with pytest.raises(TypeError) as excinfo:
            del tag_memory[0]
        assert str(excinfo.value) == \
            "Type1TagMemoryReader object does not support item deletion"

    def test_slice_assign_with_different_length(self, tag):
        tag.clf.exchange.return_value = b"\x11\x00" + self.mmap[:120]  # RALL
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        with pytest.raises(ValueError) as excinfo:
            tag_memory[0:2] = "\x00\x11\x22"
        assert str(excinfo.value) == \
            "Type1TagMemoryReader requires item assignment of identical length"

    @pytest.mark.parametrize("offset", [0, 120, 128])
    def test_read_mute_tag_at_offset(self, tag, offset):
        tag.clf.exchange.side_effect \
            = nfc.tag.tt1.Type1TagCommandError(nfc.tag.TIMEOUT_ERROR)
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        tag_memory._data_from_tag = self.mmap[:offset]
        with pytest.raises(IndexError):
            tag_memory[offset]

    def test_write_raises_command_error(self, tag):
        tag.clf.exchange.side_effect = [
            b"\x12\x00" + self.mmap[:120],           # RALL
            b"\x0F" + self.mmap[120:128],            # READ8(15)
            b"\x10" + self.mmap[128:256],            # RSEG(1)
            b''
        ]
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(tag)
        tag_memory[128] = 0x5A
        tag_memory.synchronize()
        tag.clf.exchange.assert_has_calls([
            mock.call(fromhex('00 00 00 01020304'), 0.1),
            mock.call(fromhex('02 0f 00000000 00000000 01020304'), 0.1),
            mock.call(fromhex('10 10 00000000 00000000 01020304'), 0.1),
            mock.call(fromhex('54 10 5A000000 00000000 01020304'), 0.1),
        ])
