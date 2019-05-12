# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.tag
import nfc.tag.tt1

import mock
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.tag.tt1").setLevel(logging_level)
logging.getLogger("nfc.tag.tt1_broadcom").setLevel(logging_level)


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
    target.sens_res = HEX("000C")
    target.rid_res = HEX("000001020304")
    return target


###############################################################################
#
# TOPAZ
#
###############################################################################
class TestTopaz:
    mmap = HEX(
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
        target.rid_res = HEX("1148 01020304")
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
            HEX("09 12"),  # WRITE-E
            HEX("0d 00"),  # WRITE-E
        ]
        assert tag.format(version=0x12) is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX("00 00 00 01020304"), 0.1),
            mock.call(HEX("53 09 12 01020304"), 0.1),
            mock.call(HEX("53 0d 00 01020304"), 0.1),
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
        commands = [mock.call(HEX("00 00 00 01020304"), 0.1)]
        for addr in range(13, 57):
            cmd = bytearray([0x53, addr, 0, 1, 2, 3, 4])
            commands.append(mock.call(cmd, 0.1))
        assert tag.clf.exchange.mock_calls == commands

    def test_protect_with_defaults(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            HEX("0b 0f"),  # WRITE-E
            HEX("70 ff"),  # WRITE-E
            HEX("71 ff"),  # WRITE-E
        ]
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX("00 00 00 01020304"), 0.1),  # RALL
            mock.call(HEX("1a 0b 0f 01020304"), 0.1),  # WRITE-E
            mock.call(HEX("1a 70 ff 01020304"), 0.1),  # WRITE-E
            mock.call(HEX("1a 71 ff 01020304"), 0.1),  # WRITE-E
        ]

    def test_protect_with_password(self, tag):
        assert tag.protect("abcdefg") is False


###############################################################################
#
# TOPAZ 512
#
###############################################################################
class TestTopaz512:
    mmap = HEX(
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
        target.rid_res = HEX("124c 01020304")
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
            HEX("54 e1123f000103f230"),
            HEX("54 330203f002030300"),
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError
        ]
        assert tag.format(version=0x12) is True
        print(tag.clf.exchange.mock_calls)
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX("00 00 00 01020304"), 0.1),
            mock.call(HEX("54 01 e1123f000103f230 01020304"), 0.1),
            mock.call(HEX("54 02 330203f002030300 01020304"), 0.1),
        ]

    def test_format_invalid_version_number(self, tag):
        tag.clf.exchange.side_effect = [
            tag.target.rid_res[:2] + self.mmap[:120],
        ]
        assert tag.format(version=0xFF) is False

    def test_format_with_wipe_all_zero(self, tag):
        tag.clf.exchange.side_effect = [               # Responses
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            HEX("0F") + self.mmap[120:128],        # READ8(15)
            HEX("10") + self.mmap[128:256],        # RSEG(1)
            HEX("20") + self.mmap[256:384],        # RSEG(2)
            HEX("30") + self.mmap[384:512],        # RSEG(3)
            HEX("54 330203f002030300"),            # WRITE-E8(2)
        ] + [
            HEX("54 0000000000000000") for _ in range(3, 38)
        ]
        assert tag.format(wipe=0) is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX("00 00 00 01020304"), 0.1),
            mock.call(HEX("02 0f 0000000000000000 01020304"), 0.1),
            mock.call(HEX("10 10 0000000000000000 01020304"), 0.1),
            mock.call(HEX("10 20 0000000000000000 01020304"), 0.1),
            mock.call(HEX("10 30 0000000000000000 01020304"), 0.1),
            mock.call(HEX("54 02 330203f002030300 01020304"), 0.1),
        ] + [
            mock.call(HEX("54 %02x 0000000000000000 01020304" % b), 0.1)
            for b in range(3, 13)
        ] + [
            mock.call(HEX("54 %02x 0000000000000000 01020304" % b), 0.1)
            for b in range(16, 38)
        ]

    def test_protect_with_defaults(self, tag):
        tag.clf.exchange.side_effect = [               # Responses
            tag.target.rid_res[:2] + self.mmap[:120],  # RALL
            HEX("0F") + self.mmap[120:128],        # READ8(15)
            HEX("10") + self.mmap[128:256],        # RSEG(1)
            HEX("20") + self.mmap[256:384],        # RSEG(2)
            HEX("0b 0f"),                          # WRITE-NE(11)
            HEX("70 ff"),                          # WRITE-NE(112)
            HEX("71 ff"),                          # WRITE-NE(113)
            HEX("78 ff"),                          # WRITE-NE(120)
            HEX("79 ff"),                          # WRITE-NE(121)
        ] + 30 * [nfc.clf.TimeoutError]
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX("00 00 00 01020304"), 0.1),
            mock.call(HEX("02 0f 0000000000000000 01020304"), 0.1),
            mock.call(HEX("10 10 0000000000000000 01020304"), 0.1),
            mock.call(HEX("10 20 0000000000000000 01020304"), 0.1),
            mock.call(HEX("1a 0b 0f 01020304"), 0.1),
            mock.call(HEX("1a 70 ff 01020304"), 0.1),
            mock.call(HEX("1a 71 ff 01020304"), 0.1),
            mock.call(HEX("1a 78 ff 01020304"), 0.1),
            mock.call(HEX("1a 79 ff 01020304"), 0.1),
        ]

    def test_protect_with_password(self, tag):
        assert tag.protect("abcdefg") is False
