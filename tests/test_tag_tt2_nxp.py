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
    target.sdd_res = HEX("04517CA1E1ED2580")
    return target


@pytest.fixture()  # noqa: F811
def clf(mocker, target):
    mocker.patch('os.urandom', new=lambda n: bytes(bytearray(range(n))))

    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch.object(clf, 'sense', autospec=True)
    clf.sense.return_value = target

    return clf


###############################################################################
#
# MIFARE ULTRALIGHT
#
###############################################################################
class TestUltralight:
    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.MifareUltralight)
        assert tag.product == "Mifare Ultralight (MF01CU1)"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX('04517ca1 e1ed2580 83480000 00000000'),
            HEX('e1ed2580 83480000 00000000 ffffffff'),
            HEX('83480000 00000000 ffffffff 00000000'),
            HEX('00000000 ffffffff 00000000 00000000'),
            HEX('ffffffff 00000000 00000000 00000000'),
        ] + 11 * [
            HEX('00000000 00000000 00000000 00000000'),
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: 83 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: 00 00 00 00 (OTP0-OTP3)",
            "004: ff ff ff ff |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "00F: 00 00 00 00 |....|",
        ]


###############################################################################
#
# MIFARE ULTRALIGHT C
#
###############################################################################
class TestUltralightC:
    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('aff7dfc7fa617c7f1d'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.MifareUltralightC)
        assert tag.product == "Mifare Ultralight C (MF01CU2)"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX('04517ca1 e1ed2580 01480000 00000000'),
            HEX('e1ed2580 01480000 00000000 02000010'),
            HEX('01480000 00000000 02000010 00060110'),
            HEX('00000000 02000010 00060110 11ff0000'),
            HEX('02000010 00060110 11ff0000 00000000'),
            HEX('00060110 11ff0000 00000000 00000000'),
            HEX('11ff0000 00000000 00000000 00000000'),
        ] + 33 * [
            HEX('00000000 00000000 00000000 00000000'),
        ] + 4 * [
            HEX('00'),
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: 01 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: 00 00 00 00 (OTP0-OTP3)",
            "004: 02 00 00 10 |....|",
            "005: 00 06 01 10 |....|",
            "006: 11 ff 00 00 |....|",
            "007: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "027: 00 00 00 00 |....|",
            "028: ?? ?? ?? ?? (LOCK2-LOCK3)",
            "029: ?? ?? ?? ?? (CTR0-CTR1)",
            "02A: ?? ?? ?? ?? (AUTH0)",
            "02B: ?? ?? ?? ?? (AUTH1)",
        ]

    @pytest.mark.parametrize("password", [
        b'', b'IEMKAERB!NACUOYF', b'IEMKAERB!NACUOYF+ignored',
    ])
    def test_authenticate(self, tag, password):
        commands = [
            (HEX('1a 00'), 0.1),
            (HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
        ]
        responses = [
            HEX('af f7dfc7fa 617c7f1d'),
            HEX('00 0355f3c1 76dcd1b1'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate(password) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_authenticate_failure(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.authenticate(b'too-short')
        assert str(excinfo.value) == "password must be at least 16 byte"

        commands = [
            (HEX('1a 00'), 0.1),
            (HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
            (HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
            (HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
        ]
        responses = [
            HEX('af f7dfc7fa 617c7f1d'),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate(b'') is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_lockbits(self, tag):
        commands = [
            (HEX('30 03'), 0.005),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('a2 28 ffff0000'), 0.1),
        ]
        responses = [
            HEX('00000000 00000000 00000000 00000000'),  # Block 3-6
            HEX('0a'), HEX('0a'),  # ACK
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect(None) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        commands = [
            (HEX('30 03'), 0.005),
            (HEX('a2 03 e110000f'), 0.1),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('a2 28 ffff0000'), 0.1),
        ]
        responses = [
            HEX('E1100000 00000000 00000000 00000000'),  # pages 3-6
            HEX('0a'), HEX('0a'), HEX('0a'),  # ACK
        ]
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.protect(None) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        commands = [
            (HEX('30 03'), 0.005),
            (HEX('30 03'), 0.005),
            (HEX('30 03'), 0.005),
        ]
        responses = [
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.protect(None) is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    @pytest.mark.parametrize("pwd, cc, auth", [  # noqa: F811
        (b'', 'E11000', True),
        (b'IEMKAERB!NACUOYF', 'E11000', True),
        (b'IEMKAERB!NACUOYF+ignored', 'E11000', True),
        (b'', '000000', True),
        (b'', 'E11000', False),
    ])
    def test_protect_with_password(self, mocker, tag, pwd, cc, auth):
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = auth

        commands = [
            (HEX('a2 2c 42524541'), 0.1),  # write page 44
            (HEX('a2 2d 4b4d4549'), 0.1),  # write page 45
            (HEX('a2 2e 46594f55'), 0.1),  # write page 46
            (HEX('a2 2f 43414e21'), 0.1),  # write page 47
            (HEX('a2 2a 03000000'), 0.1),  # write page 42
            (HEX('a2 2b 01000000'), 0.1),  # write page 43
            (HEX('30 03'), 0.005),         # read page 3-6
        ]
        if cc.startswith('E11'):
            commands.append((HEX('a2 03') + HEX(cc) + HEX('08'), 0.1))
        responses = [
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
            HEX(cc) + HEX('00 00000000 00000000 00000000'), HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect(pwd) is auth
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(b'IEMKAERB!NACUOYF')

    @pytest.mark.parametrize("protect_from_page", [  # noqa: F811
        1, 2, 3, 4, 48, 49
    ])
    def test_protect_from_page(self, mocker, tag, protect_from_page):
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = True

        page42 = bytearray([min(48, max(3, protect_from_page)), 0, 0, 0])
        commands = [
            (HEX('a2 2c 42524541'), 0.1),  # write page 44
            (HEX('a2 2d 4b4d4549'), 0.1),  # write page 45
            (HEX('a2 2e 46594f55'), 0.1),  # write page 46
            (HEX('a2 2f 43414e21'), 0.1),  # write page 47
            (HEX('a2 2a') + page42, 0.1),  # write page 42
            (HEX('a2 2b 01000000'), 0.1),  # write page 43
        ]
        responses = [
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
        ]
        if protect_from_page <= 3:
            commands += [
                (HEX('30 03'), 0.005),         # read page 3-6
                (HEX('a2 03 E1100008'), 0.1),  # write page 03
            ]
            responses += [
                HEX('E1100000 00000000 00000000 00000000'), HEX('0a'),
            ]

        tag.clf.exchange.side_effect = responses
        assert tag.protect('', protect_from=protect_from_page) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(b'IEMKAERB!NACUOYF')

    def test_protect_make_read_only(self, mocker, tag):  # noqa: F811
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = True

        commands = [
            (HEX('a2 2c 42524541'), 0.1),  # write page 44
            (HEX('a2 2d 4b4d4549'), 0.1),  # write page 45
            (HEX('a2 2e 46594f55'), 0.1),  # write page 46
            (HEX('a2 2f 43414e21'), 0.1),  # write page 47
            (HEX('a2 2a 03000000'), 0.1),  # write page 42
            (HEX('a2 2b 00000000'), 0.1),  # write page 43
            (HEX('30 03'), 0.005),         # read page 3-6
            (HEX('a2 03 E1100088'), 0.1),  # write page 03
        ]
        responses = [
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
            HEX('E1100000 00000000 00000000 00000000'), HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect('', read_protect=True) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(b'IEMKAERB!NACUOYF')

    def test_protect_with_short_password(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect("abc")
        assert str(excinfo.value) == "password must be at least 16 byte"

    def test_read_ndef(self, tag):
        commands = [
            (HEX('30 00'), 0.005),  # read page 0-3
            (HEX('30 04'), 0.005),  # read page 4-7
            (HEX('30 08'), 0.005),  # read page 8-11
            (HEX('30 0c'), 0.005),  # read page 12-15
        ]
        responses = [
            HEX('04049018 00000001 01480000 e1100688'),
            HEX('031fd102 1a537091 010a5503 6e666370'),
            HEX('792e6f72 67510108 5402656e 6e666370'),
            HEX('79fe0000 00000000 00000000 00000000'),
        ]

        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.is_writeable is False
        assert tag.ndef.is_readable is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    @pytest.mark.parametrize("rw, rf, wf", [  # noqa: F811
        ('00', True, True),
        ('08', True, False),
        ('80', False, True),
        ('88', False, False),
        ('ff', False, False),
    ])
    def test_read_ndef_with_authenticate(self, mocker, tag, rw, rf, wf):
        mocker.patch.object(tag, '_authenticate', autospec=True)
        tag._authenticate.return_value = True

        commands = [
            (HEX('30 00'), 0.005),  # read page 0-3
            (HEX('30 04'), 0.005),  # read page 4-7
            (HEX('30 08'), 0.005),  # read page 8-11
            (HEX('30 0c'), 0.005),  # read page 12-15
        ]
        responses = [
            HEX('04049018 00000001 01480000 e11006' + rw),
            HEX('031fd102 1a537091 010a5503 6e666370'),
            HEX('792e6f72 67510108 5402656e 6e666370'),
            HEX('79fe0000 00000000 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.is_writeable is wf
        assert tag.ndef.is_readable is rf
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate(b'') is True
        assert tag.ndef is not None
        assert tag.ndef.is_writeable is (rf or rw[0] == '8')
        assert tag.ndef.is_readable is (wf or rw[1] == '8')
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag._authenticate.assert_called_once_with(b'')

    def test_read_ndef_from_unformatted_tag(self, tag):
        commands = [
            (HEX('30 00'), 0.005),  # read page 0-3
        ]
        responses = [
            HEX('04049018 00000001 01480000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# MIFARE ULTRALIGHT EV1
#
###############################################################################
class TestUltralightEV1:
    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004030101000B03'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.MF0UL11)
        assert tag.product == "Mifare Ultralight EV1 (MF0UL11)"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    @pytest.mark.parametrize("version_response, product", [
        ('0004030101000B03', "MF0UL11"),
        ("0004030201000B03", "MF0ULH11"),
        ("0004030101000E03", "MF0UL21"),
        ("0004030201000E03", "MF0ULH21"),
    ])
    def test_init(self, clf, target, version_response, product):
        clf.exchange.side_effect = [
            HEX('00'), HEX(version_response),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, eval("nfc.tag.tt2_nxp." + product))
        assert tag.product == "Mifare Ultralight EV1 (%s)" % product
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]

    @pytest.mark.parametrize("version_response, product", [
        ('0004030101000B03', "MF0UL11"),
        ("0004030201000B03", "MF0ULH11"),
        ("0004030101000E03", "MF0UL21"),
        ("0004030201000E03", "MF0ULH21"),
    ])
    def test_dump_ul11(self, clf, target, version_response, product):
        responses = [
            HEX('00'), HEX(version_response),
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + ({'11': 15, '21': 36}.get(product[-2:])) * [
            HEX("00000000 00000000 00000000 00000000")
        ]
        clf.exchange.side_effect = responses
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, eval("nfc.tag.tt2_nxp." + product))
        assert tag.dump() == {
            '11': [
                "000: 04 51 7c a1 (UID0-UID2, BCC0)",
                "001: e1 ed 25 80 (UID3-UID6)",
                "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
                "003: e1 10 06 00 (OTP0-OTP3)",
                "004: 03 00 fe 00 |....|",
                "005: 00 00 00 00 |....|",
                "  *  00 00 00 00 |....|",
                "00F: 00 00 00 00 |....|",
                "010: 00 00 00 00 (MOD, RFU, RFU, AUTH0)",
                "011: 00 00 00 00 (ACCESS, VCTID, RFU, RFU)",
                "012: 00 00 00 00 (PWD0, PWD1, PWD2, PWD3)",
                "013: 00 00 00 00 (PACK0, PACK1, RFU, RFU)",
            ],
            '21': [
                "000: 04 51 7c a1 (UID0-UID2, BCC0)",
                "001: e1 ed 25 80 (UID3-UID6)",
                "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
                "003: e1 10 06 00 (OTP0-OTP3)",
                "004: 03 00 fe 00 |....|",
                "005: 00 00 00 00 |....|",
                "  *  00 00 00 00 |....|",
                "023: 00 00 00 00 |....|",
                "024: 00 00 00 00 (LOCK2, LOCK3, LOCK4, RFU)",
                "025: 00 00 00 00 (MOD, RFU, RFU, AUTH0)",
                "026: 00 00 00 00 (ACCESS, VCTID, RFU, RFU)",
                "027: 00 00 00 00 (PWD0, PWD1, PWD2, PWD3)",
                "028: 00 00 00 00 (PACK0, PACK1, RFU, RFU)",
            ]
        }.get(product[-2:])


###############################################################################
#
# NTAG 203
#
###############################################################################
class TestNTAG203:
    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('00'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NTAG203)
        assert tag.product == "NXP NTAG203"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        [
            HEX('04517ca1 e1ed2580 01480000 00000000'),
            HEX('e1ed2580 01480000 00000000 02000010'),
            HEX('01480000 00000000 02000010 00060110'),
            HEX('00000000 02000010 00060110 11ff0000'),
            HEX('02000010 00060110 11ff0000 00000000'),
            HEX('00060110 11ff0000 00000000 00000000'),
            HEX('11ff0000 00000000 00000000 00000000'),
        ] + 33 * [
            HEX('00000000 00000000 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = [
            HEX('04517ca1 e1ed2580 75480000 e1101200'),
            HEX('e1ed2580 75480000 e1101200 030bd101'),
            HEX('75480000 e1101200 030bd101 07540265'),
            HEX('e1101200 030bd101 07540265 6e746573'),
            HEX('030bd101 07540265 6e746573 74fe0000'),
            HEX('07540265 6e746573 74fe0000 00000000'),
            HEX('6e746573 74fe0000 00000000 00000000'),
            HEX('74fe0000 00000000 00000000 00000000'),
        ] + 32 * [
            HEX('00000000 00000000 00000000 00000000'),
        ] + [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX('00000000 00000000 00000000 00000000'),
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: 75 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 12 00 (OTP0-OTP3)",
            "004: 03 0b d1 01 |....|",
            "005: 07 54 02 65 |.T.e|",
            "006: 6e 74 65 73 |ntes|",
            "007: 74 fe 00 00 |t...|",
            "008: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "027: 00 00 00 00 |....|",
            "028: ?? ?? ?? ?? (LOCK2-LOCK3)",
            "029: 00 00 00 00 (CNTR0-CNTR1)",
        ]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0103a010'), 0.1),
            (HEX('a2 05 440300fe'), 0.1),
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('fe000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0103a010 440300fe 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0303d000 00fe0000 00000000 00000000'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_password(self, tag):
        assert tag.protect(password='') is False

    def test_protect_with_ndef(self, tag):
        commands = [
            (HEX('3003'), 0.005),
            (HEX('a2 03 e110120f'), 0.1),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('a2 28 ff010000'), 0.1),
        ]
        responses = [
            HEX('e1101200 0303d000 00fe0000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_blank(self, tag):
        commands = [
            (HEX('3003'), 0.005),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('a2 28 ff010000'), 0.1),
        ]
        responses = [
            HEX('00000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_read_error(self, tag):
        commands = [
            (HEX('3003'), 0.005), (HEX('3003'), 0.005), (HEX('3003'), 0.005),
        ]
        responses = [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect() is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# NTAG 21x
#
###############################################################################
class BaseNTAG21x:
    def test_signature(self, tag):
        commands = [
            (HEX('3c 00'), 0.1),
            (HEX('3c 00'), 0.1),
            (HEX('3c 00'), 0.1),
            (HEX('3c 00'), 0.1),
        ]
        responses = [
            bytearray(range(32)),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.signature == bytearray(range(32))
        assert tag.signature == bytearray(32)
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        with pytest.raises(AttributeError):
            tag.signature = bytearray(32)

    def test_authenticate(self, tag):
        commands = [
            (HEX('1b ffffffff'), 0.1),
            (HEX('1b abcdefff'), 0.1),
            (HEX('1b 01234567'), 0.1),
            (HEX('1b ffffffff'), 0.1),
            (HEX('1b ffffffff'), 0.1),
            (HEX('1b ffffffff'), 0.1),
        ]
        responses = [
            HEX('0000'), HEX('1234'), HEX('89ab'),
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate(HEX('')) is True
        assert tag.authenticate(HEX('ABCDEFFF1234')) is True
        assert tag.authenticate(HEX('0123456789ABCDEF')) is True
        assert tag.authenticate(HEX('')) is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        with pytest.raises(ValueError) as excinfo:
            tag.authenticate(HEX('ffffffff00'))
        assert str(excinfo.value) == "password must be at least 6 bytes"

    def test_protect_with_lockbits(self, tag):
        commands = [
            (HEX('3003'), 0.005),
            (HEX('a2 03 e110120f'), 0.1),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('30 %02x' % self.cfgpage), 0.005),
            (HEX('a2 %02x 40000000' % (self.cfgpage+1)), 0.1),
        ]
        responses = [
            HEX('e1101200 0303d000 00fe0000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('00000000 00000000 00000000 00000000'),
            HEX('0a'),
        ]
        if self.cfgpage > 16:
            command = HEX('a2 %02x ffffff00' % (self.cfgpage-1))
            commands.insert(3, (command, 0.1))
            responses.insert(3, HEX('0a'))
        tag.clf.exchange.side_effect = responses
        assert tag.protect(password=None) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        commands = [
            (HEX('30 03'), 0.005),
            (HEX('a2 02 0000ffff'), 0.1),
            (HEX('30 %02x' % self.cfgpage), 0.005),
        ]
        responses = [
            HEX('00000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('00000000 40000000 00000000 00000000'),
        ]
        if self.cfgpage > 16:
            command = HEX('a2 %02x ffffff00' % (self.cfgpage-1))
            commands.insert(2, (command, 0.1))
            responses.insert(2, HEX('0a'))
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.protect(password=None) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        commands = [
            (HEX('3003'), 0.005), (HEX('3003'), 0.005), (HEX('3003'), 0.005),
        ]
        responses = [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.protect(password=None) is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_short_password(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect(password=b'abc')
        assert str(excinfo.value) == "password must be at least 6 bytes"

    @pytest.mark.parametrize("pwd, key", [  # noqa: F811
        ('', 'FFFFFFFF0000'),
        ('12345678abcdef', '12345678abcd'),
    ])
    def test_protect_with_password(self, mocker, tag, pwd, key):
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = True

        commands = [
            (HEX('30 %02x' % self.cfgpage), 0.005),
            (HEX('a2 %02x 00000003' % self.cfgpage), 0.1),
            (HEX('a2 %02x 00000000' % (self.cfgpage+1)), 0.1),
            (HEX('a2 %02x %s' % (self.cfgpage+2, key[0:8])), 0.1),
            (HEX('a2 %02x %s0000' % (self.cfgpage+3, key[8:12])), 0.1),
            (HEX('30 03'), 0.005),
            (HEX('a2 03 e1101208'), 0.1),
        ]
        responses = [
            HEX('00000000 00000000 00000000 00000000'),
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
            HEX('e1101200 0303d000 00fe0000 00000000'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect(password=HEX(pwd)) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(HEX(key))

    def test_protect_read_protected(self, mocker, tag):  # noqa: F811
        commands = [
            (HEX('30 %02x' % self.cfgpage), 0.005),
            (HEX('a2 %02x 00000003' % (self.cfgpage)), 0.1),
            (HEX('a2 %02x 80000000' % (self.cfgpage+1)), 0.1),
            (HEX('a2 %02x ffffffff' % (self.cfgpage+2)), 0.1),
            (HEX('a2 %02x 00000000' % (self.cfgpage+3)), 0.1),
            (HEX('30 03'), 0.005),
            (HEX('a2 03 e1101288'), 0.1),
        ]
        responses = [
            HEX('00000000 00000000 00000000 00000000'),
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
            HEX('e1101200 0303d000 00fe0000 00000000'),
            HEX('0a'),
        ]
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = True
        tag.clf.exchange.side_effect = responses
        assert tag.protect(b'', read_protect=True) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(HEX('ffffffff0000'))

    def test_protect_unformatted_tag(self, mocker, tag):  # noqa: F811
        commands = [
            (HEX('30 %02x' % self.cfgpage), 0.005),
            (HEX('a2 %02x 00000003' % (self.cfgpage)), 0.1),
            (HEX('a2 %02x 00000000' % (self.cfgpage+1)), 0.1),
            (HEX('a2 %02x ffffffff' % (self.cfgpage+2)), 0.1),
            (HEX('a2 %02x 00000000' % (self.cfgpage+3)), 0.1),
            (HEX('30 03'), 0.005),
        ]
        responses = [
            HEX('00000000 00000000 00000000 00000000'),
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
            HEX('00000000 00000000 00000000 00000000'),
        ]
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = True
        tag.clf.exchange.side_effect = responses
        assert tag.protect(b'') is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(HEX('ffffffff0000'))

    @pytest.mark.parametrize("protect_from_page", [4, 255, 256])  # noqa: F811
    def test_protect_protect_from(self, mocker, tag, protect_from_page):
        from_page = max(3, min(protect_from_page, 255))
        commands = [
            (HEX('30 %02x' % self.cfgpage), 0.005),
            (HEX('a2 %02x 000000%02x' % (self.cfgpage, from_page)), 0.1),
            (HEX('a2 %02x 00000000' % (self.cfgpage+1)), 0.1),
            (HEX('a2 %02x ffffffff' % (self.cfgpage+2)), 0.1),
            (HEX('a2 %02x 00000000' % (self.cfgpage+3)), 0.1),
        ]
        responses = [
            HEX('00000000 00000000 00000000 00000000'),
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
        ]
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = True
        tag.clf.exchange.side_effect = responses
        assert tag.protect(b'', protect_from=protect_from_page) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(HEX('ffffffff0000'))

    @pytest.mark.parametrize("rw, rf, wf, rfa, wfa", [  # noqa: F811
        ('00', True, True, True, True),
        ('08', True, False, True, True),
        ('80', False, True, True, True),
        ('88', False, False, True, True),
        ('0f', True, False, True, False),
        ('f0', False, True, False, True),
        ('ff', False, False, False, False),
    ])
    def test_authenticated_read_ndef(self, mocker, tag, rw, rf, wf, rfa, wfa):
        mocker.patch.object(tag, '_authenticate', autospec=True)
        tag._authenticate.return_value = True

        commands = [
            (HEX('30 00'), 0.005),
            (HEX('30 04'), 0.005),
        ]
        responses = [
            HEX("04517CA1 E1ED2580 A9480000 E11006" + rw),
            HEX("0300FE00 00000000 00000000 00000000"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is not None
        assert tag.ndef.is_writeable is wf
        assert tag.ndef.is_readable is rf
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

        tag._ndef = None
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate(b'') is True
        assert tag.ndef is not None
        assert tag.ndef.is_writeable is wfa
        assert tag.ndef.is_readable is rfa
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_ndef_unformatted_tag(self, tag):
        commands = [
            (HEX('30 00'), 0.005),
        ]
        responses = [
            HEX("04517CA1 E1ED2580 A9480000 00000000"),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# NTAG 210
#
###############################################################################
class TestNTAG210(BaseNTAG21x):
    cfgpage = 16

    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040101000B03'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NTAG210)
        assert tag.product == "NXP NTAG210"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + 13 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX("00000000 00000000 00000000 00000000")
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 06 00 (OTP0-OTP3)",
            "004: 03 00 fe 00 |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "00F: 00 00 00 00 |....|",
            "010: 00 00 00 00 (MIRROR_BYTE, RFU, MIRROR_PAGE, AUTH0)",
            "011: 00 00 00 00 (ACCESS)",
            "012: ?? ?? ?? ?? (PWD0-PWD3)",
            "013: 00 00 00 00 (PACK0-PACK1)",
        ]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
            (HEX('a2 05 00000000'), 0.1),
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('fe000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0300fe00 00000000 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0303d000 00fe0000 00000000 00000000'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# NTAG 212
#
###############################################################################
class TestNTAG212(BaseNTAG21x):
    cfgpage = 37

    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040101000E03'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NTAG212)
        assert tag.product == "NXP NTAG212"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + 34 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX("00000000 00000000 00000000 00000000")
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 06 00 (OTP0-OTP3)",
            "004: 03 00 fe 00 |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "023: 00 00 00 00 |....|",
            "024: 00 00 00 00 (LOCK2-LOCK4)",
            "025: 00 00 00 00 (MIRROR_BYTE, RFU, MIRROR_PAGE, AUTH0)",
            "026: 00 00 00 00 (ACCESS)",
            "027: ?? ?? ?? ?? (PWD0-PWD3)",
            "028: 00 00 00 00 (PACK0-PACK1)",
        ]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0103900a'), 0.1),
            (HEX('a2 05 340300fe'), 0.1),
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('fe000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0103900a 340300fe 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0303d000 00fe0000 00000000 00000000'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# NTAG 213
#
###############################################################################
class TestNTAG213(BaseNTAG21x):
    cfgpage = 41

    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040201000F03'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NTAG213)
        assert tag.product == "NXP NTAG213"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + 38 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX("00000000 00000000 00000000 00000000")
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 06 00 (OTP0-OTP3)",
            "004: 03 00 fe 00 |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "027: 00 00 00 00 |....|",
            "028: 00 00 00 00 (LOCK2-LOCK4)",
            "029: 00 00 00 00 (MIRROR, RFU, MIRROR_PAGE, AUTH0)",
            "02A: 00 00 00 00 (ACCESS)",
            "02B: ?? ?? ?? ?? (PWD0-PWD3)",
            "02C: 00 00 00 00 (PACK0-PACK1)",
        ]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0103a00c'), 0.1),
            (HEX('a2 05 340300fe'), 0.1),
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('fe000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0103a00c 340300fe 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0303d000 00fe0000 00000000 00000000'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# NTAG 215
#
###############################################################################
class TestNTAG215(BaseNTAG21x):
    cfgpage = 131

    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040201001103'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NTAG215)
        assert tag.product == "NXP NTAG215"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + 128 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX("00000000 00000000 00000000 00000000")
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 06 00 (OTP0-OTP3)",
            "004: 03 00 fe 00 |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "081: 00 00 00 00 |....|",
            "082: 00 00 00 00 (LOCK2-LOCK4)",
            "083: 00 00 00 00 (MIRROR, RFU, MIRROR_PAGE, AUTH0)",
            "084: 00 00 00 00 (ACCESS)",
            "085: ?? ?? ?? ?? (PWD0-PWD3)",
            "086: 00 00 00 00 (PACK0-PACK1)",
        ]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
            (HEX('a2 05 00000000'), 0.1),
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('fe000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0300fe00 00000000 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0303d000 00fe0000 00000000 00000000'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# NTAG 216
#
###############################################################################
class TestNTAG216(BaseNTAG21x):
    cfgpage = 227

    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040201001303'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NTAG216)
        assert tag.product == "NXP NTAG216"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + 224 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
            HEX("00000000 00000000 00000000 00000000")
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 06 00 (OTP0-OTP3)",
            "004: 03 00 fe 00 |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "0E1: 00 00 00 00 |....|",
            "0E2: 00 00 00 00 (LOCK2-LOCK4)",
            "0E3: 00 00 00 00 (MIRROR, RFU, MIRROR_PAGE, AUTH0)",
            "0E4: 00 00 00 00 (ACCESS)",
            "0E5: ?? ?? ?? ?? (PWD0-PWD3)",
            "0E6: 00 00 00 00 (PACK0-PACK1)",
        ]

    def test_format_blank_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
            (HEX('a2 05 00000000'), 0.1),
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('fe000000 00000000 00000000 00000000'),
            HEX('0a'),
            HEX('0a'),
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0300fe00 00000000 00000000 00000000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_tag(self, tag):
        commands = [
            (HEX('3000'), 0.005),
            (HEX('3004'), 0.005),
            (HEX('a2 04 0300fe00'), 0.1),
        ]
        responses = [
            HEX('04a8d8fc 62bc2b80 75480000 e1101200'),
            HEX('0303d000 00fe0000 00000000 00000000'),
            HEX('0a'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]


###############################################################################
#
# NTAG I2C 1K
#
###############################################################################
class TestNT3H1101:
    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040502011303'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NT3H1101)
        assert tag.product == "NTAG I2C 1K (NT3H1101)"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + 223 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            HEX('0a'), nfc.clf.TimeoutError,  # sector select
            HEX("00000000 00000000 00000000 00000000"),
            HEX('0a'), nfc.clf.TimeoutError,  # sector select
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 06 00 (OTP0-OTP3)",
            "004: 03 00 fe 00 |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "0E1: 00 00 00 00 |....|",
            "0E2: 00 00 00 00 (LOCK2-LOCK4, CHK)",
            "",
            "Configuration registers:",
            "0E8: 00 00 00 00 (NC, LD, SM, WDT0)",
            "0E9: 00 00 00 00 (WDT1, CLK, LOCK, RFU)",
            "",
            "Session registers:",
            "3F8: 00 00 00 00 (NC, LD, SM, WDT0)",
            "3F9: 00 00 00 00 (WDT1, CLK, NS, RFU)",
        ]


###############################################################################
#
# NTAG I2C 2K
#
###############################################################################
class TestNT3H1201:
    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040502011503'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.NT3H1201)
        assert tag.product == "NTAG I2C 2K (NT3H1201)"
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("04517CA1 E1ED2580 A9480000 E1100600"),
            HEX("E1ED2580 A9480000 E1100600 0300FE00"),
            HEX("A9480000 E1100600 0300FE00 00000000"),
            HEX("E1100600 0300FE00 00000000 00000000"),
            HEX("0300FE00 00000000 00000000 00000000"),
        ] + 251 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            HEX('0a'), nfc.clf.TimeoutError,  # sector select
        ] + 226 * [
            HEX("00000000 00000000 00000000 00000000")
        ] + [
            HEX('0a'), nfc.clf.TimeoutError,  # sector select
            HEX("00000000 00000000 00000000 00000000"),
            HEX('0a'), nfc.clf.TimeoutError,  # sector select
        ]
        assert tag.dump() == [
            "000: 04 51 7c a1 (UID0-UID2, BCC0)",
            "001: e1 ed 25 80 (UID3-UID6)",
            "002: a9 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: e1 10 06 00 (OTP0-OTP3)",
            "004: 03 00 fe 00 |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "1DF: 00 00 00 00 |....|",
            "1E0: 00 00 00 00 (LOCK2-LOCK4, CHK)",
            "",
            "Configuration registers:",
            "1E8: 00 00 00 00 (NC, LD, SM, WDT0)",
            "1E9: 00 00 00 00 (WDT1, CLK, LOCK, RFU)",
            "",
            "Session registers:",
            "3F8: 00 00 00 00 (NC, LD, SM, WDT0)",
            "3F9: 00 00 00 00 (WDT1, CLK, NS, RFU)",
        ]


###############################################################################
#
# ACTIVATE
#
###############################################################################
class TestActivate:
    def test_ultralightc_gone_after_authenticate(self, clf, target):
        clf.sense.return_value = None
        clf.exchange.side_effect = [
            HEX('aff7dfc7fa617c7f1d'),
        ]
        assert nfc.tag.activate(clf, target) is None
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
        ]

    def test_timeout_and_gone_after_authenticate(self, clf, target):
        clf.sense.return_value = None
        clf.exchange.side_effect = [
            nfc.clf.TimeoutError,
        ]
        assert nfc.tag.activate(clf, target) is None
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
        ]

    def test_communication_error_authenticate(self, clf, target):
        clf.exchange.side_effect = [
            nfc.clf.CommunicationError,
        ]
        assert type(nfc.tag.activate(clf, target)) == nfc.tag.tt2.Type2Tag
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
        ]

    def test_target_gone_after_get_version(self, clf, target):
        clf.sense.side_effect = [
            target, None, None,
        ]
        clf.exchange.side_effect = [
            HEX('00'), HEX('00'),
        ]
        assert nfc.tag.activate(clf, target) is None
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]

    def test_target_unknown_version_string(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), HEX('0004040502021303'),
        ]
        assert type(nfc.tag.activate(clf, target)) == nfc.tag.tt2.Type2Tag
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]

    def test_timeout_and_gone_after_get_version(self, clf, target):
        clf.sense.side_effect = [
            target, None, None,
        ]
        clf.exchange.side_effect = [
            HEX('00'), nfc.clf.TimeoutError,
        ]
        assert nfc.tag.activate(clf, target) is None
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]

    def test_communication_error_get_version(self, clf, target):
        clf.exchange.side_effect = [
            HEX('00'), nfc.clf.CommunicationError,
        ]
        assert type(nfc.tag.activate(clf, target)) == nfc.tag.tt2.Type2Tag
        assert clf.exchange.mock_calls == [
            mock.call(HEX('1A00'), timeout=0.01),
            mock.call(HEX('60'), timeout=0.01),
        ]
