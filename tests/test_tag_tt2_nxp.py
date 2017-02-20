# -*- coding: latin-1 -*-

import sys
import pytest
from mock import MagicMock, call
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.DEBUG)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag.tt2").setLevel(logging_level)
logging.getLogger("nfc.tag").setLevel(logging_level)

sys.modules['usb1'] = MagicMock

import nfc          # noqa: E402
import nfc.tag      # noqa: E402
import nfc.tag.tt2  # noqa: E402

import nfc.ndef
import ndef


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()  # noqa: F811
def clf(mocker, target):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch.object(clf, 'sense', new=lambda *args, **kwargs: target)
    mocker.patch('os.urandom', new=lambda n: bytes(bytearray(range(n))))
    return clf


class Type2TagSimulator(nfc.clf.ContactlessFrontend):
    pass

###############################################################################
#
# TEST MIFARE ULTRALIGHT
#
###############################################################################
class TestUltralight:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("106A")
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("04F6A281A02280")
        return target

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
            call(HEX('1A00'), timeout=0.01),
            call(HEX('60'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX('04f6a2d881a022808348000000000000'),
            HEX('81a022808348000000000000ffffffff'),
            HEX('8348000000000000ffffffff00000000'),
            HEX('00000000ffffffff0000000000000000'),
            HEX('ffffffff000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000004f6a2d8'),
            HEX('000000000000000004f6a2d881a02280'),
            HEX('0000000004f6a2d881a0228083480000'),
        ]
        assert tag.dump() == [
            "000: 04 f6 a2 d8 (UID0-UID2, BCC0)",
            "001: 81 a0 22 80 (UID3-UID6)",
            "002: 83 48 00 00 (BCC1, INT, LOCK0-LOCK1)",
            "003: 00 00 00 00 (OTP0-OTP3)",
            "004: ff ff ff ff |....|",
            "005: 00 00 00 00 |....|",
            "  *  00 00 00 00 |....|",
            "00F: 00 00 00 00 |....|",
        ]
        

###############################################################################
#
# TEST MIFARE ULTRALIGHT C
#
###############################################################################
class TestUltralightC:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("106A")
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("04049000000001")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [
            HEX('aff7dfc7fa617c7f1d'),
        ]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt2_nxp.MifareUltralightC)
        assert tag.product == "Mifare Ultralight C (MF01CU2)"
        assert clf.exchange.mock_calls == [
            call(HEX('1A00'), timeout=0.01),
        ]
        clf.exchange.reset_mock()
        return tag

    def test_init(self, tag):
        pass  # tested by tag fixture

    def test_dump(self, tag):
        tag.clf.exchange.side_effect = [
            HEX('04049018000000010148000000000000'),
            HEX('00000001014800000000000002000010'),
            HEX('01480000000000000200001000060110'),
            HEX('00000000020000100006011011ff0000'),
            HEX('020000100006011011ff000000000000'),
            HEX('0006011011ff00000000000000000000'),
            HEX('11ff0000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000000000000'),
            HEX('00000000000000000000000004049018'),
            HEX('00000000000000000404901800000001'),
            HEX('00000000040490180000000101480000'),
            HEX('00'),
            HEX('00'),
            HEX('00'),
            HEX('00'),
        ]
        assert tag.dump() == [
            "000: 04 04 90 18 (UID0-UID2, BCC0)",
            "001: 00 00 00 01 (UID3-UID6)",
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
        tag.clf.exchange.side_effect = [
            HEX('af f7dfc7fa 617c7f1d'),
            HEX('00 0355f3c1 76dcd1b1'),
        ]
        assert tag.authenticate(password) is True
        assert tag.clf.exchange.mock_calls == [
            call(HEX('1a 00'), 0.1),
            call(HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
        ]

    def test_authenticate_failure(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.authenticate(b'too-short')
        assert str(excinfo.value) == "password must be at least 16 byte"

        tag.clf.exchange.side_effect = [
            HEX('af f7dfc7fa 617c7f1d'),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        assert tag.authenticate(b'') is False
        assert tag.clf.exchange.mock_calls == [
            call(HEX('1a 00'), 0.1),
            call(HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
            call(HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
            call(HEX('af ab7efbe6 3f403940 10d04f01 8f8f48c3'), 0.1),
        ]

    def test_protect_with_lockbits(self, tag):
        tag.clf.exchange.side_effect = [
            HEX('00000000 00000000 00000000 00000000'),  # Block 3-6
            HEX('0a'), HEX('0a'),  # ACK
        ]
        assert tag.protect(None) is True
        assert tag.clf.exchange.mock_calls == [
            call(HEX('30 03'), 0.005),
            call(HEX('a2 02 0000ffff'), 0.1),
            call(HEX('a2 28 ffff0000'), 0.1),
        ]

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('E1100000 00000000 00000000 00000000'),  # pages 3-6
            HEX('0a'), HEX('0a'), HEX('0a'),  # ACK
        ]
        assert tag.protect(None) is True
        assert tag.clf.exchange.mock_calls == [
            call(HEX('30 03'), 0.005),
            call(HEX('a2 03 e110000f'), 0.1),
            call(HEX('a2 02 0000ffff'), 0.1),
            call(HEX('a2 28 ffff0000'), 0.1),
        ]

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = 3 * [nfc.clf.TimeoutError]
        assert tag.protect(None) is False
        assert tag.clf.exchange.mock_calls == 3 * [call(HEX('30 03'), 0.005)]

    @pytest.mark.parametrize("pwd, cc, auth", [
        (b'', 'E11000', True),
        (b'IEMKAERB!NACUOYF', 'E11000', True),
        (b'IEMKAERB!NACUOYF+ignored', 'E11000', True),
        (b'', '000000', True),
        (b'', 'E11000', False),
    ])
    def test_protect_with_password(self, mocker, tag, pwd, cc, auth):
        mocker.patch.object(tag, 'authenticate', autospec=True)
        tag.authenticate.return_value = auth

        tag.clf.exchange.side_effect = [
            HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'), HEX('0a'),
            HEX(cc) + HEX('00 00000000 00000000 00000000'), HEX('0a'),
        ]
        assert tag.protect(pwd) is auth
        mock_calls = [
            call(HEX('a2 2c 42524541'), 0.1),  # write page 44
            call(HEX('a2 2d 4b4d4549'), 0.1),  # write page 45
            call(HEX('a2 2e 46594f55'), 0.1),  # write page 46
            call(HEX('a2 2f 43414e21'), 0.1),  # write page 47
            call(HEX('a2 2a 03000000'), 0.1),  # write page 42
            call(HEX('a2 2b 01000000'), 0.1),  # write page 43
            call(HEX('30 03'), 0.005),         # read page 3-6
        ]
        if cc.startswith('E11'):
            mock_calls.append(call(HEX('a2 03') + HEX(cc) + HEX('08'), 0.1))
        assert tag.clf.exchange.mock_calls == mock_calls
        tag.authenticate.assert_called_once_with(b'IEMKAERB!NACUOYF')

    @pytest.mark.parametrize("protect_from_page", [1, 2, 3, 4, 48, 49])
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
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]
        tag.authenticate.assert_called_once_with(b'IEMKAERB!NACUOYF')

    def test_protect_make_read_only(self, mocker, tag):
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
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]
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
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

    @pytest.mark.parametrize("rw, rf, wf", [
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
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate(b'') is True
        assert tag.ndef is not None
        assert tag.ndef.is_writeable is (rf or rw[0] == '8')
        assert tag.ndef.is_readable is (wf or rw[1] == '8')
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]
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
        assert tag.clf.exchange.mock_calls == [call(*_) for _ in commands]


###############################################################################
#
# TEST NTAG 203
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestNTAG203:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
            "01 03 A0 10  44 03 00 FE  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(168 - 32)

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG203)
        assert self.tag._product == "NXP NTAG203"

    def __test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 11
        assert lines[-1] == ' 41: 00 00 00 00 (CNTR0-CNTR1)'
        
    def __test_dump_memory_with_error(self):
        del self.clf.memory[-8:]
        lines = self.tag.dump()
        assert len(lines) == 11
        assert lines[-1] == ' 41: ?? ?? ?? ?? (CNTR0-CNTR1)'

    def __test_protect_without_password(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:164] == "\xFF\x01\x00\x00"
        assert self.tag.ndef.is_writeable is False

    def __test_protect_unformatted_tag(self):
        self.clf.memory[12:16] = "\1\2\3\4"
        assert self.tag.protect() is True
        assert self.clf.memory[12:16] == "\1\2\3\4"
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:164] == "\xFF\x01\x00\x00"

    def __test_protect_with_password(self):
        assert self.tag.protect("123456") is False

    def __test_protect_with_read_error(self):
        self.clf.tag_is_present = False
        assert self.tag.protect() is False


################################################################################
#
# TEST NTAG 21x
#
################################################################################
class NTAG21xSimulator(Type2TagSimulator):
    def __init__(self, tag_memory, version):
        super(NTAG21xSimulator, self).__init__(tag_memory)
        self.version = bytearray(version)

    def unknown_command(self, data, timeout):
        if data == "\x60": # GET_VERSION COMMAND
            return bytearray(self.version)
        if data == "\x3C\x00": # READ_SIG COMMAND
            return bytearray(32 * "\1")
        if data[0] == 0x1B: # PWD_AUTH COMMAND
            pwd = data[1:5]
            if pwd == self.memory[-8:-4]:
                return self.memory[-4:-2]
            else: return bytearray([0x00])

@pytest.mark.skip(reason="not yet converted")
class TestNTAG21x:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 06 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 008-011
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 012-015
            "00 00 00 00  00 00 00 00  FF FF FF FF  00 00 00 00" # 016-019
        )
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\1\1\0\x0B\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG21x)
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG210)

    def __test_signature_attribute_get(self):
        assert type(self.tag.signature) is str
        assert self.tag.signature == 32 * "\1"

    #pytest.raises(AttributeError)
    def __test_signature_attribute_set(self):
        self.tag.signature = 32 * "\1"

    def __test_signature_read_from_mute_tag(self):
        self.clf.tag_is_present = False
        assert self.tag.signature == 32 * "\0"

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[-12] == 0x40

    def __test_protect_with_lockbits_no_ndef_capabilities(self):
        self.clf.memory[12:16] = "\0\0\0\0"
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x00
        assert self.clf.memory[-12] == 0x40

    def __test_protect_with_lockbits_but_config_is_locked(self):
        self.clf.memory[-12] = 0x40
        assert self.tag.protect() is True

    def __test_protect_with_lockbits_but_unreadable_config(self):
        del self.clf.memory[-16:]
        assert self.tag.protect() is False

    #pytest.raises(ValueError)
    def __test_protect_with_invalid_password(self):
        self.tag.protect("abc")

    def __test_protect_with_default_password(self):
        self.clf.memory[-16:] = bytearray(16)
        assert self.tag.protect("") is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x03"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\xFF\xFF\xFF\xFF"
        assert self.clf.memory[ -4:   ] == "\x00\x00\x00\x00"
        assert self.clf.memory[15] == 0x08
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def __test_protect_with_custom_password(self):
        assert self.tag.protect("123456") is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x03"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x08
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def __test_protect_with_protect_from_page_5(self):
        assert self.tag.protect("123456", protect_from=5) is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x05"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x00
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def __test_protect_with_protect_from_page_256(self):
        assert self.tag.protect("123456", protect_from=256) is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\xFF"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x00
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def __test_protect_with_read_protect_true(self):
        assert self.tag.protect("123456", read_protect=True) is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x03"
        assert self.clf.memory[-12: -8] == "\x80\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x88
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def __test_authenticate_with_default_password(self):
        assert self.tag.is_authenticated is False
        assert self.tag.authenticate("") is True
        assert self.tag.is_authenticated is True

    def __test_authenticate_with_custom_password(self):
        self.clf.memory[-8:-2] = "012345"
        assert self.tag.is_authenticated is False
        assert self.tag.authenticate("0123456789abcdef") is True
        assert self.tag.is_authenticated is True

    def __test_authenticate_with_wrong_password(self):
        assert self.tag.authenticate("0123456789abcdef") is False
        assert self.tag.is_authenticated is False

    #pytest.raises(ValueError)
    def __test_authenticate_with_invalid_password(self):
        self.tag.authenticate("abc")

    def __test_authenticate_with_command_error(self):
        self.clf.tag_is_present = False
        assert self.tag.authenticate("") is False


###############################################################################
#
# TEST NTAG 210
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestNTAG210:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 06 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(20*4 - 32)
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\1\1\0\x0B\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG210)
        assert self.tag._product == "NXP NTAG210"
        assert self.tag._cfgpage == 16

    def __test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == ' 19: 00 00 00 00 (PACK0-PACK1)'
        
    def __test_dump_memory_with_error(self):
        del self.clf.memory[-8:]
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == ' 19: ?? ?? ?? ?? (PACK0-PACK1)'

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[17*4] == 0x40


###############################################################################
#
# TEST NTAG 212
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestNTAG212:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 10 00" # 000-003
            "01 03 90 0A  34 03 00 FE  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(41*4 - 32)
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\1\1\0\x0E\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})
        #assert self.tag._cfgpage == 37

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG212)
        assert self.tag._product == "NXP NTAG212"

    def __test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 40: 00 00 00 00 (PACK0-PACK1)'
        
    def __test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 40: ?? ?? ?? ?? (PACK0-PACK1)'

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[144:148] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[38*4] == 0x40


###############################################################################
#
# TEST NTAG 213
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestNTAG213:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
            "01 03 A0 0C  34 03 00 FE  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(45*4 - 32)
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\2\1\0\x0F\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})
        #assert self.tag._cfgpage == 41

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG213)
        assert self.tag._product == "NXP NTAG213"

    def __test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 44: 00 00 00 00 (PACK0-PACK1)'
        
    def __test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 44: ?? ?? ?? ?? (PACK0-PACK1)'

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:164] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[42*4] == 0x40


###############################################################################
#
# TEST NTAG 215
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestNTAG215:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 3E 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(135*4 - 32)
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\2\1\0\x11\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})
        #assert self.tag._cfgpage == 131

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG215)
        assert self.tag._product == "NXP NTAG215"

    def __test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '134: 00 00 00 00 (PACK0-PACK1)'
        
    def __test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '134: ?? ?? ?? ?? (PACK0-PACK1)'

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[520:524] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[132*4] == 0x40


###############################################################################
#
# TEST NTAG 216
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestNTAG216:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 6D 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(231*4 - 32)
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\2\1\0\x13\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})
        #assert self.tag._cfgpage == 227

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG216)
        assert self.tag._product == "NXP NTAG216"

    def __test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '230: 00 00 00 00 (PACK0-PACK1)'
        
    def __test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '230: ?? ?? ?? ?? (PACK0-PACK1)'

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[904:908] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[228*4] == 0x40


################################################################################
#
# TEST MIFARE ULTRALIGHT EV1
#
################################################################################
@pytest.mark.skip(reason="not yet converted")
class TestUltralightEV1UL11:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 06 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(20*4 - 32)
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert self.tag._product == "Mifare Ultralight EV1 (MF0UL11)"
        assert self.tag._cfgpage == 16

    def __test_activation_ulh11(self):
        self.clf.version = bytearray("\0\4\3\2\1\0\x0B\3")
        tag = self.clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert tag._product == "Mifare Ultralight EV1 (MF0ULH11)"
        assert tag._cfgpage == 16

    def __test_dump_memory(self):
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == " 19: 00 00 00 00 (PACK0, PACK1, RFU, RFU)"

    def __test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == " 19: ?? ?? ?? ?? (PACK0, PACK1, RFU, RFU)"

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x0F
        assert self.clf.memory[68] == 0x40
        assert self.tag.ndef.is_writeable is False

@pytest.mark.skip(reason="not yet converted")
class TestUltralightEV1UL21:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 10 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(41*4 - 32)
        #self.clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0E\3")
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def __test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert self.tag._product == "Mifare Ultralight EV1 (MF0UL21)"
        assert self.tag._cfgpage == 37

    def __test_activation_ulh21(self):
        self.clf.version = bytearray("\0\4\3\2\1\0\x0E\3")
        tag = self.clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert tag._product == "Mifare Ultralight EV1 (MF0ULH21)"
        assert tag._cfgpage == 37

    def __test_dump_memory(self):
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == " 40: 00 00 00 00 (PACK0, PACK1, RFU, RFU)"

    def __test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == " 40: ?? ?? ?? ?? (PACK0, PACK1, RFU, RFU)"

    def __test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[144:148] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.clf.memory[152] == 0x40
        assert self.tag.ndef.is_writeable is False

@pytest.mark.skip(reason="not yet converted")
class TestActivation:
    def __test_activation_with_digital_error_for_authenticate(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.crc_error_after = 1
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag

    def __test_activation_with_digital_error_for_get_version(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.crc_error_after = 2
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag
        
    def __test_activation_with_unknown_version_for_get_version(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.return_response = bytearray(8)
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag
