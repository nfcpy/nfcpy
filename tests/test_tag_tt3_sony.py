# -*- coding: latin-1 -*-
import nfc
import nfc.ndef
import nfc.tag.tt3
import nfc.tag.tt3_sony
import ndef
import mock
import pytest
from pytest_mock import mocker  # noqa: F401
from struct import pack, unpack

import logging
logging.basicConfig(level=logging.DEBUG)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag.tt3").setLevel(logging_level)
logging.getLogger("nfc.tag").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)

@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    return clf


###############################################################################
#
# FeliCa Standard
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaStandard:
    idm = "01 02 03 04 05 06 07 08"
    pmm = "00 01 FF FF FF FF FF FF"

    def setup(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "FF FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF FF",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        ]]
        tag_memory = {
            0x0009: service_data, 0x000B: service_data,
            0x0048: service_data[1:], 0x0049: service_data[1:],
            0x004A: service_data[1:], 0x004B: service_data[1:],
            0x010C: service_data[-1:], 0x010D: service_data[-1:],
            0x010E: service_data[-1:], 0x010F: service_data[-1:],
            0x0210: service_data[-1:], 0x0211: service_data[-1:],
            0x0312: service_data[-1:], 0x0313: service_data[-1:],
            0x0414: service_data[-1:], 0x0415: service_data[-1:],
            0x0516: service_data[-1:], 0x0517: service_data[-1:],
        }
        #self.clf = Type3TagSimulator(tag_memory, "0000", self.idm, self.pmm)
        #self.clf.sys.append(bytearray.fromhex("12FC"))
        #self.tag = self.clf.connect(rdwr={'on-connect': None})
    
    def __test_init_with_ic_code(self):
        for ic in (0, 1, 2, 8, 9, 11, 12, 13, 32, 50, 53):
            yield self.check_init_with_ic_code, ic

    def check_init_with_ic_code(self, ic):
        pmm = "00{0:02X}FFFF FFFFFFFF".format(ic)
        clf = Type3TagSimulator(None, "0000", self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaStandard)
        assert tag._product.startswith("FeliCa Standard")

    def test_request_service_success(self):
        sc_list = [nfc.tag.tt3.ServiceCode(0, 9), nfc.tag.tt3.ServiceCode(1, 9)]
        assert self.tag.request_service(sc_list) == [0x0009, 0x0049]

    #pytest.raises(nfc.tag.TagCommandError)
    def test_request_service_error(self):
        self.clf.return_response = "\x0B\x03" + self.clf.idm + '\x00'
        sc_list = [nfc.tag.tt3.ServiceCode(0, 9)]
        try: self.tag.request_service(sc_list)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR; raise

    def test_request_response_success(self):
        assert self.tag.request_response() == 0

    #pytest.raises(nfc.tag.TagCommandError)
    def test_request_response_error(self):
        self.clf.return_response = "\x0C\x05" + self.clf.idm + "\0\0"
        try: self.tag.request_response()
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR; raise

    def test_search_service_code(self):
        assert self.tag.search_service_code(0) == (0x0000, 0xFFFE)
        assert self.tag.search_service_code(1) == (0x0009,)
        assert self.tag.search_service_code(2) == (0x000B,)
        assert self.tag.search_service_code(1000) == None

    def test_request_system_code(self):
        assert self.tag.request_system_code() == [0x0000, 0x12fc]

    #pytest.raises(nfc.tag.TagCommandError)
    def test_request_system_code_failure(self):
        self.clf.return_response = "\x0C\x0D" + self.clf.idm + '\x01\x02'
        try: self.tag.request_system_code()
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR; raise

    def test_is_present_if_present(self):
        assert self.tag.is_present is True

    def test_is_present_if_gone(self):
        self.clf.tag_is_present = False
        assert self.tag.is_present is False

    def test_dump(self):
        lines = self.tag.dump()
        assert len(lines) == 58


###############################################################################
#
# FeliCa Mobile
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaMobile:
    idm = "01 02 03 04 05 06 07 08"
    
    def __test_init_with_ic_code(self):
        for ic in [6, 7] + range(16, 32):
            yield self.check_init_with_ic_code, ic

    def check_init_with_ic_code(self, ic):
        pmm = "00{0:02X}FFFF FFFFFFFF".format(ic)
        clf = Type3TagSimulator(None, "0000", self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaMobile)
        assert tag._product.startswith("FeliCa Mobile")


###############################################################################
#
# FeliCa Lite
#
###############################################################################
felica_lite_data_1 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
] + 18 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
]

felica_lite_dump_1 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  *  43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MEMORY_CONFIG)",
]

felica_lite_data_2 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("0c 07 0102030405060708 FFFF"),
] + 18 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
] + [
    HEX("0c 07 0102030405060708 FFFF"),
]

felica_lite_dump_2 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  4: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? |................|",
    "  5: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (MEMORY_CONFIG)",
]

class TestFelicaLite:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX("01 0102030405060708 00F0FFFFFFFFFFFF 88B4")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLite)
        return tag

    @pytest.mark.parametrize("ic_code, product", [
        ('F0', "FeliCa Lite (RC-S965)"),
    ])
    def test_init(self, target, ic_code, product):
        target.sensf_res[10] = HEX(ic_code)[0]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLite)
        assert tag.product == product

    @pytest.mark.parametrize("data, dump", [
        (felica_lite_data_1, felica_lite_dump_1),
        (felica_lite_data_2, felica_lite_dump_2),
    ])
    def test_dump(self, tag, data, dump):
        tag.clf.exchange.side_effect = data
        assert tag.dump() == dump

    def test_ndef(self, tag, mocker):
        mocker.patch('os.urandom', new=lambda x: bytes(bytearray(range(x))))
        tag.clf.exchange.side_effect = [
            # authenticate
            HEX('0c 09 0102030405060708 0000'),  # write block 0x80
            HEX('2d 07 0102030405060708 0000 01'  # read block 0x82, 0x81
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
            # ndef reading
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX('2d 07 0102030405060708 0000 02'
                '10 04 01 00  03 00 00 00  00 00 01 00  00 27 00 40'
                'af 36 b1 f1  52 4e 3e b9  00 00 00 00  00 00 00 00'),
            HEX('4d 07 0102030405060708 0000 04'
                'd1 02 22 53  70 91 01 0e  55 03 6e 66  63 2d 66 6f'
                '72 75 6d 2e  6f 72 67 51  01 0c 54 02  65 6e 4e 46'
                '43 20 46 6f  72 75 6d 00  00 00 00 00  00 00 00 00'
                '9e 2d 7f e1  5b 2f 5d 1c  00 00 00 00  00 00 00 00'),
            # ndef writing
            HEX('2d 07 0102030405060708 0000 02'
                '10 04 01 00  03 00 00 00  00 00 01 00  00 27 00 40'
                'af 36 b1 f1  52 4e 3e b9  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 0
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 0
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        assert tag.authenticate("0123456789abcdef") is True
        assert tag.ndef is not None
        assert tag.ndef._original_nbr == 4
        assert tag.ndef.capacity == 48
        assert tag.ndef.length == 39
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        tag.ndef.records = [ndef.TextRecord('ab')]
        assert tag.clf.exchange.mock_calls == [
            # authenticate
            mock.call(HEX('20 08 0102030405060708 010900 018080'
                          '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            mock.call(HEX('12 06 0102030405060708 010b00 0280828081'),
                      0.46402560000000004),
            # ndef read
            mock.call(HEX('06 00 12fc 0000'), 0.003625),
            mock.call(HEX('12 06 0102030405060708 010b00 0280008081'),
                      0.46402560000000004),
            mock.call(HEX('16 06 0102030405060708 010b00 048001800280038081'),
                      0.7733760000000001),
            # ndef write
            mock.call(HEX('12 06 0102030405060708 010b00 0280008081'),
                      0.46402560000000004),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 03000000 000f0100 0027004f'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018001'
                          'd1010554 02656e61 62000000 00000000'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 03000000 00000100 00090022'), 0.3093504),
        ]

    @pytest.mark.parametrize("flip_key, mac_result", [
        (False, "0b1268d7a4ac6932"),
        (True, "18cdd33c0fb25dd7"),
    ])
    def test_generate_mac(self, flip_key, mac_result):
        data = bytearray(range(32))
        key = bytearray(range(16))
        iv = bytearray(range(8))
        mac = nfc.tag.tt3_sony.FelicaLite.generate_mac(data, key, iv, flip_key)
        assert mac == HEX(mac_result)

    def test_read_with_mac(self, tag):
        with pytest.raises(RuntimeError) as excinfo:
            tag.read_with_mac(0, 1)
        assert str(excinfo.value) == "authentication required"

        tag.clf.exchange.side_effect = [
            HEX("3d 07 0102030405060708 0000 03") + bytearray(48),
        ]
        tag._sk = bytearray(range(16))
        tag._iv = bytearray(range(8))
        assert tag.read_with_mac(0, 1) is None
        tag.clf.exchange.assert_called_once_with(
            HEX('14 06 0102030405060708 01 0b00 03 8000 8001 8081'), 0.6187008)

    def test_protect(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect("abc")
        assert str(excinfo.value) == "password must be at least 16 byte"

        with pytest.raises(ValueError) as excinfo:
            tag.protect("0123456789abcdef", protect_from=-1)
        assert str(excinfo.value) == "protect_from can not be negative"

        # this tag can not be made read protected
        assert tag.protect("0123456789abcdef", read_protect=True) is False

        # system block protected, can't write key
        tag.clf.exchange.side_effect = [
            HEX("1d 07 0102030405060708 0000 01"
                "FF FF 00 01  07 00 00 00  00 00 00 00  00 00 00 00"),
        ]
        assert tag.protect("0123456789abcdef") is False
        tag.clf.exchange.assert_called_with(
            HEX('10 06 0102030405060708 010b00 018088'), 0.3093504)

        # also set ndef rw flag because tag has ndef
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),
            HEX("12 01 0102030405060708 00F0FFFFFFFFFFFF"),
            HEX('1d 07 0102030405060708 0000 01'
                '10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28'),
            HEX('1d 07 0102030405060708 0000 01'
                'd1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d'),
            HEX('1d 07 0102030405060708 0000 01'
                '10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28'),
            HEX('0c 09 0102030405060708 0000'),
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.protect("0123456789abcdef") is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018087'
                          '37363534 33323130 66656463 62613938'), 0.3093504),
            mock.call(HEX('060012fc0000'), 0.003625),
            mock.call(HEX('10 06 0102030405060708 010b00 018000'), 0.3093504),
            mock.call(HEX('10 06 0102030405060708 010b00 018001'), 0.3093504),
            mock.call(HEX('10 06 0102030405060708 010b00 018000'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10010100 05000000 00000000 00100027'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018088'
                          '00400001 07000000 00000000 00000000'), 0.3093504),
        ]

        # not setting ndef rw flag because protect_from > 0
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.protect("0123456789abcdef", protect_from=1) is True
        print(tag.clf.exchange.mock_calls)
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018087'
                          '37363534 33323130 66656463 62613938'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018088'
                          '01400001 07000000 00000000 00000000'), 0.3093504),
        ]

    def test_authenticate(self, tag, mocker):
        mocker.patch('os.urandom', new=lambda x: bytes(bytearray(range(x))))

        # test invalid password (too short)
        with pytest.raises(ValueError) as excinfo:
            tag.authenticate("abc")
        assert str(excinfo.value) == "password must be at least 16 byte"

        # test successful authentication
        tag.clf.exchange.side_effect = [
            HEX('0c 09 0102030405060708 0000'),
            HEX('2d 07 0102030405060708 0000 01'  # block number 82, 81
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
        ]
        assert tag.authenticate("0123456789abcdef") is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('20 08 0102030405060708 010900 018080'
                          '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            mock.call(HEX('12 06 0102030405060708 010b00 0280828081'),
                      0.46402560000000004),
        ]

        # test failed authentication (wrong mac)
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('0c 09 0102030405060708 0000'),
            HEX('2d 07 0102030405060708 0000 01'  # block number 82, 81
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
        ]
        assert tag.authenticate("0123456789abcdef") is False
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('20 08 0102030405060708 010900 018080'
                          '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            mock.call(HEX('12 06 0102030405060708 010b00 0280828081'),
                      0.46402560000000004),
        ]

    def test_format(self, tag):
        with pytest.raises(AssertionError):
            tag.format(version='')

        with pytest.raises(AssertionError):
            tag.format(wipe='')

        # test invalid ndef mapping major version
        assert tag.format(version=0xF0) is False

        # the first user data block is not writeable
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # block number 88
                'FE FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
        ]
        assert tag.format() is False
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
        ]

        # ndef system code not enabled and MC block is read-only
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # block number 88
                'FF FF 00 00  07 00 00 00  00 00 00 00  00 00 00 00'),
        ]
        assert tag.format() is False
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
        ]

        # enable ndef system code, all data blocks writable, version 1.15
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # read block 88
                'FF FF FF 00  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 88
            HEX('0c 09 0102030405060708 0000'),  # write block 0
        ]
        assert tag.format(version=0x1F) is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018088'
                          'FFFFFF01 07000000 00000000 00000000'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '1F040100 0d000000 00000100 00000032'), 0.3093504),
        ]

        # last user data block is read-only
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # read block 88
                'FF DF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 0
        ]
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 0c000000 00000100 00000022'), 0.3093504),
        ]

        # only first ndef data block is writable, wipe with 0xA5
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'  # read block 88
                '03 C0 FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),  # write block 0
            HEX('0c 09 0102030405060708 0000'),  # write block 1

            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
            HEX('0c 09 0102030405060708 0000'),  # write block 1
        ]
        assert tag.format(wipe=0xA5) is True
        print(tag.clf.exchange.mock_calls)
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018000'
                          '10040100 01000000 00000100 00000017'), 0.3093504),
            mock.call(HEX('20 08 0102030405060708 010900 018001'
                          'a5a5a5a5 a5a5a5a5 a5a5a5a5 a5a5a5a5'), 0.3093504),
        ]


###############################################################################
#
# FeliCa Lite-S
#
###############################################################################
felica_lites_data_1 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
] + 21 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
]

felica_lites_dump_1 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  *  43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  6: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MEMORY_CONFIG)",
    '144: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (WCNT[3])',
    '145: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC_A[8])',
    '146: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (STATE)',
]

felica_lites_data_2 = [
    HEX("1d 07 0102030405060708 0000 01 10040100030000000000010000270040"),
    HEX('1d 07 0102030405060708 0000 01 d10222537091010e55036e66632d666f'),
    HEX("1d 07 0102030405060708 0000 01 72756d2e6f726751010c5402656e4e46"),
    HEX("1d 07 0102030405060708 0000 01 4320466f72756d000000000000000000"),
    HEX("0c 07 0102030405060708 FFFF"),
] + 21 * [
    HEX('1d 07 0102030405060708 0000 01') + bytearray(16)
] + [
    HEX("0c 07 0102030405060708 FFFF"),
]

felica_lites_dump_2 = [
    "  0: 10 04 01 00 03 00 00 00 00 00 01 00 00 27 00 40 |.............'.@|",
    '  1: d1 02 22 53 70 91 01 0e 55 03 6e 66 63 2d 66 6f |.."Sp...U.nfc-fo|',
    "  2: 72 75 6d 2e 6f 72 67 51 01 0c 54 02 65 6e 4e 46 |rum.orgQ..T.enNF|",
    "  3: 43 20 46 6f 72 75 6d 00 00 00 00 00 00 00 00 00 |C Forum.........|",
    "  4: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? |................|",
    "  5: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "  *  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    " 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (REGA[4]B[4]C[8])",
    "128: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (RC1[8], RC2[8])",
    "129: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC[8])",
    "130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDD[8], DFC[2])",
    "131: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (IDM[8], PMM[8])",
    "132: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SERVICE_CODE[2])",
    "133: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (SYSTEM_CODE[2])",
    "134: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CKV[2])",
    "135: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (CK1[8], CK2[8])",
    "136: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MEMORY_CONFIG)",
    '144: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (WCNT[3])',
    '145: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (MAC_A[8])',
    '146: ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (STATE)',
]

class TestFelicaLiteS:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX("01 0102030405060708 00F1FFFFFFFFFFFF 88B4")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLiteS)
        return tag

    @pytest.mark.parametrize("ic_code, product", [
        ('F1', "FeliCa Lite-S (RC-S966)"),
        ('F2', "FeliCa Link (RC-S730) Lite-S Mode"),
    ])
    def test_init(self, target, ic_code, product):
        target.sensf_res[10] = HEX(ic_code)[0]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLiteS)
        assert tag.product == product

    @pytest.mark.parametrize("data, dump", [
        (felica_lites_data_1, felica_lites_dump_1),
        (felica_lites_data_2, felica_lites_dump_2),
    ])
    def test_dump(self, tag, data, dump):
        tag.clf.exchange.side_effect = data
        assert tag.dump() == dump

    def test_protect_with_password_too_short(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect("abc")
        assert str(excinfo.value) == "password must be at least 16 byte"

    def test_protect_from_negative_block_value(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.protect("0123456789abcdef", protect_from=-1)
        assert str(excinfo.value) == "protect_from can not be negative"

    def test_protect_when_key_change_is_disabled(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("1d 07 0102030405060708 0000 01"
                "FF FF 00 01  07 00 00 00  00 00 00 00  00 00 00 00"),
        ]
        assert tag.protect("0123456789abcdef") is False
        tag.clf.exchange.assert_called_with(
            HEX('10 06 0102030405060708 010b00 018088'), 0.3093504)

    def test_protect_when_authentication_needed(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("1d 07 0102030405060708 0000 01"
                "FF FF 00 01  07 01 00 00  00 00 00 00  00 00 00 00"),
        ]
        assert tag.protect("0123456789abcdef") is False
        tag.clf.exchange.assert_called_with(
            HEX('10 06 0102030405060708 010b00 018088'), 0.3093504)

    def test_protect_ndef_tag_readonly(self, tag, mocker):
        mocker.patch('os.urandom', new=lambda x: bytes(bytearray(range(x))))
        commands = [
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 1
            (HEX('10 06 0102030405060708 010b00 018086'), 0.3093504),   # 2
            (HEX('20 08 0102030405060708 010900 018086'  # write CKV    # 3
                 '01000000 00000000 00000000 00000000'), 0.3093504),
            (HEX('20 08 0102030405060708 010900 018087'  # write CK     # 4
                 '37363534 33323130 66656463 62613938'), 0.3093504),
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
            # authenticate_2 - write_with_mac
            (HEX('10 06 0102030405060708 010b00 018090'), 0.3093504),   # 7
            (HEX('32 08 0102030405060708 010900 0280928091'             # 8
                 '01000000 00000000 00000000 00000000'
                 '17c19e3b bdc3e8bd 00feff00 00000000'),
             0.46402560000000004),  # write STATE, MAC_A
            (HEX('12 06 0102030405060708 010b00 0280928081'),           # 9
             0.46402560000000004),  # read_with_mac STATE
            # read ndef
            (HEX('06 00 12fc 0000'), 0.003625),  # poll for ndef        # 10
            (HEX('12 06 0102030405060708 010b00 0280008081'),           # 11
             0.46402560000000004),  # read_with_mac Block 0
            # read MC for ndef attribute rw flag
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 12
            # read and write ndef attribute data
            (HEX('10 06 0102030405060708 010b00 018000'), 0.3093504),   # 13
            (HEX('20 08 0102030405060708 010900 018000'                 # 14
                 '10040100 03000000 00000000 00000018'), 0.3093504),
            # write memory configuration
            (HEX('20 08 0102030405060708 010900 018088'  # write MC     # 15
                 'ffff0001 0701ff3f ff3fff3f 00000000'), 0.3093504),
        ]
        responses = [
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 1
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read CKV            # 2
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write CKV           # 3
            HEX('0c 09 0102030405060708 0000'),   # write CK            # 4
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
            # authenticate_2
            HEX('1d 07 0102030405060708 0000 01'  # read WCNT           # 7
                '00 FE FF 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write STATE, MAC_A  # 8
            HEX('2d 07 0102030405060708 0000 02'  # read STATE, MAC     # 9
                '01 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'bd 73 eb 72  94 a0 02 79  00 00 00 00  00 00 00 00'),
            HEX("12 01 0102030405060708 00F1FFFFFFFFFFFF"),  # polling  # 10
            HEX('2d 07 0102030405060708 0000 02'  # read attribute data # 11
                '10 04 01 00  03 00 00 00  00 00 01 00  00 00 00 19'
                'a6 22 c3 37  a4 e4 42 71  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 12
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read attribute data # 13
                '10 04 01 00  03 00 00 00  00 00 01 00  00 00 00 19'),
            HEX('0c 09 0102030405060708 0000'),   # write Block 0       # 14
            HEX('0c 09 0102030405060708 0000'),   # write MC            # 15
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect("0123456789abcdef", read_protect=True) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_unformatted_tag(self, tag, mocker):
        mocker.patch('os.urandom', new=lambda x: bytes(bytearray(range(x))))
        commands = [
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 1
            (HEX('10 06 0102030405060708 010b00 018086'), 0.3093504),   # 2
            (HEX('20 08 0102030405060708 010900 018086'  # write CKV    # 3
                 '01000000 00000000 00000000 00000000'), 0.3093504),
            (HEX('20 08 0102030405060708 010900 018087'  # write CK     # 4
                 '37363534 33323130 66656463 62613938'), 0.3093504),
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
            # authenticate_2 - write_with_mac
            (HEX('10 06 0102030405060708 010b00 018090'), 0.3093504),   # 7
            (HEX('32 08 0102030405060708 010900 0280928091'             # 8
                 '01000000 00000000 00000000 00000000'
                 '17c19e3b bdc3e8bd 00feff00 00000000'),
             0.46402560000000004),  # write STATE, MAC_A
            (HEX('12 06 0102030405060708 010b00 0280928081'),           # 9
             0.46402560000000004),  # read_with_mac STATE
            # read ndef
            (HEX('06 00 12fc 0000'), 0.003625),  # poll for ndef        # 10
            (HEX('12 06 0102030405060708 010b00 0280008081'),           # 11
             0.46402560000000004),  # read_with_mac Block 0
            # read MC for ndef attribute rw flag
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 12
            # write memory configuration
            (HEX('20 08 0102030405060708 010900 018088'  # write MC     # 13
                 'ffff0001 07010000 ff3fff3f 00000000'), 0.3093504),
        ]
        responses = [
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 1
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read CKV            # 2
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write CKV           # 3
            HEX('0c 09 0102030405060708 0000'),   # write CK            # 4
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
            # authenticate_2
            HEX('1d 07 0102030405060708 0000 01'  # read WCNT           # 7
                '00 FE FF 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write STATE, MAC_A  # 8
            HEX('2d 07 0102030405060708 0000 02'  # read STATE, MAC     # 9
                '01 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'bd 73 eb 72  94 a0 02 79  00 00 00 00  00 00 00 00'),
            HEX("12 01 0102030405060708 00F1FFFFFFFFFFFF"),  # polling  # 10
            HEX('2d 07 0102030405060708 0000 02'  # read attribute data # 11
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 12
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write MC            # 13
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect("0123456789abcdef") is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_protect_with_wrong_password(self, tag, mocker):
        mocker.patch('os.urandom', new=lambda x: bytes(bytearray(range(x))))
        commands = [
            (HEX('10 06 0102030405060708 010b00 018088'), 0.3093504),   # 1
            (HEX('10 06 0102030405060708 010b00 018086'), 0.3093504),   # 2
            (HEX('20 08 0102030405060708 010900 018086'  # write CKV    # 3
                 '01000000 00000000 00000000 00000000'), 0.3093504),
            (HEX('20 08 0102030405060708 010900 018087'  # write CK     # 4
                 '38373635 34333231 66656463 62613039'), 0.3093504),
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
        ]
        responses = [
            HEX('1d 07 0102030405060708 0000 01'  # read MC             # 1
                'FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('1d 07 0102030405060708 0000 01'  # read CKV            # 2
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write CKV           # 3
            HEX('0c 09 0102030405060708 0000'),   # write CK            # 4
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.protect("1234567890abcdef") is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_mutual_authentication_error(self, tag, mocker):
        mocker.patch('os.urandom', new=lambda x: bytes(bytearray(range(x))))
        commands = [
            # authenticate_1
            (HEX('20 08 0102030405060708 010900 018080'  # write RC     # 5
                 '07060504 03020100 0f0e0d0c 0b0a0908'), 0.3093504),
            (HEX('12 06 0102030405060708 010b00 0280828081'),           # 6
             0.46402560000000004),  # read ID, MAC
            # authenticate_2 - write_with_mac
            (HEX('10 06 0102030405060708 010b00 018090'), 0.3093504),   # 7
            (HEX('32 08 0102030405060708 010900 0280928091'             # 8
                 '01000000 00000000 00000000 00000000'
                 '17c19e3b bdc3e8bd 00feff00 00000000'),
             0.46402560000000004),  # write STATE, MAC_A
            (HEX('12 06 0102030405060708 010b00 0280928081'),           # 9
             0.46402560000000004),  # read_with_mac STATE
        ]
        responses = [
            # authenticate_1
            HEX('0c 09 0102030405060708 0000'),   # write RC            # 5
            HEX('2d 07 0102030405060708 0000 02'  # read ID, MAC        # 6
                '01 02 03 04  05 06 07 08  00 00 00 00  00 00 00 00'
                '91 ae c5 b6  d9 b3 b1 2d  00 00 00 00  00 00 00 00'),
            # authenticate_2
            HEX('1d 07 0102030405060708 0000 01'  # read WCNT           # 7
                '00 FE FF 00  00 00 00 00  00 00 00 00  00 00 00 00'),
            HEX('0c 09 0102030405060708 0000'),   # write STATE, MAC_A  # 8
            HEX('2d 07 0102030405060708 0000 02'  # read STATE, MAC     # 9
                '00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00'
                'cc 97 f1 b9  7b 8b bc 79  00 00 00 00  00 00 00 00'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.authenticate("0123456789abcdef") is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_with_mac_wrong_data_size(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.write_with_mac(bytearray(15), 0)
        assert str(excinfo.value) == "data must be 16 octets"

    def test_write_with_mac_block_arg_not_int(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.write_with_mac(bytearray(16), '0')
        assert str(excinfo.value) == "block number must be int"

    def test_write_with_mac_not_authenticated(self, tag):
        with pytest.raises(RuntimeError) as excinfo:
            tag.write_with_mac(bytearray(16), 0)
        assert str(excinfo.value) == "tag must be authenticated first"


###############################################################################
#
# FeliCa Plug
#
###############################################################################
@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaPlug:
    sys = "00 00"
    idm = "01 02 03 04 05 06 07 08"
    
    def __test_init_with_ic_code_e0(self):
        pmm = "00E0FFFF FFFFFFFF"
        clf = Type3TagSimulator(None, self.sys, self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaPlug)
        assert tag._product == "FeliCa Plug (RC-S926)"
        assert tag._nbr == 12
        assert tag._nbw == 12

    def __test_init_with_ic_code_e1(self):
        pmm = "00E1FFFF FFFFFFFF"
        clf = Type3TagSimulator(None, self.sys, self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaPlug)
        assert tag._product == "FeliCa Link (RC-S730) Plug Mode"
        assert tag._nbr == 12
        assert tag._nbw == 12
