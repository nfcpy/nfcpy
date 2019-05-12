# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.tag
import nfc.tag.tt3

import mock
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.tag.tt3").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    return clf


@pytest.fixture()
def target():
    target = nfc.clf.RemoteTarget("212F")
    target.sensf_res = HEX("01 0102030405060708 FFFFFFFFFFFFFFFF 12FC")
    return target


@pytest.fixture()
def tag(clf, target):
    tag = nfc.tag.activate(clf, target)
    assert isinstance(tag, nfc.tag.tt3.Type3Tag)
    return tag


def test_activate_with_wrong_idm_returns_none(clf):
    target = nfc.clf.RemoteTarget("212F")
    target.sensf_res = HEX("01 01FE000000000000 FFFFFFFFFFFFFFFF")
    assert nfc.tag.activate(clf, target) is None


###############################################################################
#
# TEST SERVICE CODE CLASS
#
###############################################################################
class TestServiceCode:
    def test_init(self):
        sc = nfc.tag.tt3.ServiceCode(1, 9)
        assert sc.number == 1
        assert sc.attribute == 9
        sc = nfc.tag.tt3.ServiceCode(number=1, attribute=9)
        assert sc.number == 1
        assert sc.attribute == 9

    def test_unpack(self):
        sc = nfc.tag.tt3.ServiceCode.unpack(b"\x0B\x01")
        assert sc.number == 4
        assert sc.attribute == 11

    def test_pack(self):
        assert nfc.tag.tt3.ServiceCode(4, 11).pack() == b"\x0B\x01"

    def test_repr(self):
        sc = nfc.tag.tt3.ServiceCode(1, 8)
        assert repr(sc) == "ServiceCode(1, 8)"

    def test_str(self):
        sc = nfc.tag.tt3.ServiceCode(1, 8)
        assert str(sc) == "Service Code 0048h (Service 1 Random RW with key)"
        sc = nfc.tag.tt3.ServiceCode(1, 0b111111)
        assert str(sc) == "Service Code 007Fh (Service 1 Type 111111b)"


###############################################################################
#
# TEST BLOCK CODE CLASS
#
###############################################################################
class TestBlockCode:
    def test_init(self):
        bc = nfc.tag.tt3.BlockCode(12)
        assert bc.number == 12
        assert bc.access == 0
        assert bc.service == 0
        bc = nfc.tag.tt3.BlockCode(12, 3)
        assert bc.number == 12
        assert bc.access == 3
        assert bc.service == 0
        bc = nfc.tag.tt3.BlockCode(12, 3, 1)
        assert bc.number == 12
        assert bc.access == 3
        assert bc.service == 1
        bc = nfc.tag.tt3.BlockCode(12, access=3)
        assert bc.number == 12
        assert bc.access == 3
        assert bc.service == 0
        bc = nfc.tag.tt3.BlockCode(12, service=1)
        assert bc.number == 12
        assert bc.access == 0
        assert bc.service == 1

    def test_pack(self):
        assert nfc.tag.tt3.BlockCode(12).pack() == b"\x80\x0C"
        assert nfc.tag.tt3.BlockCode(12, 3).pack() == b"\xB0\x0C"
        assert nfc.tag.tt3.BlockCode(12, 3, 1).pack() == b"\xB1\x0C"
        assert nfc.tag.tt3.BlockCode(255).pack() == b"\x80\xff"
        assert nfc.tag.tt3.BlockCode(256).pack() == b"\x00\x00\x01"
        assert nfc.tag.tt3.BlockCode(256, 3).pack() == b"\x30\x00\x01"
        assert nfc.tag.tt3.BlockCode(256, 3, 1).pack() == b"\x31\x00\x01"
        assert nfc.tag.tt3.BlockCode(0xffff).pack() == b"\x00\xff\xff"

    def test_repr(self):
        sc = nfc.tag.tt3.BlockCode(1, 3, 7)
        assert repr(sc) == "BlockCode(1, 3, 7)"

    def test_str(self):
        sc = nfc.tag.tt3.BlockCode(1, 3)
        assert str(sc) == "BlockCode(number=1, access=011, service=0)"


###############################################################################
#
# TEST TYPE 3 TAG CLASS
#
###############################################################################
ndef_data_1 = HEX(
    "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28"
    "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
    "02 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "03 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "04 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "05 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "06 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "07 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "08 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "09 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "0a 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
)

ndef_dump_1 = [
    "0000: 10 01 01 00 05 00 00 00 00 00 01 00 00 10 00 28 |...............(|",
    "0001: d1 02 0b 53 70 d1 01 07 55 03 61 62 2e 63 6f 6d |...Sp...U.ab.com|",
    "0002: 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0003: 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0004: 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0005: 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0006: 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0007: 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0008: 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0009: 09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "000A: 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
]

ndef_data_2 = HEX(
    "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28"
    "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "06 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "07 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "08 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "09 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "0a 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
)

ndef_dump_2 = [
    "0000: 10 01 01 00 05 00 00 00 00 00 01 00 00 10 00 28 |...............(|",
    "0001: d1 02 0b 53 70 d1 01 07 55 03 61 62 2e 63 6f 6d |...Sp...U.ab.com|",
    "0002: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "*     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0006: 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0007: 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0008: 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0009: 09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "000A: 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
]

ndef_data_3 = HEX(
    "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28"
    "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "06 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "0a 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
)

ndef_dump_3 = [
    "0000: 10 01 01 00 05 00 00 00 00 00 01 00 00 10 00 28 |...............(|",
    "0001: d1 02 0b 53 70 d1 01 07 55 03 61 62 2e 63 6f 6d |...Sp...U.ab.com|",
    "0002: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "*     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0006: 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0007: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "*     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "000A: 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
]

ndef_data_4 = HEX(
    "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28"
    "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "06 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
)

ndef_dump_4 = [
    "0000: 10 01 01 00 05 00 00 00 00 00 01 00 00 10 00 28 |...............(|",
    "0001: d1 02 0b 53 70 d1 01 07 55 03 61 62 2e 63 6f 6d |...Sp...U.ab.com|",
    "0002: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "*     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0006: 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "0007: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "*     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
    "000A: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|",
]


class TestType3Tag:
    def test_init(self, tag):
        assert tag.sys == 0x12FC
        assert tag.idm == HEX("01 02 03 04 05 06 07 08")
        assert tag.pmm == HEX("FF FF FF FF FF FF FF FF")
        assert tag.identifier == bytes(tag.idm)

    def test_str(self, tag):
        s = "Type3Tag ID=0102030405060708 PMM=FFFFFFFFFFFFFFFF SYS=12FC"
        assert str(tag) == s

    def test_init_without_system_code(self, clf, target):
        target.sensf_res = target.sensf_res[0:17]
        tag = nfc.tag.activate(clf, target)
        assert isinstance(tag, nfc.tag.tt3.Type3Tag)
        assert tag.sys == 0xFFFF
        assert tag.idm == HEX("01 02 03 04 05 06 07 08")
        assert tag.pmm == HEX("FF FF FF FF FF FF FF FF")

    def test_is_present(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        assert tag.is_present is True
        assert tag.is_present is False
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('060012fc0000'), 0.003625),
            mock.call(HEX('060012fc0000'), 0.003625),
            mock.call(HEX('060012fc0000'), 0.003625),
            mock.call(HEX('060012fc0000'), 0.003625),
        ]

    def test_polling(self, tag):
        tag.clf.exchange.side_effect = [
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX("14 01 0102030405060708 FFFFFFFFFFFFFFFF 12FC"),
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            HEX("10 01 0102030405060708 FFFFFFFFFFFF"),
        ]
        assert tag.polling() == (tag.idm, tag.pmm)
        assert tag.polling(0x12FC) == (tag.idm, tag.pmm)
        assert tag.polling(0xFFFF, 1) == (tag.idm, tag.pmm, HEX("12FC"))
        assert tag.polling(0x12FC, 0, 1) == (tag.idm, tag.pmm)
        assert tag.polling(0x12FC, 0, 3) == (tag.idm, tag.pmm)
        assert tag.polling(0x12FC, 0, 7) == (tag.idm, tag.pmm)
        assert tag.polling(0x12FC, 0, 15) == (tag.idm, tag.pmm)
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.polling()
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('0600ffff0000'), 0.003625),
            mock.call(HEX('060012fc0000'), 0.003625),
            mock.call(HEX('0600ffff0100'), 0.003625),
            mock.call(HEX('060012fc0001'), 0.0048330000000000005),
            mock.call(HEX('060012fc0003'), 0.007249),
            mock.call(HEX('060012fc0007'), 0.012081),
            mock.call(HEX('060012fc000f'), 0.021745),
            mock.call(HEX('0600ffff0000'), 0.003625),
        ]
        with pytest.raises(ValueError) as excinfo:
            tag.polling(0xFFFF, request_code=3)
        assert str(excinfo.value) == "invalid request code for polling"
        with pytest.raises(ValueError) as excinfo:
            tag.polling(0xFFFF, time_slots=255)
        assert str(excinfo.value) == "invalid number of time slots"

    def test_read_without_encryption(self, tag):
        data = HEX(
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23"
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
        )
        tag.clf.exchange.side_effect = [
            HEX('2d 07 0102030405060708 0000 02') + data[:32],
            HEX('2d 07 0102030405060708 0000 02') + data[:32],
            HEX('2c 07 0102030405060708 0000 02') + data[:31],
        ]

        sc_list = [nfc.tag.tt3.ServiceCode(0, 11)]
        bc_list = [nfc.tag.tt3.BlockCode(0), nfc.tag.tt3.BlockCode(1)]
        assert tag.read_without_encryption(sc_list, bc_list) == data[:32]

        sc_list = 2 * [nfc.tag.tt3.ServiceCode(0, 11)]
        bc_list = [nfc.tag.tt3.BlockCode(0), nfc.tag.tt3.BlockCode(1, 0, 1)]
        assert tag.read_without_encryption(sc_list, bc_list) == data[:32]

        sc_list = [nfc.tag.tt3.ServiceCode(0, 11)]
        bc_list = [nfc.tag.tt3.BlockCode(0), nfc.tag.tt3.BlockCode(1)]
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.read_without_encryption(sc_list, bc_list)
        assert excinfo.value.errno == nfc.tag.tt3.DATA_SIZE_ERROR

        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('12 06 0102030405060708 010b00 0280008001'),
                      0.46402560000000004),
            mock.call(HEX('14 06 0102030405060708 020b000b00 0280008101'),
                      0.46402560000000004),
            mock.call(HEX('12 06 0102030405060708 010b00 0280008001'),
                      0.46402560000000004),
        ]

    def test_read_from_ndef_service(self, tag):
        data = HEX(
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23"
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
        )
        tag.clf.exchange.side_effect = [
            HEX('2d 07 0102030405060708 0000 02') + data[:32],
        ]
        assert tag.read_from_ndef_service(0, 1) == data
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('12 06 0102030405060708 010b00 0280008001'),
                      0.46402560000000004),
        ]
        tag.sys = 0x0000
        tag.clf.exchange.reset_mock()
        assert tag.read_from_ndef_service(0, 1) is None
        assert tag.clf.exchange.called is False

    def test_write_without_encryption(self, tag):
        data = HEX(
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23"
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
        )
        tag.clf.exchange.side_effect = [
            HEX('0c 09 0102030405060708 0000'),
            HEX('0c 09 0102030405060708 0000'),
        ]

        sc_list = [nfc.tag.tt3.ServiceCode(0, 9)]
        bc_list = [nfc.tag.tt3.BlockCode(0),
                   nfc.tag.tt3.BlockCode(1)]
        tag.write_without_encryption(sc_list, bc_list, data)

        sc_list = [nfc.tag.tt3.ServiceCode(0, 9),
                   nfc.tag.tt3.ServiceCode(1, 9)]
        bc_list = [nfc.tag.tt3.BlockCode(0),
                   nfc.tag.tt3.BlockCode(1, 0, 1)]
        tag.write_without_encryption(sc_list, bc_list, data)

        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('3208 0102030405060708 0109000280008001') + data,
                      0.46402560000000004),
            mock.call(HEX('3408 0102030405060708 02090049000280008101') + data,
                      0.46402560000000004),
        ]

    def test_write_to_ndef_service(self, tag):
        data = HEX(
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23"
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d"
        )
        tag.clf.exchange.side_effect = [
            HEX('0c 09 0102030405060708 0000'),
        ] + 3 * [nfc.clf.TimeoutError]
        assert tag.write_to_ndef_service(data, 0, 1) is None
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX('32 08 0102030405060708 010900 0280008001') + data,
                      0.46402560000000004),
        ]
        tag.sys = 0x0000
        tag.clf.exchange.reset_mock()
        assert tag.write_to_ndef_service(data, 0, 1) is None
        assert tag.clf.exchange.called is False

    def test_send_cmd_recv_rsp(self, tag):
        xxx = tag.clf.exchange

        xxx.return_value = HEX("0DF1") + tag.idm + HEX("00005A")
        rsp = tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1)
        xxx.assert_called_once_with(HEX("0BF0") + tag.idm + HEX("A5"), 0.1)
        assert rsp == HEX("5A")

        xxx.reset_mock()
        xxx.return_value = HEX("03F15A")
        rsp = tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1, send_idm=False)
        xxx.assert_called_once_with(HEX("03F0A5"), 0.1)
        assert rsp == HEX("5A")

        xxx.reset_mock()
        xxx.return_value = HEX("0DF1") + tag.idm + HEX("12345A")
        rsp = tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1, check_status=False)
        xxx.assert_called_once_with(HEX("0BF0") + tag.idm + HEX("A5"), 0.1)
        assert rsp == HEX("12345A")

        xxx.reset_mock()
        xxx.return_value = HEX("04F15A")
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1, send_idm=False)
        assert excinfo.value.errno == nfc.tag.tt3.RSP_LENGTH_ERROR
        xxx.assert_called_once_with(HEX("03F0A5"), 0.1)

        xxx.reset_mock()
        xxx.return_value = HEX("03F35A")
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1, send_idm=False)
        assert excinfo.value.errno == nfc.tag.tt3.RSP_CODE_ERROR
        xxx.assert_called_once_with(HEX("03F0A5"), 0.1)

        xxx.reset_mock()
        xxx.return_value = HEX("0DF1 1020304050607080 0000 5A")
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1)
        assert excinfo.value.errno == nfc.tag.tt3.TAG_IDM_ERROR
        xxx.assert_called_once_with(HEX("0BF0") + tag.idm + HEX("A5"), 0.1)

        xxx.reset_mock()
        xxx.return_value = HEX("0DF1") + tag.idm + HEX("1234 5A")
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1)
        assert excinfo.value.errno == 0x1234
        xxx.assert_called_once_with(HEX("0BF0") + tag.idm + HEX("A5"), 0.1)

        xxx.reset_mock()
        xxx.side_effect = 3 * [nfc.clf.TimeoutError]
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1)
        assert excinfo.value.errno == nfc.tag.TIMEOUT_ERROR
        xxx.assert_called_with(HEX("0BF0") + tag.idm + HEX("A5"), 0.1)
        assert xxx.call_count == 3

        xxx.reset_mock()
        xxx.side_effect = 3 * [nfc.clf.TransmissionError]
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1)
        assert excinfo.value.errno == nfc.tag.RECEIVE_ERROR
        xxx.assert_called_with(HEX("0BF0") + tag.idm + HEX("A5"), 0.1)
        assert xxx.call_count == 3

        xxx.reset_mock()
        xxx.side_effect = 3 * [nfc.clf.ProtocolError]
        with pytest.raises(nfc.tag.tt3.Type3TagCommandError) as excinfo:
            tag.send_cmd_recv_rsp(0xF0, HEX("A5"), 0.1)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        xxx.assert_called_with(HEX("0BF0") + tag.idm + HEX("A5"), 0.1)
        assert xxx.call_count == 3

    @pytest.mark.parametrize("data, dump", [
        (ndef_data_1, ndef_dump_1),
        (ndef_data_2, ndef_dump_2),
        (ndef_data_3, ndef_dump_3),
        (ndef_data_4, ndef_dump_4),
    ])
    def test_dump(self, tag, data, dump):
        tag.clf.exchange.side_effect = [
            (HEX('1d 07 0102030405060708 0000 01') + data[i:i+16])
            for i in range(0, len(data), 16)
        ] + 3 * [nfc.clf.TimeoutError]
        assert tag.dump() == dump
        tag.sys = 0x0000
        assert tag.dump() == ["This is not an NFC Forum Tag."]

    def test_format_nbr_3_and_nbw_2_and_wipe(self, tag):
        tag.clf.exchange.side_effect = [
            # Read block 0 succeeds.
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),
        ] + 13 * [
            # Read block 0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400,
            # 0x0200, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010, 0x0008 fails.
            HEX('0c 07 0102030405060708 FFFF'),
        ] + 3 * [
            # Read block 0x0004, 0x0006, 0x0007 succeeds.
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),
        ] + [
            # number of blocks that can be read in one command
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),  # 0
            HEX('2d 07 0102030405060708 0000 02') + bytearray(32),  # 0, 1
            HEX('3d 07 0102030405060708 0000 03') + bytearray(48),  # 0, 1, 2
            HEX('0c 07 0102030405060708 FFFF'),  # read 4 blocks fails
        ] + [
            # number of blocks that can be written in one command
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),  # 0
            HEX('0c 09 0102030405060708 0000'),  # write 1 block ok
            HEX('0c 09 0102030405060708 0000'),  # write 2 blocks ok
            HEX('0c 09 0102030405060708 FFFF'),  # write 3 blocks fail
        ] + [
            # response to write attribute information block
            HEX('0c 09 0102030405060708 0000'),
        ] + 7 * [
            # Wipe NmaxB (7) data blocks
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.format(version=0x1F, wipe=0x5A) is True
        tag.clf.exchange.assert_any_call(HEX(
            '20 08 0102030405060708 010900 018000'
            # Ver Nbr Nbw NmaxB reserved WF RW Length Check
            ' 1f  03  02  0007  00000000 00 01 000000 002c'), 0.3093504)
        tag.clf.exchange.assert_called_with(HEX(
            '20 08 0102030405060708 010900 018001'
            '5a5a5a5a 5a5a5a5a 5a5a5a5a 5a5a5a5a'), 0.3093504)

    def test_format_nbr_15_and_nbw_13_not_wipe(self, tag):
        tag.clf.exchange.side_effect = [
            # Read block 0 succeeds.
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),
        ] + 13 * [
            # Read block 0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400,
            # 0x0200, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010, 0x0008 fails.
            HEX('0c 07 0102030405060708 FFFF'),
        ] + 3 * [
            # Read block 0x0004, 0x0006, 0x0007 succeeds.
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),
        ] + [
            # number of blocks that can be read in one command
            HEX('%xD 07 0102030405060708 0000 %02x' % (i, i)) + bytearray(i*16)
            for i in range(1, 16)
        ] + [
            # number of blocks that can be written in one command
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),  # 0
        ] + 13 * [
            HEX('0c 09 0102030405060708 0000'),  # write N blocks ok
        ] + [
            # response to write attribute information block
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.format(version=0x1F) is True
        tag.clf.exchange.assert_called_with(HEX(
            '20 08 0102030405060708 010900 018000'
            # Ver Nbr Nbw NmaxB reserved WF RW Length Check
            ' 1f  0F  0D  0007  00000000 00 01 000000 0043'), 0.3093504)

    def test_format_with_max_data_blocks(self, tag):
        tag.clf.exchange.side_effect = [
            # read block 0 succeeds
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),
        ] + 16 * [
            # read all blocks succeeds
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),
        ] + [
            # number of blocks that can be read in one command
            HEX('%xD 07 0102030405060708 0000 %02x' % (i, i)) + bytearray(i*16)
            for i in range(1, 16)
        ] + [
            # number of blocks that can be written in one command
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),  # 0
        ] + 13 * [
            HEX('0c 09 0102030405060708 0000'),  # write N blocks ok
        ] + [
            # response to write attribute information block
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.format(version=0x1F) is True
        tag.clf.exchange.assert_called_with(HEX(
            '20 08 0102030405060708 010900 018000'
            # Ver Nbr Nbw NmaxB reserved WF RW Length Check
            ' 1f  0F  0C  FFFF  00000000 00 01 000000 0239'), 0.3093504)

    def test_format_with_one_data_block(self, tag):
        tag.clf.exchange.side_effect = [
            # read block 0 succeeds
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),
        ] + 16 * [
            # fail read all other blocks
            HEX('0c 07 0102030405060708 FFFF'),
        ] + [
            # number of blocks that can be read in one command
            HEX('%xD 07 0102030405060708 0000 %02x' % (i, i)) + bytearray(i*16)
            for i in range(1, 16)
        ] + [
            # number of blocks that can be written in one command
            HEX('1d 07 0102030405060708 0000 01') + bytearray(16),  # 0
        ] + 13 * [
            HEX('0c 09 0102030405060708 0000'),  # write N blocks ok
        ] + [
            # response to write attribute information block
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.format(version=0x1F) is True
        tag.clf.exchange.assert_called_with(HEX(
            '20 08 0102030405060708 010900 018000'
            # Ver Nbr Nbw NmaxB reserved WF RW Length Check
            ' 1f  0F  0D  0000  00000000 00 01 000000 003C'), 0.3093504)

    def test_format_with_zero_data_blocks(self, tag):
        tag.clf.exchange.side_effect = [
            # read block 0 fails
            HEX('0c 07 0102030405060708 FFFF'),
        ]
        assert tag.format() is False

    def test_format_invalid_version_number(self, tag):
        assert tag.format(version=0xF0) is False

    def test_format_wrong_system_code(self, tag):
        tag.sys = 0x0000
        assert tag.format() is False

    def test_ndef_read(self, tag):
        data = HEX(
            "10 02 02 00  03 00 00 00  00 00 01 00  00 27 00 3f"
            "d1 02 22 53  70 91 01 0e  55 03 6e 66  63 2d 66 6f"
            "72 75 6d 2e  6f 72 67 51  01 0c 54 02  65 6e 4e 46"
            "43 20 46 6f  72 75 6d 00  00 00 00 00  00 00 00 00"
        )
        # polling fails
        tag.sys = 0x0000
        tag.clf.exchange.side_effect = [
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        assert tag.ndef is None
        tag.clf.exchange.assert_called_with(HEX('06 00 12FC 0000'), 0.003625)

        # read block 0 fails
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX("12 01 0102030405060708 FFFFFFFFFFFFFFFF"),
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        assert tag.ndef is None
        tag.clf.exchange.assert_called_with(HEX(
            '10 06 0102030405060708 010b00 018000'), 0.3093504)

        # read without error
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01') + data[:16],
            HEX('2d 07 0102030405060708 0000 02') + data[16:48],
            HEX('1d 07 0102030405060708 0000 01') + data[48:64],
        ]
        assert tag.ndef is not None
        assert tag.ndef.capacity == 48
        assert tag.ndef.length == 39
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        assert tag.ndef.octets == data[16:16+tag.ndef.length]
        tag.clf.exchange.assert_called_with(
            HEX('10 06 0102030405060708 010b00 018003'), 0.3093504)

        # readonly tag without content
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01') +
            HEX("10 02 02 00 03 00 00 00 00 00 00 00 00 00 00 17"),
        ]
        tag._ndef = None
        assert tag.ndef is not None
        assert tag.ndef.capacity == 48
        assert tag.ndef.length == 0
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is False
        assert tag.ndef.octets == b''
        tag.clf.exchange.assert_called_with(HEX(
            '10 06 0102030405060708 010b00 018000'), 0.3093504)

        # read block 4 fails
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01') + data[:16],
            HEX('2d 07 0102030405060708 0000 02') + data[16:48],
            nfc.clf.TimeoutError, nfc.clf.TimeoutError, nfc.clf.TimeoutError,
        ]
        tag._ndef = None
        assert tag.ndef is None
        tag.clf.exchange.assert_called_with(HEX(
            '10 06 0102030405060708 010b00 018003'), 0.3093504)

        # checksum error
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'
                "20 02 02 00  03 00 00 00  00 00 01 00  00 27 00 3f"),
        ]
        tag._ndef = None
        assert tag.ndef is None
        tag.clf.exchange.assert_called_with(HEX(
            '10 06 0102030405060708 010b00 018000'), 0.3093504)

        # version error
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01'
                "20 02 02 00  03 00 00 00  00 00 01 00  00 27 00 4f"),
        ]
        tag._ndef = None
        assert tag.ndef is None
        tag.clf.exchange.assert_called_with(HEX(
            '10 06 0102030405060708 010b00 018000'), 0.3093504)

    def test_ndef_write(self, tag):
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01') +
            HEX("10 02 02 00 03 00 00 00 00 00 01 00 00 00 00 18"),
        ]
        assert tag.ndef is not None
        assert tag.ndef.capacity == 48
        assert tag.ndef.length == 0
        assert tag.ndef.is_readable is True
        assert tag.ndef.is_writeable is True
        assert tag.ndef.octets == b''
        tag.clf.exchange.assert_called_with(HEX(
            '10 06 0102030405060708 010b00 018000'), 0.3093504)

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [
            HEX('1d 07 0102030405060708 0000 01') +
            HEX("10 02 02 00 03 00 00 00 00 00 01 00 00 00 00 18"),
            HEX('0c 09 0102030405060708 0000'),  # write block 0
            HEX('0c 09 0102030405060708 0000'),  # write block 1, 2
            HEX('0c 09 0102030405060708 0000'),  # write block 3
            HEX('0c 09 0102030405060708 0000'),  # write block 0
        ]
        tag.ndef.octets = (
            HEX('d1022253 7091010e 55036e66 632d666f') +  # .."Sp...U.nfc-fo
            HEX('72756d2e 6f726751 010c5402 656e4e46') +  # rum.orgQ..T.enNF
            HEX('4320466f 72756d')                        # C Forum|
        )
        tag.clf.exchange.assert_has_calls([
            mock.call(  # read attribute data
                HEX('10 06 0102030405060708 010b00 018000'), 0.3093504),
            mock.call(  # write attribute data (set WriteFlag)
                HEX('20 08 0102030405060708 010900 018000'
                    '1002020003000000000f010000000027'), 0.3093504),
            mock.call(  # write data blocks 1 and 2 (because Nbw is 2)
                HEX('32 08 0102030405060708 010900 0280018002'
                    'd10222537091010e55036e66632d666f'
                    '72756d2e6f726751010c5402656e4e46'), 0.46402560000000004),
            mock.call(  # write data block 3 (with zero padding)
                HEX('20 08 0102030405060708 010900 018003'
                    '4320466f72756d000000000000000000'), 0.3093504),
            mock.call(  # write attribute data (unset WriteFlag, set Ln)
                HEX('20 08 0102030405060708 010900 018000'
                    '1002020003000000000001000027003f'), 0.3093504),
        ])


###############################################################################
#
# TEST TYPE 3 TAG EMULATION
#
###############################################################################
def BLOCK_DATA(value):
    return bytearray(16 * [value] if isinstance(value, int) else value)


class TestTagEmulation:
    @pytest.fixture()
    def target(self):
        target = nfc.clf.LocalTarget('212F')
        target.sensf_req = HEX('0012FC0103')
        target.sensf_res = HEX('0102FE010203040506FFFFFFFFFFFFFFFF12FC')
        target.tt3_cmd = HEX('0602fe010203040506010b00018000')
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        tag = nfc.tag.emulate(clf, target)
        assert isinstance(tag, nfc.tag.tt3.Type3TagEmulation)
        return tag

    def test_init(self, tag, clf, target):
        assert tag.services == {}
        assert tag.target == target
        assert tag.cmd == HEX('100602fe010203040506010b00018000')
        assert tag.idm == HEX('02FE010203040506')
        assert tag.pmm == HEX('FFFFFFFFFFFFFFFF')
        assert tag.sys == HEX('12FC')
        assert tag.clf == clf

    def test_str(self, tag):
        assert str(tag) == ("Type3TagEmulation IDm=02fe010203040506"
                            " PMm=ffffffffffffffff SYS=12fc")

    def test_send_response(self, tag):
        tag.clf.exchange.side_effect = [HEX('040506')]
        assert tag.send_response(HEX('010203'), 0.5) == HEX('040506')
        assert tag.clf.exchange.mock_calls == [mock.call(HEX('010203'), 0.5)]

    def test_polling(self, tag):
        rsp = tag.process_command(HEX('06 00 12FC0003'))
        assert rsp == HEX('12 01 02FE010203040506 FFFFFFFFFFFFFFFF')
        rsp = tag.process_command(HEX('06 0012FC0103'))
        assert rsp == HEX('14 01 02FE010203040506 FFFFFFFFFFFFFFFF 12FC')

    def test_request_response(self, tag):
        rsp = tag.process_command(HEX('0A 04 02FE010203040506'))
        assert rsp == HEX('0B 05 02FE010203040506 00')

    @pytest.mark.parametrize("bn, be", [
        # (block_number, block_element)
        (0, '8000'), (1, '8001'), (0, '000000'), (1, '000100'),
    ])
    def test_read_service_check_block_data(self, tag, bn, be):
        def read(block_number, rb, re):
            assert rb is True and re is True
            return BLOCK_DATA(block_number % 256)

        tag.add_service(0x000B, read, lambda: False)

        cmd_fmt = '{:02x} 06 02fe010203040506 010b00 01 {:s}'
        cmd = HEX(cmd_fmt.format(14 + len(HEX(be)), be))
        rsp = HEX('1d 07 02fe010203040506 0000 01') + BLOCK_DATA(bn)
        assert tag.process_command(cmd) == rsp

    @pytest.mark.parametrize("nob, bel", [
        # (number_of_blocks, block_element_list)
        (1, '01 8000'), (2, '02 8000 8001'), (3, '03 8000 000100 8002'),
    ])
    def test_read_service_multiple_blocks(self, tag, nob, bel):
        def read(block_number, rb, re):
            assert rb is (True if block_number == 0 else False)
            assert re is (True if block_number == nob-1 else False)
            return BLOCK_DATA(0)

        tag.add_service(0x000B, read, lambda: False)

        cmd_fmt = '{:02x} 06 02fe010203040506 010b00 {:s}'
        rsp_fmt = '{:x}D  07 02fe010203040506 0000 {:02x} {:s}'
        cmd = HEX(cmd_fmt.format(13 + len(HEX(bel)), bel))
        rsp = HEX(rsp_fmt.format(nob, nob, nob * 16 * '00'))
        assert tag.process_command(cmd) == rsp

    @pytest.mark.parametrize("bn, be", [
        # (block_number, block_element)
        (0, '8000'), (1, '8001'), (0, '000000'), (1, '000100'),
    ])
    def test_write_service_check_block_data(self, tag, bn, be):
        def write(block_number, block_data, wb, we):
            assert block_data == BLOCK_DATA(block_number % 256)
            assert wb is True and we is True
            return True

        tag.add_service(0x0009, lambda: False, write)

        cmd = '{:02x} 08 02fe010203040506 010900 01 {:s}'
        cmd = HEX(cmd.format(14 + len(HEX(be)) + 16, be)) + BLOCK_DATA(bn)
        assert tag.process_command(cmd) == HEX('0C 09 02fe010203040506 0000')

    @pytest.mark.parametrize("nob, bel", [
        # (number_of_blocks, block_element_list)
        (1, '01 8000'), (2, '02 8000 8001'), (3, '03 8000 000100 8002'),
    ])
    def test_write_service_multiple_blocks(self, tag, nob, bel):
        def write(block_number, block_data, wb, we):
            assert block_data == BLOCK_DATA(0)
            assert wb is (True if block_number == 0 else False)
            assert we is (True if block_number == nob-1 else False)
            return True

        tag.add_service(0x0009, lambda: False, write)

        cmd_fmt = '{:02x} 08 02fe010203040506 010900 {:s} {:s}'
        rsp_fmt = '{:02x} 09 02fe010203040506 0000'
        cmd = HEX(cmd_fmt.format(13+len(HEX(bel))+nob*16, bel, nob*16*'00'))
        rsp = HEX(rsp_fmt.format(12))
        assert tag.process_command(cmd) == rsp

    def test_request_system_code(self, tag):
        rsp = tag.process_command(HEX('0A 0C 02FE010203040506'))
        assert rsp == HEX('0D 0D 02FE010203040506 01 12FC')

    def test_process_unknown_command(self, tag):
        assert tag.process_command(HEX('0A FF 02FE010203040506')) is None

    def test_process_command_length_error(self, tag):
        assert tag.process_command(HEX('0B 0C 02FE010203040506')) is None

    def test_process_command_idm_error(self, tag):
        assert tag.process_command(HEX('0A 0C F2FE010203040506')) is None

    def test_read_from_unknown_service(self, tag):
        cmd = HEX('10 06 02fe010203040506 010b00 018000')
        rsp = HEX('0C 07 02fe010203040506 FFA1')
        assert tag.process_command(cmd) == rsp

    def test_read_more_blocks_than_possible(self, tag):
        tag.add_service(0x000B, None, None)
        cmd = HEX('2E 06 02fe010203040506 010b00 10' + 16 * '8000')
        rsp = HEX('0C 07 02fe010203040506 FFA2')
        assert tag.process_command(cmd) == rsp

    def test_read_from_non_existing_block(self, tag):
        tag.add_service(0x000B, None, None)
        cmd = HEX('10 06 02fe010203040506 010b00 018000')
        rsp = HEX('0C 07 02fe010203040506 01A2')
        assert tag.process_command(cmd) == rsp

    def test_read_wrong_service_list_index(self, tag):
        tag.add_service(0x000B, None, None)
        cmd = HEX('10 06 02fe010203040506 010b00 018100')
        rsp = HEX('0C 07 02fe010203040506 01A3')
        assert tag.process_command(cmd) == rsp

    def test_write_to_unknown_service(self, tag):
        cmd = HEX('20 08 02fe010203040506 010b00 018000') + bytearray(16)
        rsp = HEX('0C 09 02fe010203040506 FFA1')
        assert tag.process_command(cmd) == rsp

    def test_write_insufficient_block_data(self, tag):
        tag.add_service(0x000B, None, None)
        cmd = HEX('1F 08 02fe010203040506 010b00 018000') + bytearray(15)
        rsp = HEX('0C 09 02fe010203040506 FFA2')
        assert tag.process_command(cmd) == rsp

    def test_write_to_non_existing_block(self, tag):
        tag.add_service(0x000B, None, None)
        cmd = HEX('20 08 02fe010203040506 010b00 018000') + bytearray(16)
        rsp = HEX('0C 09 02fe010203040506 01A2')
        assert tag.process_command(cmd) == rsp

    def test_write_wrong_service_list_index(self, tag):
        tag.add_service(0x000B, None, None)
        cmd = HEX('20 08 02fe010203040506 010b00 018100') + bytearray(16)
        rsp = HEX('0C 09 02fe010203040506 01A3')
        assert tag.process_command(cmd) == rsp
