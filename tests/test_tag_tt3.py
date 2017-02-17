# -*- coding: latin-1 -*-
import nfc
import nfc.tag
import nfc.tag.tt3
import ndef
import mock
import pytest
from pytest_mock import mocker  # noqa: F401


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
        sc = nfc.tag.tt3.ServiceCode.unpack("\x0B\x01")
        assert sc.number == 4
        assert sc.attribute == 11

    def test_pack(self):
        assert nfc.tag.tt3.ServiceCode(4, 11).pack() == "\x0B\x01"

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
        assert nfc.tag.tt3.BlockCode(12).pack() == "\x80\x0C"
        assert nfc.tag.tt3.BlockCode(12, 3).pack() == "\xB0\x0C"
        assert nfc.tag.tt3.BlockCode(12, 3, 1).pack() == "\xB1\x0C"
        assert nfc.tag.tt3.BlockCode(255).pack() == "\x80\xff"
        assert nfc.tag.tt3.BlockCode(256).pack() == "\x00\x00\x01"
        assert nfc.tag.tt3.BlockCode(256, 3).pack() == "\x30\x00\x01"
        assert nfc.tag.tt3.BlockCode(256, 3, 1).pack() == "\x31\x00\x01"
        assert nfc.tag.tt3.BlockCode(0xffff).pack() == "\x00\xff\xff"

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
            mock.call(HEX(
                '12 06 0102030405060708 010b00 0280008001'),
                      0.46402560000000004),
            mock.call(HEX(
                '14 06 0102030405060708 020b000b00 0280008101'),
                      0.46402560000000004),
            mock.call(HEX(
                '12 06 0102030405060708 010b00 0280008001'),
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
            mock.call(HEX(
                '12 06 0102030405060708 010b00 0280008001'),
                      0.46402560000000004),
        ]

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
            mock.call(HEX(
                '32 08 0102030405060708 010900 0280008001') + data,
                      0.46402560000000004),
            mock.call(HEX(
                '34 08 0102030405060708 0209004900 0280008101') + data,
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
        tag.write_to_ndef_service(data, 0, 1)
        assert tag.clf.exchange.mock_calls == [
            mock.call(HEX(
                '32 08 0102030405060708 010900 0280008001') + data,
                0.46402560000000004),
        ]

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

    def test_format(self, tag):
        tag.clf.exchange.side_effect = 13 * [
            # Read block 0x7fff, 0x3fff, 0x1fff, 0x0fff, 0x07ff, 0x03ff,
            # 0x01ff, 0x00ff, 0x007f, 0x003f, 0x001f, 0x000f, 0x0007 fails.
            HEX('0c 07 0102030405060708 FFFF'),
        ] + 3 * [
            # Read block 0x0003, 0x0005, 0x0006 succeeds.
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
        ] + 6 * [
            # Wipe NmaxB (6) data blocks
            HEX('0c 09 0102030405060708 0000'),
        ]
        assert tag.format(version=0x1F, wipe=0x5A) is True
        tag.clf.exchange.assert_any_call(HEX(
            '20 08 0102030405060708 010900 018000'
            # Ver Nbr Nbw NmaxB reserved WF RW Length Check
            ' 1f  03  02  0006  00000000 00 01 000000 002b'), 0.3093504)
        tag.clf.exchange.assert_called_with(HEX(
            '20 08 0102030405060708 010900 018001'
            '5a5a5a5a 5a5a5a5a 5a5a5a5a 5a5a5a5a'), 0.3093504)

        # Test no data block can be read.
        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = 16 * [
            # Read block 0x7fff, 0x3fff, 0x1fff, 0x0fff, 0x07ff, 0x03ff,
            # 0x01ff, 0x00ff, 0x007f, 0x003f, 0x001f, 0x000f, 0x0007,
            # 0x0003, 0x0001, 0x0000 fails.
            HEX('0c 07 0102030405060708 FFFF'),
        ]
        assert tag.format() is False

        # Test invalid version number.
        assert tag.format(version=0xF0) is False

        # Test wrong system code.
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
        records = [ndef.SmartposterRecord("http://nfc-forum.org", "NFC Forum")]
        tag.ndef.records = records
        print(tag.clf.exchange.mock_calls)
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
