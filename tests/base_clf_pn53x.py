# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.pn53x

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call
from binascii import hexlify


def HEX(s):
    return bytearray.fromhex(s)


def SFRAME(hexstr):
    data = HEX(hexstr)
    return (bytearray([0, 0, 255, len(data), 256-len(data)]) + data +
            bytearray([256 - sum(data) & 255, 0]))


def CMD(hexstr):
    return SFRAME('D4' + hexstr)


def RSP(hexstr):
    return SFRAME('D5' + hexstr)


ACK = HEX('0000FF00FF00')
NAK = HEX('0000FFFF0000')
ERR = HEX('0000FF01FF7F8100')


class TestChipset:
    @pytest.mark.parametrize("args, result, command, response", [
        (('rom', None), True, '00 01', '01 00'),
        (('ram', None), True, '00 02', '01 00'),
        ((0xFF, b'\x31'), b'\x32', '00 ff31', '01 32'),
    ])
    def test_diagnose(self, chipset, args, result, command, response):
        chipset.transport.read.side_effect = [ACK, RSP(response)]
        assert chipset.diagnose(*args) == result
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(CMD(command))]

    def test_get_general_status(self, chipset):
        chipset.transport.read.side_effect = [ACK, RSP('05 00 01 02')]
        assert chipset.get_general_status() == HEX('00 01 02')
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        assert chipset.transport.write.mock_calls == [call(CMD('04'))]
        chipset.transport.read.side_effect = [ACK, RSP('05')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.get_general_status()
        assert excinfo.value.errno == 255

    @pytest.mark.parametrize("args, command, response, value", [
        ((0x0102,), '06 0102', '07 01', 0x01),
        (("CIU_TMode",), '06 631A', '07 BB', 0xBB),
        ((0x0102, "CIU_TMode"), '06 0102631A', '07 AABB', [0xAA, 0xBB]),
    ])
    def test_read_register(self, chipset, args, command, response, value):
        chipset.transport.read.side_effect = [ACK, RSP(response)]
        assert chipset.read_register(*args) == value
        assert chipset.transport.read.mock_calls == [call(100), call(250)]
        assert chipset.transport.write.mock_calls == [call(CMD(command))]

    @pytest.mark.parametrize("args, command", [
        ((0x0102, 0x00), '08 0102 00'),
        (("CIU_Mode", 0x01), '08 6301 01'),
        (((0x0102, 0x10), ("CIU_Mode", 0x11)), '08 0102 10 6301 11'),
    ])
    def test_write_register(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK, RSP('09')]
        assert chipset.write_register(*args) is None
        assert chipset.transport.read.mock_calls == [call(100), call(250)]
        assert chipset.transport.write.mock_calls == [call(CMD(command))]

    @pytest.mark.parametrize("args, command", [
        # (act_pass, br, passive_data, nfcid3, gi)
        ((False, 106, HEX(''), HEX(''), HEX('')),
         CMD('56 00 00 00')),
        ((True, 212, HEX('f1f2f3f4'), HEX(''), HEX('')),
         CMD('56 01 01 01 f1f2f3f4')),
        ((True, 212, HEX('f1f2f3f4f5'), HEX(''), HEX('d1d2')),
         CMD('56 01 01 05 f1f2f3f4f5 d1d2')),
        ((True, 212, HEX(''), HEX('0102030405060708090a'), HEX('')),
         CMD('56 01 01 02 0102030405060708090a')),
    ])
    def test_in_jump_for_dep(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK, RSP('57 00 01 aa')]
        assert chipset.in_jump_for_dep(*args) == HEX('aa')
        chipset.transport.read.side_effect = [ACK, RSP('57 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_jump_for_dep(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(3000)]
        assert chipset.transport.write.mock_calls == 2 * [call(command)]

    @pytest.mark.parametrize("args, command", [
        # (act_pass, br, passive_data, nfcid3, gi)
        ((False, 106, HEX(''), HEX(''), HEX('')),
         CMD('46 00 00 00')),
        ((True, 212, HEX('f1f2f3f4'), HEX(''), HEX('')),
         CMD('46 01 01 01 f1f2f3f4')),
        ((True, 212, HEX('f1f2f3f4f5'), HEX(''), HEX('d1d2')),
         CMD('46 01 01 05 f1f2f3f4f5 d1d2')),
        ((True, 212, HEX(''), HEX('0102030405060708090a'), HEX('')),
         CMD('46 01 01 02 0102030405060708090a')),
    ])
    def test_in_jump_for_psl(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK, RSP('47 00 01 aa')]
        assert chipset.in_jump_for_psl(*args) == HEX('aa')
        chipset.transport.read.side_effect = [ACK, RSP('47 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_jump_for_psl(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(3000)]
        assert chipset.transport.write.mock_calls == 2 * [call(command)]

    @pytest.mark.parametrize("args, command", [
        # (max_tg, brty, initiator_data)
        ((1, 0x02, HEX('0a 0b')), CMD('4A 01 02 0a 0b')),
    ])
    def test_in_list_passive_target(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK, RSP('4B 01 01 aa bb')]
        assert chipset.in_list_passive_target(*args) == HEX('aa bb')
        chipset.transport.read.side_effect = [ACK, RSP('4B 00')]
        assert chipset.in_list_passive_target(*args) is None
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == 2 * [call(command)]

    @pytest.mark.parametrize("args, command", [
        # (nfcid3i, gi)
        ((HEX(''), HEX('')),
         CMD('50 01 00')),
        ((HEX('0102030405060708090a'), HEX('')),
         CMD('50 01 01 0102030405060708090a')),
        ((HEX('0102030405060708090a'), HEX('0b0c0d0e0f')),
         CMD('50 01 03 0102030405060708090a 0b0c0d0e0f')),
    ])
    def test_in_atr(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK, RSP('51 00 aa bb cc')]
        assert chipset.in_atr(*args) == HEX('aa bb cc')
        chipset.transport.read.side_effect = [ACK, RSP('51 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_atr(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(1500)]
        assert chipset.transport.write.mock_calls == 2 * [call(command)]

    @pytest.mark.parametrize("args, command", [
        # (br_it, br_ti)
        ((2, 1), CMD('4E 01 02 01')),
    ])
    def test_in_psl(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK, RSP('4F 00')]
        assert chipset.in_psl(*args) is None
        chipset.transport.read.side_effect = [ACK, RSP('4F 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_psl(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == 2 * [call(command)]


class TestDevice:
    @pytest.fixture()
    def device(self, transport):
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK, RSP('01 00' + hexlify(bytearray(range(251)))),  # Diagnose
            ACK, RSP('03 0304'),  # GetFirmwareVersion
            ACK, RSP('15'),       # SAMConfiguration
            ACK, RSP('13'),       # SetTAMAParameters
            ACK, RSP('33'),       # RFConfiguration
            ACK, RSP('33'),       # RFConfiguration
            ACK, RSP('33'),       # RFConfiguration
            ACK, RSP('33'),       # RFConfiguration
        ]
        device = nfc.clf.pn531.init(transport)
        assert isinstance(device, nfc.clf.pn531.Device)
        assert isinstance(device.chipset, nfc.clf.pn531.Chipset)
        assert transport.write.mock_calls == [call(_) for _ in [
            CMD('00 00' + hexlify(bytearray(range(251)))),  # Diagnose
            CMD('02'),            # GetFirmwareVersion
            CMD('14 0100'),       # SAMConfiguration
            CMD('12 00'),         # SetTAMAParameters
            CMD('32 02000b0a'),   # RFConfiguration
            CMD('32 0400'),       # RFConfiguration
            CMD('32 05010001'),   # RFConfiguration
            CMD('32 0102'),       # RFConfiguration
        ]]
        transport.write.reset_mock()
        transport.read.reset_mock()
        yield device
        transport.write.reset_mock()
        transport.read.reset_mock()
        transport.read.side_effect = [
            ACK, RSP('33'),  # RFConfiguration
        ]
        device.close()
        assert transport.write.mock_calls == [
            call(CMD('32 0102')),  # RFConfiguration
        ]

    def test_sense_tta_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK, RSP('4B 00'),  # InListPassiveTarget
            ACK, RSP('07 26'),  # ReadRegister
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.write.mock_calls == [
            call(CMD('4A 0100')),  # InListPassiveTarget
            call(CMD('06 6339')),  # ReadRegister
        ]
        pass
