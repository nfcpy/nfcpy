# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.pn53x

import os
import errno
import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call


def HEX(s):
    return bytearray.fromhex(s)


def STD_FRAME(data):
    LEN = bytearray([len(data)])
    LCS = bytearray([256 - sum(LEN) & 255])
    DCS = bytearray([256 - sum(data) & 255])
    return HEX('0000ff') + LEN + LCS + data + DCS + HEX('00')


def EXT_FRAME(data):
    LEN = bytearray([len(data) // 256, len(data) % 256])
    LCS = bytearray([256 - sum(LEN) & 255])
    DCS = bytearray([256 - sum(data) & 255])
    return HEX('0000ffffff') + LEN + LCS + data + DCS + HEX('00')


def CMD(hexstr):
    data = HEX('D4' + hexstr)
    return STD_FRAME(data) if len(data) < 256 else EXT_FRAME(data)


def RSP(hexstr):
    data = HEX('D5' + hexstr)
    return STD_FRAME(data) if len(data) < 256 else EXT_FRAME(data)


def ACK():
    return HEX('0000FF00FF00')


def NAK():
    return HEX('0000FFFF0000')


def ERR():
    return HEX('0000FF01FF7F8100')


class TestChipset:
    def test_command_with_standard_frame(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('0000ff 05fb d5 01 343536 8b 00')
        chipset.transport.read.side_effect = [ACK(), rsp]
        assert chipset.command(0, b'123', 1.0) == b'456'
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_extended_frame(self, chipset):
        if chipset.host_command_frame_max_size >= 256:
            cmd_data = b'123' + bytearray(256)
            rsp_data = b'456' + bytearray(256)
            cmd = HEX('0000ffffff 0105fa d400') + cmd_data + HEX('9600')
            rsp = HEX('0000ffffff 0105fa d501') + rsp_data + HEX('8b00')
            chipset.transport.read.side_effect = [ACK(), rsp]
            assert chipset.command(0, cmd_data, 1.0) == rsp_data
            assert chipset.transport.read.mock_calls == [call(100), call(1000)]
            assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_cmd_data_is_none(self, chipset):
        rsp = HEX('0000ff 05fb d5 01 343536 8b 00')
        chipset.transport.read.side_effect = [rsp]
        assert chipset.command(0, None, 1.0) == b'456'
        assert chipset.transport.read.mock_calls == [call(1000)]
        assert chipset.transport.write.mock_calls == []

    def test_command_with_timeout_zero(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        chipset.transport.read.side_effect = [ACK()]
        assert chipset.command(0, b'123', 0) is None
        assert chipset.transport.read.mock_calls == [call(100)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_missing_ack_frame(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('0000ff 05fb d5 01 343536 8b 00')
        chipset.transport.read.side_effect = [rsp]
        assert chipset.command(0, b'123', 1.0) == b'456'
        assert chipset.transport.read.mock_calls == [call(100)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_too_much_data(self, chipset):
        with pytest.raises(AssertionError):
            cmd_data = bytearray(chipset.host_command_frame_max_size)
            chipset.command(0, cmd_data, 1.0)

    def test_command_with_error_waiting_for_ack(self, chipset):
        chipset.transport.read.side_effect = [IOError]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO

    def test_command_with_ack_invalid_sof(self, chipset):
        chipset.transport.read.side_effect = [HEX('000000')]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO

    def test_command_with_rsp_timeout_error(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = IOError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.ETIMEDOUT
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd), call(ACK())]

    def test_command_with_rsp_inout_error(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = IOError(errno.EIO, os.strerror(errno.EIO))
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_std_frame_length_check_error(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('0000ff 04fb d5 01 343536 8b 00')
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_std_frame_length_value_error(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('0000ff 05fb d5 01 3435 8b 00')
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_ext_frame_length_check_error(self, chipset):
        if chipset.host_command_frame_max_size >= 256:
            cmd_data = b'123' + bytearray(256)
            rsp_data = b'456' + bytearray(256)
            cmd = HEX('0000ffffff 0105fa d400') + cmd_data + HEX('9600')
            rsp = HEX('0000ffffff 0104fa d501') + rsp_data + HEX('8b00')
            chipset.transport.read.side_effect = [ACK(), rsp]
            with pytest.raises(IOError) as excinfo:
                chipset.command(0, cmd_data, 1.0)
            assert excinfo.value.errno == errno.EIO
            assert chipset.transport.read.mock_calls == [call(100), call(1000)]
            assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_ext_frame_length_value_error(self, chipset):
        if chipset.host_command_frame_max_size >= 256:
            cmd_data = b'123' + bytearray(256)
            rsp_data = b'456' + bytearray(255)
            cmd = HEX('0000ffffff 0105fa d400') + cmd_data + HEX('9600')
            rsp = HEX('0000ffffff 0105fa d501') + rsp_data + HEX('8b00')
            chipset.transport.read.side_effect = [ACK(), rsp]
            with pytest.raises(IOError) as excinfo:
                chipset.command(0, cmd_data, 1.0)
            assert excinfo.value.errno == errno.EIO
            assert chipset.transport.read.mock_calls == [call(100), call(1000)]
            assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_rsp_invalid_sof(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('000000 05fb d5 01 343536 8b 00')
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_rsp_data_check_error(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('0000ff 05fb d5 01 343536 8a 00')
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_rsp_error_frame(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        chipset.transport.read.side_effect = [ACK(), ERR()]
        with pytest.raises(chipset.Error) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == 0x7f
        assert str(excinfo.value) == \
            "Error 0x7F: Invalid command syntax - received error frame"
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_rsp_frame_id_error(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('0000ff 05fb d6 01 343536 8a 00')
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_command_with_unexpected_rsp_code(self, chipset):
        cmd = HEX('0000ff 05fb d4 00 313233 96 00')
        rsp = HEX('0000ff 05fb d5 02 343536 8a 00')
        chipset.transport.read.side_effect = [ACK(), rsp]
        with pytest.raises(IOError) as excinfo:
            chipset.command(0, b'123', 1.0)
        assert excinfo.value.errno == errno.EIO
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(cmd)]

    def test_send_ack(self, chipset):
        assert chipset.send_ack() is None
        assert chipset.transport.write.mock_calls == [call(ACK())]

    @pytest.mark.parametrize("args, result, command, response", [
        (('rom', None), True, '00 01', '01 00'),
        (('ram', None), True, '00 02', '01 00'),
        ((0xFF, b'\x31'), b'\x32', '00 ff31', '01 32'),
    ])
    def test_diagnose(self, chipset, args, result, command, response):
        chipset.transport.read.side_effect = [ACK(), RSP(response)]
        assert chipset.diagnose(*args) == result
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(CMD(command))]

    def test_get_general_status(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('05 00 01 02')]
        assert chipset.get_general_status() == HEX('00 01 02')
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        assert chipset.transport.write.mock_calls == [call(CMD('04'))]
        chipset.transport.read.side_effect = [ACK(), RSP('05')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.get_general_status()
        assert excinfo.value.errno == 255

    @pytest.mark.parametrize("args, command, response, value", [
        ((0x0102,), '06 0102', '07 01', 0x01),
        (("CIU_TMode",), '06 631A', '07 BB', 0xBB),
        ((0x0102, "CIU_TMode"), '06 0102631A', '07 AABB', [0xAA, 0xBB]),
    ])
    def test_read_register(self, chipset, args, command, response, value):
        chipset.transport.read.side_effect = [ACK(), RSP(response)]
        assert chipset.read_register(*args) == value
        assert chipset.transport.read.mock_calls == [call(100), call(250)]
        assert chipset.transport.write.mock_calls == [call(CMD(command))]
        with pytest.raises(NotImplementedError):
            nfc.clf.pn53x.Chipset(None, None).read_register(*args)

    @pytest.mark.parametrize("args, command", [
        ((0x0102, 0x00), '08 0102 00'),
        (("CIU_Mode", 0x01), '08 6301 01'),
        (((0x0102, 0x10), ("CIU_Mode", 0x11)), '08 0102 10 6301 11'),
    ])
    def test_write_register(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK(), RSP('09')]
        assert chipset.write_register(*args) is None
        assert chipset.transport.read.mock_calls == [call(100), call(250)]
        assert chipset.transport.write.mock_calls == [call(CMD(command))]
        with pytest.raises(NotImplementedError):
            nfc.clf.pn53x.Chipset(None, None).write_register(*args)

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
        chipset.transport.read.side_effect = [ACK(), RSP('57 00 01 aa')]
        assert chipset.in_jump_for_dep(*args) == HEX('aa')
        chipset.transport.read.side_effect = [ACK(), RSP('57 01')]
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
        chipset.transport.read.side_effect = [ACK(), RSP('47 00 01 aa')]
        assert chipset.in_jump_for_psl(*args) == HEX('aa')
        chipset.transport.read.side_effect = [ACK(), RSP('47 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_jump_for_psl(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(3000)]
        assert chipset.transport.write.mock_calls == 2 * [call(command)]

    def test_in_list_passive_target(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('4B 01 01 32')]
        assert chipset.in_list_passive_target(1, 2, b'1') == b'2'
        chipset.transport.read.side_effect = [ACK(), RSP('4B 00')]
        assert chipset.in_list_passive_target(1, 2, b'1') is None
        assert chipset.transport.read.mock_calls == 2*[call(100), call(1000)]
        assert chipset.transport.write.mock_calls == 2*[call(CMD('4A010231'))]

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
        chipset.transport.read.side_effect = [ACK(), RSP('51 00 aa bb cc')]
        assert chipset.in_atr(*args) == HEX('aa bb cc')
        chipset.transport.read.side_effect = [ACK(), RSP('51 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_atr(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(1500)]
        assert chipset.transport.write.mock_calls == 2 * [call(command)]

    def test_in_psl(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('4F 00')]
        assert chipset.in_psl(2, 1) is None
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(CMD('4E 01 02 01'))]

        chipset.transport.read.side_effect = [ACK(), RSP('4F 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_psl(2, 1)
        assert excinfo.value.errno == 1

    def test_in_data_exchange(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('41 00 aabb')]
        assert chipset.in_data_exchange(b'12', 1.1) == (HEX('aabb'), False)
        assert chipset.transport.read.mock_calls == [call(100), call(1100)]
        assert chipset.transport.write.mock_calls == [call(CMD('40 01 3132'))]

        chipset.transport.read.side_effect = [ACK(), RSP('41 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_data_exchange(b'', 1.1)
        assert excinfo.value.errno == 1

    def test_in_communicate_thru(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('43 00 aabb')]
        assert chipset.in_communicate_thru(b'12', 1.1) == HEX('aabb')
        assert chipset.transport.read.mock_calls == [call(100), call(1100)]
        assert chipset.transport.write.mock_calls == [call(CMD('42 3132'))]

        chipset.transport.read.side_effect = [ACK(), RSP('43 00 aabb')]
        assert chipset.in_communicate_thru(b'34', 0) is None

        chipset.transport.read.side_effect = [ACK(), RSP('43 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.in_communicate_thru(b'', 1.1)
        assert excinfo.value.errno == 1

    def test_tg_set_general_bytes(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('93 00')]
        assert chipset.tg_set_general_bytes(b'12') is None
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        assert chipset.transport.write.mock_calls == [call(CMD('92 3132'))]

        chipset.transport.read.side_effect = [ACK(), RSP('93 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.tg_set_general_bytes(b'')
        assert excinfo.value.errno == 1

    def test_tg_get_data(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('87 00 aabb')]
        assert chipset.tg_get_data(1.1) == (HEX('aabb'), False)
        chipset.transport.read.side_effect = [ACK(), RSP('87 40 aabb')]
        assert chipset.tg_get_data(1.1) == (HEX('aabb'), True)
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(1100)]
        assert chipset.transport.write.mock_calls == 2 * [call(CMD('86'))]

        chipset.transport.read.side_effect = [ACK(), RSP('87 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.tg_get_data(1.1)
        assert excinfo.value.errno == 1

    def test_tg_set_data(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('8F 00')]
        assert chipset.tg_set_data(b'12', 1.1) is None
        assert chipset.transport.read.mock_calls == [call(100), call(1100)]
        assert chipset.transport.write.mock_calls == [call(CMD('8E 3132'))]

        chipset.transport.read.side_effect = [ACK(), RSP('8F 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.tg_set_data(b'12', 1.1)
        assert excinfo.value.errno == 1

    def test_tg_set_meta_data(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('95 00')]
        assert chipset.tg_set_meta_data(b'12', 1.1) is None
        assert chipset.transport.read.mock_calls == [call(100), call(1100)]
        assert chipset.transport.write.mock_calls == [call(CMD('94 3132'))]

        chipset.transport.read.side_effect = [ACK(), RSP('95 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.tg_set_meta_data(b'12', 1.1)
        assert excinfo.value.errno == 1

    def test_tg_get_initiator_command(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('89 00 3132')]
        assert chipset.tg_get_initiator_command(1.1) == b'12'
        assert chipset.transport.read.mock_calls == [call(100), call(1100)]
        assert chipset.transport.write.mock_calls == [call(CMD('88'))]

        chipset.transport.read.reset_mock()
        chipset.transport.write.reset_mock()
        chipset.transport.read.side_effect = [ACK(), RSP('89 00 3132')]
        assert chipset.tg_get_initiator_command(0) is None
        assert chipset.transport.read.mock_calls == [call(100)]
        assert chipset.transport.write.mock_calls == [call(CMD('88'))]

        chipset.transport.read.side_effect = [ACK(), RSP('89 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.tg_get_initiator_command(1.1)
        assert excinfo.value.errno == 1

    def test_tg_response_to_initiator(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('91 00')]
        assert chipset.tg_response_to_initiator(b'12') is None
        assert chipset.transport.read.mock_calls == [call(100), call(1000)]
        assert chipset.transport.write.mock_calls == [call(CMD('90 3132'))]

        chipset.transport.read.side_effect = [ACK(), RSP('91 01')]
        with pytest.raises(nfc.clf.pn53x.Chipset.Error) as excinfo:
            chipset.tg_response_to_initiator(b'12')
        assert excinfo.value.errno == 1

    def test_tg_get_target_status(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('8B 01 00')]
        assert chipset.tg_get_target_status() == (1, 106, 106)
        chipset.transport.read.side_effect = [ACK(), RSP('8B 01 11')]
        assert chipset.tg_get_target_status() == (1, 212, 212)
        chipset.transport.read.side_effect = [ACK(), RSP('8B 01 22')]
        assert chipset.tg_get_target_status() == (1, 424, 424)
        chipset.transport.read.side_effect = [ACK(), RSP('8B 00 FF')]
        assert chipset.tg_get_target_status() == (0, 0, 0)
        assert chipset.transport.read.mock_calls == 4 * [call(100), call(100)]
        assert chipset.transport.write.mock_calls == 4 * [call(CMD('8A'))]


class TestDevice:
    def pn53x_test_sense_tta_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('26'),                    # ReadRegister
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
            CMD('06 6339'),                               # ReadRegister
        ]]

    def pn53x_test_sense_tta_target_is_tt1(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('93'),                    # ReadRegister
            ACK(), RSP('4B 01010c00b2565400'),            # InListPassiveTarget
            ACK(), RSP('41 001148b2565400'),              # InDataExchange
        ]
        return device.sense_tta(nfc.clf.RemoteTarget('106A'))

    def pn53x_test_sense_tta_target_is_tt2(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 0101004400070416c6c2d73881'),  # InListPassiveTarget
            ACK(), self.reg_rsp('FF'),                    # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.sel_res == HEX('00')
        assert target.sdd_res == HEX('0416C6C2D73881')
        return target

    def pn53x_test_sense_tta_target_is_dep(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 0101004440070416c6c2d73881'),  # InListPassiveTarget
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.sel_res == HEX('40')
        assert target.sdd_res == HEX('0416C6C2D73881')
        return target

    def test_sense_tta_unsupported_bitrate(self, device):
        with pytest.raises(ValueError) as excinfo:
            device.sense_tta(nfc.clf.RemoteTarget('100A'))
        assert str(excinfo.value) == "unsupported bitrate 100A"

    @pytest.mark.parametrize("uid, initiator_data", [
        ('01020304', '01020304'),
        ('01020304050607', '8801020304050607'),
        ('01020304050607080910', '880102038804050607080910'),
    ])
    def test_sense_tta_send_with_uid(self, device, uid, initiator_data):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('26'),                    # ReadRegister
        ]
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        assert device.sense_tta(target) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100' + initiator_data),              # InListPassiveTarget
            CMD('06 6339'),                               # ReadRegister
        ]]

    def test_sense_tta_rid_response_error(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('93'),                    # ReadRegister
            ACK(), RSP('4B 01010c00b2565400'),            # InListPassiveTarget
            ACK(), RSP('41 01'),                          # InDataExchange
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None

    def test_sense_tta_tt1_response_timeout(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('93'),                    # ReadRegister
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None

    def pn53x_test_sense_ttb_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
        ]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 010300'),                             # InListPassiveTarget
        ]]

    def pn53x_test_sense_ttf_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('03'),                    # ReadRegister
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
        ]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6304'),                               # ReadRegister
            CMD('4A 010100ffff0100'),                     # InListPassiveTarget
        ]]

    def pn53x_test_sense_dep_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('47 01'),                          # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        atr_req = HEX('D400 30313233343536373839 00000000')
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        assert device.sense_dep(target) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('46 01000230313233343536373839'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]

    def pn53x_test_listen_tta_not_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), IOError(errno.ETIMEDOUT, ""),          # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 1.0) is None

    def pn53x_test_listen_ttf_not_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), self.reg_rsp('00 00 00 00'),           # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX("01 3132333435363738 FFFFFFFFFFFFFFFF 12FC")
        assert device.listen_ttf(target, 0.001) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('08 633100633a806339 0063390063390063'
                '   3900633900633900 6339316339326339'
                '   3363393463393563 3936633937633938'
                '   6339ff6339ff6339 ff6339ff6339ff63'
                '   39ff6339ff6339ff 6339126339fc6339'
                '   00633101'),                           # WriteRegister
            CMD('08 633c0063013f630b 8063029263039a63'
                '   0480630520630961 63347f63357f6331'
                '   0d'),                                 # WriteRegister
            CMD('06 6337633863346335'),                   # ReadRegister
            CMD('08 633100'),                             # WriteRegister
        ]]

    def pn53x_test_listen_dep_not_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), IOError(errno.ETIMEDOUT, ""),          # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX("D501 d0d1d2d3d4d5d6d7d8d9 0000000800")
        assert device.listen_dep(target, 0.001) is None
