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


class TestChipset(object):
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


class TestDevice(object):
    def test_sense_tta_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('26'),                    # ReadRegister
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
            CMD('06 6339'),                               # ReadRegister
        ]]

    def test_sense_tta_target_is_tt1(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('93'),                    # ReadRegister
            ACK(), RSP('4B 01010c00b2565400'),            # InListPassiveTarget
            ACK(), RSP('41 001148b2565400'),              # InDataExchange
        ]
        return device.sense_tta(nfc.clf.RemoteTarget('106A'))

    def test_sense_tta_target_is_tt2(self, device):
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

    def test_sense_tta_target_is_dep(self, device):
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

    def test_sense_ttb_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
        ]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 010300'),                             # InListPassiveTarget
        ]]

    def test_sense_ttb_target_found(self, device, deselect_cmd):
        sensb_res = '50E8253EEC00000011008185'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 0101' + sensb_res + '0100'),   # InListPassiveTarget
            ACK(), RSP('43 00c2'),                        # InCommunicateThru
            ACK(), RSP('43 00' + sensb_res),              # InCommunicateThru
        ]
        target = device.sense_ttb(nfc.clf.RemoteTarget('106B'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.sensb_res == HEX(sensb_res)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 010300'),                             # InListPassiveTarget
            CMD(deselect_cmd),                            # InCommunicateThru
            CMD('42 050008'),                             # InCommunicateThru
        ]]

    def test_sense_ttb_deselect_timeout(self, device, deselect_cmd):
        sensb_res = '50E8253EEC00000011008185'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 0101' + sensb_res + '0100'),   # InListPassiveTarget
            ACK(), RSP('43 00c2'),                        # InCommunicateThru
            ACK(), RSP('43 01'),                          # InCommunicateThru
        ]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 010300'),                             # InListPassiveTarget
            CMD(deselect_cmd),                            # InCommunicateThru
            CMD('42 050008'),                             # InCommunicateThru
        ]]

    def test_sense_ttb_unsupported_bitrate(self, device):
        with pytest.raises(ValueError) as excinfo:
            device.sense_ttb(nfc.clf.RemoteTarget('100B'))
        assert str(excinfo.value) == "unsupported bitrate 100B"

    def test_sense_ttf_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('03'),                    # ReadRegister
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
        ]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6304'),                               # ReadRegister
            CMD('4A 010100ffff0100'),                     # InListPassiveTarget
        ]]

    def test_sense_ttf_target_found(self, device):
        sensf_res = '01 0102030405060708 F1F2F3F4F5F6F7F8 AABB'
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('03'),                    # ReadRegister
            ACK(), RSP('4B 0101 14' + sensf_res),         # InListPassiveTarget
        ]
        target = device.sense_ttf(nfc.clf.RemoteTarget('212F'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "212F"
        assert target.sensf_res == HEX(sensf_res)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6304'),                               # ReadRegister
            CMD('4A 010100ffff0100'),                     # InListPassiveTarget
        ]]

    def test_sense_ttf_more_rf_on_time(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00'),                    # ReadRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
        ]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6304'),                               # ReadRegister
            CMD('32 0101'),                               # RFConfiguration
            CMD('4A 010100ffff0100'),                     # InListPassiveTarget
        ]]

    def test_sense_ttf_unsupported_bitrate(self, device):
        with pytest.raises(ValueError) as excinfo:
            device.sense_ttf(nfc.clf.RemoteTarget('100F'))
        assert str(excinfo.value) == "unsupported bitrate 100F"

    def test_sense_dep_no_target_found(self, device):
        atr_req = HEX('D400 30313233343536373839 00000000')
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('47 01'),                          # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        assert device.sense_dep(target) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('46 01000230313233343536373839'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('47 02'),                          # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        assert device.sense_dep(target) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('46 01000230313233343536373839'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]

    def test_sense_dep_target_found(self, device):
        atr_req = HEX('D400 30313233343536373839 00000002'
                      '46666d 010113 020207ff 040132 070107')
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('47 0001 66f6e98d1c13dfe56de4'
                       '0000000702 46666d 010112'
                       '020207ff 040164 070103'),         # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        target = device.sense_dep(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '106A'
        assert target.atr_req == atr_req
        assert target.atr_res == HEX(
            'D501 66f6e98d1c13dfe56de4 0000000702'
            '46666d 010112 020207ff 040164 070103')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('46 010006 30313233343536373839 46666d'
                '010113 020207ff 040132 070107'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]
        return target

    def test_send_cmd_recv_rsp_passive_dep_target(self, device):
        # Also tests for very large timeout that results in index 16
        target = self.test_sense_tta_target_is_dep(device)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('43 00 343536'),                   # InCommunicateThru
        ]
        assert device.send_cmd_recv_rsp(target, b'123', 10.0) == b'456'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630200 630300 630540'),               # WriteRegister
            CMD('32 020a0b10'),                           # RFConfiguration
            CMD('42 313233'),                             # InCommunicateThru
        ]]

    def test_send_cmd_recv_rsp_tt2_crc_pass(self, device):
        target = self.test_sense_tta_target_is_tt2(device)
        four_page_data = '00010203 04050607 08090a0b 0c0d0e0f'
        read_rsp_frame = four_page_data + '77 f5'
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('43 00' + read_rsp_frame),         # InCommunicateThru
        ]
        rsp = device.send_cmd_recv_rsp(target, HEX('30 00'), 1.0)
        assert rsp == HEX(four_page_data)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630200 630300 630540'),               # WriteRegister
            CMD('32 020a0b0f'),                           # RFConfiguration
            CMD('42 3000'),                               # InCommunicateThru
        ]]

    def test_send_cmd_recv_rsp_tt2_crc_fail(self, device):
        target = self.test_sense_tta_target_is_tt2(device)
        four_page_data = '00010203 04050607 08090a0b 0c0d0e0f'
        read_rsp_frame = four_page_data + '00 00'
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('43 00' + read_rsp_frame),         # InCommunicateThru
        ]
        with pytest.raises(nfc.clf.TransmissionError) as excinfo:
            device.send_cmd_recv_rsp(target, HEX('30 00'), 1.0)
        assert str(excinfo.value) == "crc_a check error"
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630200 630300 630540'),               # WriteRegister
            CMD('32 020a0b0f'),                           # RFConfiguration
            CMD('42 3000'),                               # InCommunicateThru
        ]]

    def test_send_cmd_recv_rsp_with_dep_target(self, device):
        target = self.test_sense_dep_target_found(device)
        assert isinstance(target, nfc.clf.RemoteTarget)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('43 00343536'),                    # InCommunicateThru
        ]
        assert device.send_cmd_recv_rsp(target, b'123', 1.0) == b'456'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630201 630301 630540'),               # WriteRegister
            CMD('32 020a0b0f'),                           # RFConfiguration
            CMD('42 313233'),                             # InCommunicateThru
        ]]

    @pytest.mark.parametrize("err, exc", [
        ('01', nfc.clf.TimeoutError),
        ('02', nfc.clf.TransmissionError),
    ])
    def test_send_cmd_recv_rsp_chipset_error(self, device, err, exc):
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('43 %s' % err),                    # InCommunicateThru
        ]
        target = nfc.clf.RemoteTarget('106A')
        with pytest.raises(exc):
            device.send_cmd_recv_rsp(target, b'123', 1.0)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630200 630300 630540'),               # WriteRegister
            CMD('32 020a0b0f'),                           # RFConfiguration
            CMD('42 313233'),                             # InCommunicateThru
        ]]

    @pytest.mark.parametrize("err, exc", [
        (errno.ETIMEDOUT, nfc.clf.TimeoutError),
        (errno.EIO, IOError),
    ])
    def test_send_cmd_recv_rsp_transport_error(self, device, err, exc):
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), IOError(err, "test"),                  # InCommunicateThru
        ]
        target = nfc.clf.RemoteTarget('106A')
        with pytest.raises(exc):
            device.send_cmd_recv_rsp(target, b'123', 1.0)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630200 630300 630540'),               # WriteRegister
            CMD('32 020a0b0f'),                           # RFConfiguration
            CMD('42 313233'),                             # InCommunicateThru
        ] + ([ACK()] if err == errno.ETIMEDOUT else [])]

    @pytest.mark.parametrize("cmd_code", ['00', '01', '1A', '53', '72'])
    def test_send_cmd_recv_rsp_tt1_cmd(self, device, cmd_code):
        target = self.test_sense_tta_target_is_tt1(device)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('41 00343536'),                    # InDataExchange
        ]
        cmd = bytes(HEX(cmd_code) + b'123')
        assert device.send_cmd_recv_rsp(target, cmd, 1.0) == b'456'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630200 630300 630540'),               # WriteRegister
            CMD('32 020a0b0f'),                           # RFConfiguration
            CMD('40 01' + cmd_code + '313233'),           # InDataExchange
        ]]

    def test_pn53x_tt1_send_cmd_recv_rsp(self, device):
        device = super(type(device), device)
        with pytest.raises(NotImplementedError):
            device._tt1_send_cmd_recv_rsp(b'\x00', 1.0)

    def test_listen_tta_not_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), IOError(errno.ETIMEDOUT, ""),          # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 1.0) is None

    def test_listen_tta_as_tt2_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('8D 00 30 00'),                    # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("08010203")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.tt2_cmd == HEX('30 00')
        return target

    def test_listen_tta_as_tt4_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 00 E0 80'),                  # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 313233'),                 # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.tt4_cmd == b'123'
        device.chipset.transport.write.assert_any_call(CMD('90 0578807002'))
        return target

    def test_listen_tta_as_tt4_with_rats(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 00 E0 80'),                  # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 313233'),                 # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        target.rats_res = HEX("05 78 80 70 00")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.tt4_cmd == b'123'
        device.chipset.transport.write.assert_any_call(CMD('90 0578807000'))
        return target

    def test_listen_tta_as_tt4_rcvd_deselect(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 00 E0 80'),                  # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 C03233'),                 # TgGetInitiatorCommand
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 12
        device.chipset.transport.write.assert_any_call(CMD('90 0578807002'))

    def test_listen_tta_as_tt4_initiator_timeout(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 00 E0 80'),                  # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 01'),                        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 8
        device.chipset.transport.write.assert_any_call(CMD('90 0578807002'))

    def test_listen_tta_as_tt4_initiator_cmd_empty(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 00 E0 80'),                  # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00'),                        # TgGetInitiatorCommand
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 10
        device.chipset.transport.write.assert_any_call(CMD('90 0578807002'))

    def test_listen_tta_as_dep_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 00 F0 11 D4' + 15 * '00'),   # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 313233'),                 # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.atr_req == HEX('d4000000000000000000000000000000')
        return target

    def test_listen_tta_as_dep_wrong_start_byte(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 00 E0 80'),                  # TgInitAsTarget
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 6

    def test_listen_tta_while_loop_timeout(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 0) is None
        assert device.chipset.transport.read.call_count == 2

    def test_listen_tta_wrong_bitrate_received(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 11 00'),                     # TgInitAsTarget
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 6

    def test_listen_tta_input_output_error(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), IOError(errno.EIO, ""),              # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        with pytest.raises(IOError):
            device.listen_tta(target, 1.0)
        assert device.chipset.transport.read.call_count == 4

    def test_listen_tta_unsupported_bitrate(self, device):
        target = nfc.clf.LocalTarget('106B')
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_tta(target, 1.0)
        assert str(excinfo.value) == "unsupported bitrate/type: '106B'"

    def test_listen_tta_type_1_tag_not_supported(self, device):
        target = nfc.clf.LocalTarget('106A')
        target.rid_res = HEX('00')
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_tta(target, 1.0)
        assert str(excinfo.value) == \
            "listening for type 1 tag activation is not supported"

    @pytest.mark.parametrize("target, errstr", [
        (nfc.clf.LocalTarget('106A'),
         "sens_res is required"),
        (nfc.clf.LocalTarget('106A', sens_res=HEX('')),
         "sdd_res is required"),
        (nfc.clf.LocalTarget('106A', sens_res=HEX(''), sdd_res=HEX('')),
         "sel_res is required"),
        (nfc.clf.LocalTarget('106A', sens_res=HEX(''),
                             sdd_res=HEX(''), sel_res=HEX('')),
         "sens_res must be 2 byte"),
        (nfc.clf.LocalTarget('106A', sens_res=HEX('0102'),
                             sdd_res=HEX(''), sel_res=HEX('')),
         "sdd_res must be 4 byte"),
        (nfc.clf.LocalTarget('106A', sens_res=HEX('0102'),
                             sdd_res=HEX('01020304'), sel_res=HEX('')),
         "sel_res must be 1 byte"),
        (nfc.clf.LocalTarget('106A', sens_res=HEX('0102'),
                             sdd_res=HEX('01020304'), sel_res=HEX('01')),
         "sdd_res[0] must be 08h"),
    ])
    def test_listen_tta_target_value_error(self, device, target, errstr):
        with pytest.raises(ValueError) as excinfo:
            device.listen_tta(target, 1.0)
        assert str(excinfo.value) == errstr

    def test_listen_ttb_not_supported(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_ttb(nfc.clf.LocalTarget('106B'), 1.0)
        assert "does not support listen as Type B Target" in str(excinfo.value)

    def test_listen_ttf_not_activated(self, device):
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

    def test_listen_ttf_get_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), self.reg_rsp('00 00 30 00'),           # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), self.reg_rsp('0a'),                    # ReadRegister
            ACK(), self.reg_rsp('0a003132333435363738'),  # ReadRegister
        ]
        sensf_res = HEX("01 3132333435363738 FFFFFFFFFFFFFFFF 12FC")
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = sensf_res
        target = device.listen_ttf(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "212F"
        assert target.sensf_res == sensf_res
        assert target.tt3_cmd == HEX('003132333435363738')
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
            CMD('08 633430'),                             # WriteRegister
            CMD('06 633a'),                               # ReadRegister
            CMD('06 6339 6339 6339 6339 6339'
                '   6339 6339 6339 6339 6339'),           # ReadRegister
        ]]
        return target

    @pytest.mark.parametrize("tt3_cmd", [
        '00003132333435363738', '0a000000000000000000',
    ])
    def test_listen_ttf_frame_length_error(self, device, tt3_cmd):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), self.reg_rsp('00 00 30 00'),           # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), self.reg_rsp('0a'),                    # ReadRegister
            ACK(), self.reg_rsp(tt3_cmd),                 # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        sensf_res = HEX("01 3132333435363738 FFFFFFFFFFFFFFFF 12FC")
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = sensf_res
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
            CMD('08 633430'),                             # WriteRegister
            CMD('06 633a'),                               # ReadRegister
            CMD('06 6339 6339 6339 6339 6339'
                '   6339 6339 6339 6339 6339'),           # ReadRegister
            CMD('08 63310d'),                             # WriteRegister
            CMD('08 633100'),                             # WriteRegister
        ]]

    def test_listen_ttf_unsupported_bitrate(self, device):
        target = nfc.clf.LocalTarget('106A')
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_ttf(target, 1.0)
        assert str(excinfo.value) == "unsupported bitrate/type: '106A'"

    @pytest.mark.parametrize("target, errstr", [
        (nfc.clf.LocalTarget('212F'),
         "sensf_res is required"),
        (nfc.clf.LocalTarget('424F', sensf_res=b''),
         "sensf_res must be 19 byte"),
    ])
    def test_listen_ttf_target_value_error(self, device, target, errstr):
        with pytest.raises(ValueError) as excinfo:
            device.listen_ttf(target, 1.0)
        assert str(excinfo.value) == errstr

    def test_listen_dep_not_activated(self, device):
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
        assert device.chipset.transport.read.call_count == 4

    def test_listen_dep_passive_106A(self, device):
        sensf_res = '01 01fe010203040506 0000000000000000 0000'
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 04 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "106A"
        assert target.sensf_res is None
        assert target.sens_res == HEX("0101")
        assert target.sel_res == HEX("40")
        assert target.sdd_res == HEX("08010203")
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req is None
        assert target.psl_res is None
        assert target.dep_req == HEX(dep_req)
        assert device.chipset.transport.read.call_count == 10
        return target

    def test_listen_dep_passive_424F(self, device):
        sensf_res = '01 01fe010203040506 0000000000000000 0000'
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 26 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "424F"
        assert target.sensf_res == HEX(sensf_res)
        assert target.sens_res is None
        assert target.sel_res is None
        assert target.sdd_res is None
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req is None
        assert target.psl_res is None
        assert target.dep_req == HEX(dep_req)
        assert device.chipset.transport.read.call_count == 10
        return target

    def test_listen_dep_passive_106A_psl_to_424F(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        psl_res = 'D505 00'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 04 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('00'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('00'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "424F"
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req == HEX(psl_req)
        assert target.psl_res == HEX(psl_res)
        assert target.dep_req == HEX(dep_req)
        assert target.sensf_res is None
        assert target.sens_res == HEX("0101")
        assert target.sel_res == HEX("40")
        assert target.sdd_res == HEX("08010203")
        assert device.chipset.transport.read.call_count == 22
        return target

    def test_listen_dep_active_106A_psl_to_424F(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        psl_res = 'D505 00'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "424F"
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req == HEX(psl_req)
        assert target.psl_res == HEX(psl_res)
        assert target.dep_req == HEX(dep_req)
        assert target.sensf_res is None
        assert target.sens_res is None
        assert target.sel_res is None
        assert target.sdd_res is None
        assert device.chipset.transport.read.call_count == 22
        return target

    @pytest.mark.parametrize("dep_req", ['D405000000ff', '0000000000'])
    def test_listen_dep_command_data_error(self, device, dep_req):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 04 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe010203040506 0000000000000000 0000')
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 8

    def test_listen_dep_chipset_timeout_after_psl(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('89 01'),                        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 20

    def test_listen_dep_ioerror_timeout_after_psl(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 20

    def test_listen_dep_ioerror_exception_after_psl(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), IOError(errno.EIO, ""),              # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        with pytest.raises(IOError):
            device.listen_dep(target, 1.0)
        assert device.chipset.transport.read.call_count == 20

    def test_listen_dep_chipset_timeout_after_atr(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 01'),                        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 8

    def test_listen_dep_ioerror_timeout_after_atr(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 8

    def test_listen_dep_ioerror_exception_after_atr(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), IOError(errno.EIO, ""),              # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        with pytest.raises(IOError):
            device.listen_dep(target, 1.0)
        assert device.chipset.transport.read.call_count == 8

    def test_listen_dep_not_atr_and_then_ioerror(self, device):
        atr_req = 'D4FF 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgInitAsTarget
            ACK(), IOError(errno.EIO, ""),              # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        with pytest.raises(IOError):
            device.listen_dep(target, 1.0)
        assert device.chipset.transport.read.call_count == 8

    @pytest.mark.parametrize("psl_req", [
        'D404 00 12 03 FF', 'D404 01 12 03'
    ])
    def test_listen_dep_active_106A_psl_req_error(self, device, psl_req):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 8

    def test_send_rsp_recv_cmd_with_dep_target(self, device):
        target = self.test_listen_dep_passive_106A(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        dep_cmd_frame = '06 D406 00 3334'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89 00' + dep_cmd_frame),        # TgGetInitiatorCommand
        ]
        cmd = device.send_rsp_recv_cmd(target, b'12', 1.0)
        assert cmd == HEX(dep_cmd_frame)
        assert device.chipset.transport.read.call_count == 4

    def test_send_rsp_recv_cmd_receive_only(self, device):
        target = self.test_listen_dep_passive_106A(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        dep_cmd_frame = '06 D406 00 3334'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('89 00' + dep_cmd_frame),        # TgGetInitiatorCommand
        ]
        cmd = device.send_rsp_recv_cmd(target, b'', 1.0)
        assert cmd == HEX(dep_cmd_frame)
        assert device.chipset.transport.read.call_count == 2

    def test_send_rsp_recv_cmd_timeout_error(self, device):
        target = self.test_listen_dep_passive_106A(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgGetInitiatorCommand
        ]
        with pytest.raises(nfc.clf.TimeoutError):
            device.send_rsp_recv_cmd(target, b'12', 1.0)
        assert device.chipset.transport.read.call_count == 4

    def test_send_rsp_recv_cmd_input_out_error(self, device):
        target = self.test_listen_dep_passive_106A(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), IOError(errno.EIO, ""),              # TgGetInitiatorCommand
        ]
        with pytest.raises(IOError):
            device.send_rsp_recv_cmd(target, b'12', 1.0)
        assert device.chipset.transport.read.call_count == 4

    @pytest.mark.parametrize("err, exc", [
        ('01', nfc.clf.TransmissionError),
        ('0A', nfc.clf.BrokenLinkError),
        ('29', nfc.clf.BrokenLinkError),
        ('31', nfc.clf.BrokenLinkError),
    ])
    def test_send_rsp_recv_cmd_broken_link_error(self, device, err, exc):
        target = self.test_listen_dep_passive_106A(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), RSP('89' + err),                     # TgGetInitiatorCommand
        ]
        with pytest.raises(exc):
            device.send_rsp_recv_cmd(target, b'12', 1.0)
        assert device.chipset.transport.read.call_count == 4

    def test_send_rsp_recv_cmd_with_tt3_target(self, device):
        target = self.test_listen_ttf_get_activated(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.read.reset_mock()
        dep_cmd_frame = '06 D406 00 3334'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('20 00'),               # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('06'),                  # ReadRegister
            ACK(), self.reg_rsp(dep_cmd_frame),         # ReadRegister
        ]
        cmd = device.send_rsp_recv_cmd(target, HEX('3132'), 1.0)
        assert cmd == HEX(dep_cmd_frame)
        assert device.chipset.transport.read.call_count == 10

    def test_send_rsp_recv_cmd_tt3_not_send_data(self, device):
        target = self.test_listen_ttf_get_activated(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.read.reset_mock()
        dep_cmd_frame = '06 D406 00 3334'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('20 00'),               # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('06'),                  # ReadRegister
            ACK(), self.reg_rsp(dep_cmd_frame),         # ReadRegister
        ]
        cmd = device.send_rsp_recv_cmd(target, None, 1.0)
        assert cmd == HEX(dep_cmd_frame)
        assert device.chipset.transport.read.call_count == 10

    def test_send_rsp_recv_cmd_tt3_timeout_error(self, device):
        target = self.test_listen_ttf_get_activated(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('00 00'),               # ReadRegister
        ]
        with pytest.raises(nfc.clf.TimeoutError):
            device.send_rsp_recv_cmd(target, None, 0.001)
        assert device.chipset.transport.read.call_count == 4

    def test_send_rsp_recv_cmd_tt3_broken_link(self, device):
        target = self.test_listen_ttf_get_activated(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('00 01'),               # ReadRegister
        ]
        with pytest.raises(nfc.clf.BrokenLinkError):
            device.send_rsp_recv_cmd(target, None, 0.001)
        assert device.chipset.transport.read.call_count == 4

    def test_send_rsp_recv_cmd_tt3_frame_error(self, device):
        target = self.test_listen_ttf_get_activated(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.read.reset_mock()
        dep_cmd_frame = '03 D406 00 3334'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('20 00'),               # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), self.reg_rsp('06'),                  # ReadRegister
            ACK(), self.reg_rsp(dep_cmd_frame),         # ReadRegister
        ]
        with pytest.raises(nfc.clf.TransmissionError):
            device.send_rsp_recv_cmd(target, None, 0.001)
        assert device.chipset.transport.read.call_count == 10

    def test_send_rsp_recv_cmd_tt3_timeout_zero(self, device):
        target = self.test_listen_ttf_get_activated(device)
        assert isinstance(target, nfc.clf.LocalTarget)
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        assert device.send_rsp_recv_cmd(target, None, 0) is None
        assert device.chipset.transport.read.call_count == 2

    def test_print_ciu_register_page(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp(16 * '00'),             # ReadRegister
            ACK(), self.reg_rsp(16 * '00'),             # ReadRegister
            ACK(), self.reg_rsp(16 * '00'),             # ReadRegister
            ACK(), self.reg_rsp(16 * '00'),             # ReadRegister
        ]
        assert len(device._print_ciu_register_page(0, 1, 2, 3)) == 59
        assert device.chipset.transport.read.call_count == 8

    def test_pn53x_init_as_target_not_implemented(self, device):
        device = super(type(device), device)
        with pytest.raises(NotImplementedError):
            device._init_as_target(1, 2, 3, 4)

    def test_pn53x_init_as_driver_raises_ioerror(self, transport):
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn53x.init(transport)
        assert excinfo.value.errno == errno.ENODEV
