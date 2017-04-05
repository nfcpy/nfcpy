# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.rcs380

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call

import logging
logging.basicConfig(level=logging.DEBUG-1)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.rcs380").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


def FRAME(hexstr):
    data = HEX(hexstr)
    LEN = bytearray([len(data) % 256, len(data) // 256])
    LCS = bytearray([256 - sum(LEN) & 255])
    DCS = bytearray([256 - sum(data) & 255])
    return HEX('0000ffffff') + LEN + LCS + data + DCS + HEX('00')


def CMD(hexstr):
    return FRAME('D6' + hexstr)


def RSP(hexstr):
    return FRAME('D7' + hexstr)


def ACK():
    return HEX('0000FF00FF00')


def ERR():
    return HEX('0000FF01FF7F8100')


@pytest.fixture()  # noqa: F811
def transport(mocker):
    mocker.patch('nfc.clf.transport.USB.__init__').return_value = None
    transport = nfc.clf.transport.USB(1, 1)
    mocker.patch.object(transport, 'write', autospec=True)
    mocker.patch.object(transport, 'read', autospec=True)
    transport._manufacturer_name = "Manufacturer Name"
    transport._product_name = "Product Name"
    transport.context = None
    transport.usb_dev = None
    return transport


@pytest.fixture()
def chipset(transport):
    transport.read.side_effect = [
        HEX('01020304'), IOError,
        ACK(), RSP('2b 00'),
        ACK(), RSP('21 1101'),
        ACK(), RSP('23 0001'),
        ACK(), RSP('07 00'),
    ]
    chipset = nfc.clf.rcs380.Chipset(transport, logger=nfc.clf.rcs380.log)
    assert transport.read.mock_calls == [
        call(timeout=10), call(timeout=10),
        call(), call(), call(), call(), call(), call(), call(), call(),
    ]
    assert transport.write.mock_calls == [call(_) for _ in [
        ACK(), CMD('2a 01'), CMD('20'), CMD('22'), CMD('06 00'),
    ]]
    transport.write.reset_mock()
    transport.read.reset_mock()
    return chipset


@pytest.fixture()
def device(chipset):
    chipset.transport.read.side_effect = [ACK(), RSP('21 1101')]
    device = nfc.clf.rcs380.Device(chipset, logger=nfc.clf.rcs380.log)
    assert chipset.transport.write.mock_calls == [call(CMD('20'))]
    assert device.chipset_name == "NFC Port-100 v1.11"
    device._path = 'usb:001:001'
    chipset.transport.write.reset_mock()
    chipset.transport.read.reset_mock()
    return device


class TestFrame(object):
    def test_encode(self):
        assert bytes(nfc.clf.rcs380.Frame(b'12')) == FRAME('3132')

    @pytest.mark.parametrize("frame, frame_type, frame_data", [
        ('0000ffffff0200fe31329d00', 'data', b'12'),
        ('0000ff00ff00', 'ack', None),
        ('0000ffffff', 'err', None),
        ('0000ff', None, None),
    ])
    def test_decode(self, frame, frame_type, frame_data):
        frame = nfc.clf.rcs380.Frame(HEX(frame))
        assert frame.type == frame_type
        assert frame.data == frame_data


class TestCommunicationError(object):
    @pytest.mark.parametrize("status, errno, errstr", [
        ('00000000', 0x00000000, "CommunicationError NO_ERROR"),
        ('01000000', 0x00000001, "CommunicationError PROTOCOL_ERROR"),
        ('02000000', 0x00000002, "CommunicationError PARITY_ERROR"),
        ('04000000', 0x00000004, "CommunicationError CRC_ERROR"),
        ('08000000', 0x00000008, "CommunicationError COLLISION_ERROR"),
        ('10000000', 0x00000010, "CommunicationError OVERFLOW_ERROR"),
        ('40000000', 0x00000040, "CommunicationError TEMPERATURE_ERROR"),
        ('80000000', 0x00000080, "CommunicationError RECEIVE_TIMEOUT_ERROR"),
        ('00010000', 0x00000100, "CommunicationError CRYPTO1_ERROR"),
        ('00020000', 0x00000200, "CommunicationError RFCA_ERROR"),
        ('00040000', 0x00000400, "CommunicationError RF_OFF_ERROR"),
        ('00080000', 0x00000800, "CommunicationError TRANSMIT_TIMEOUT_ERROR"),
        ('00000080', 0x80000000, "CommunicationError RECEIVE_LENGTH_ERROR"),
        ('ffffffff', 0xffffffff, "CommunicationError 0xFFFFFFFF"),
    ])
    def test_init(self, status, errno, errstr):
        error = nfc.clf.rcs380.CommunicationError(HEX(status))
        assert error.errno == errno
        assert str(error) == errstr

    @pytest.mark.parametrize("status, errname", [
        ('00000000', "NO_ERROR"),
        ('01000000', "PROTOCOL_ERROR"),
        ('02000000', "PARITY_ERROR"),
        ('04000000', "CRC_ERROR"),
        ('08000000', "COLLISION_ERROR"),
        ('10000000', "OVERFLOW_ERROR"),
        ('40000000', "TEMPERATURE_ERROR"),
        ('80000000', "RECEIVE_TIMEOUT_ERROR"),
        ('00010000', "CRYPTO1_ERROR"),
        ('00020000', "RFCA_ERROR"),
        ('00040000', "RF_OFF_ERROR"),
        ('00080000', "TRANSMIT_TIMEOUT_ERROR"),
        ('00000080', "RECEIVE_LENGTH_ERROR"),
        ('ffffffff', "PROTOCOL_ERROR"),
        ('ffffffff', "PARITY_ERROR"),
        ('ffffffff', "CRC_ERROR"),
        ('ffffffff', "COLLISION_ERROR"),
        ('ffffffff', "OVERFLOW_ERROR"),
        ('ffffffff', "TEMPERATURE_ERROR"),
        ('ffffffff', "RECEIVE_TIMEOUT_ERROR"),
        ('ffffffff', "CRYPTO1_ERROR"),
        ('ffffffff', "RFCA_ERROR"),
        ('ffffffff', "RF_OFF_ERROR"),
        ('ffffffff', "TRANSMIT_TIMEOUT_ERROR"),
        ('ffffffff', "RECEIVE_LENGTH_ERROR"),
    ])
    def test_compare(self, status, errname):
        error = nfc.clf.rcs380.CommunicationError(HEX(status))
        assert error == errname
        if error.errno:
            assert error != "NO_ERROR"


class TestStatusError(object):
    @pytest.mark.parametrize("errno, errstr", [
        (0, "SUCCESS"),
        (1, "PARAMETER_ERROR"),
        (2, "PB_ERROR"),
        (3, "RFCA_ERROR"),
        (4, "TEMPERATURE_ERROR"),
        (5, "PWD_ERROR"),
        (6, "RECEIVE_ERROR"),
        (7, "COMMANDTYPE_ERROR"),
        (255, "UNKNOWN STATUS ERROR 0xFF"),
    ])
    def test_init(self, errno, errstr):
        error = nfc.clf.rcs380.StatusError(errno)
        assert error.errno == errno
        assert str(error) == errstr


class TestChipset(object):
    def test_close(self, chipset):
        transport = chipset.transport
        transport.read.side_effect = [ACK(), RSP('0700')]
        chipset.close()
        assert chipset.transport is None
        assert transport.read.mock_calls == [call(), call()]
        assert transport.write.mock_calls == [call(CMD('0600')), call(ACK())]

    def test_send_command_transport_is_none(self, chipset):
        chipset.transport = None
        assert chipset.send_command(0x00, HEX('0000')) is None

    def test_send_command_missing_ack_frame(self, chipset):
        chipset.transport.read.side_effect = [RSP('07 00')]
        assert chipset.send_command(0x00, HEX('0000')) is None

    def test_send_command_missing_data_frame(self, chipset):
        chipset.transport.read.side_effect = [ACK(), ACK()]
        assert chipset.send_command(0x00, HEX('0000')) is None

    @pytest.mark.parametrize("response", ['D601', 'D700'])
    def test_send_command_invalid_response_code(self, chipset, response):
        chipset.transport.read.side_effect = [ACK(), FRAME(response)]
        assert chipset.send_command(0x00, HEX('0000')) is None

    @pytest.mark.parametrize("brty_send, brty_recv, command", [
        ('212F', None, '0001010f01'),
        ("424F", None, '0001020f02'),
        ("106A", None, '0002030f03'),
        ("212A", None, '0004040f04'),
        ("424A", None, '0005050f05'),
        ("106B", None, '0003070f07'),
        ("212B", None, '0003080f08'),
        ("424B", None, '0003090f09'),
        ('212F', '424F', '0001010f02'),
        ("424F", '212F', '0001020f01'),
    ])
    def test_in_set_rf(self, chipset, brty_send, brty_recv, command):
        chipset.transport.read.side_effect = [ACK(), RSP('0100')]
        assert chipset.in_set_rf(brty_send, brty_recv) is None
        assert chipset.transport.write.mock_calls == [call(CMD(command))]
        chipset.transport.read.side_effect = [ACK(), RSP('0101')]
        with pytest.raises(nfc.clf.rcs380.StatusError) as excinfo:
            chipset.in_set_rf(brty_send, brty_recv)
        assert excinfo.value.errno == 1

    @pytest.mark.parametrize("data, kwargs, command", [
        (None, {}, ''),
        (None, {"initial_guard_time": 255}, '0200ff'),
        (None, {"add_crc": 255}, '0201ff'),
        (None, {"check_crc": 255}, '0202ff'),
        (None, {"multi_card": 255}, '0203ff'),
        (None, {"add_parity": 255}, '0204ff'),
        (None, {"check_parity": 255}, '0205ff'),
        (None, {"bitwise_anticoll": 255}, '0206ff'),
        (None, {"last_byte_bit_count": 255}, '0207ff'),
        (None, {"mifare_crypto": 255}, '0208ff'),
        (None, {"add_sof": 255}, '0209ff'),
        (None, {"check_sof": 255}, '020aff'),
        (None, {"add_eof": 255}, '020bff'),
        (None, {"check_eof": 255}, '020cff'),
        (None, {"deaf_time": 255}, '020eff'),
        (None, {"continuous_receive_mode": 255}, '020fff'),
        (None, {"min_len_for_crm": 255}, '0210ff'),
        (None, {"type_1_tag_rrdd": 255}, '0211ff'),
        (None, {"rfca": 255}, '0212ff'),
        (None, {"guard_time": 255}, '0213ff'),
        (None, {"add_crc": 254, "check_crc": 255}, '0201fe02ff'),
        (b'1', {"add_crc": 254, "check_crc": 255}, '023101fe02ff'),
    ])
    def test_in_set_protocol(self, chipset, data, kwargs, command):
        chipset.transport.read.side_effect = [ACK(), RSP('0300')]
        assert chipset.in_set_protocol(data, **kwargs) is None
        if command:
            chipset.transport.write.assert_called_with(CMD(command))
            chipset.transport.read.side_effect = [ACK(), RSP('0301')]
            with pytest.raises(nfc.clf.rcs380.StatusError) as excinfo:
                chipset.in_set_protocol(data, **kwargs)
            assert excinfo.value.errno == 1

    @pytest.mark.parametrize("data, timeout, command", [
        (b'12', 0, '0400003132'),
        (b'12', 1, '0414003132'),
        (b'12', 2, '041e003132'),
        (b'12', 0x10000, '04ffff3132'),
    ])
    def test_in_comm_rf(self, chipset, data, timeout, command):
        chipset.transport.read.side_effect = [ACK(), RSP('0500000000083334')]
        assert chipset.in_comm_rf(data, timeout) == b'34'
        chipset.transport.write.assert_called_with(CMD(command))
        chipset.transport.read.side_effect = [ACK(), RSP('0501000000')]
        with pytest.raises(nfc.clf.rcs380.CommunicationError) as excinfo:
            chipset.in_comm_rf(data, timeout)
        assert excinfo.value == "PROTOCOL_ERROR"

    def test_switch_rf(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('0700')]
        assert chipset.switch_rf('off') is None
        chipset.transport.write.assert_called_with(CMD('0600'))
        chipset.transport.read.side_effect = [ACK(), RSP('0700')]
        assert chipset.switch_rf('on') is None
        chipset.transport.write.assert_called_with(CMD('0601'))
        chipset.transport.read.side_effect = [ACK(), RSP('0701')]
        with pytest.raises(nfc.clf.rcs380.StatusError) as excinfo:
            chipset.switch_rf('off')
        assert excinfo.value.errno == 1

    @pytest.mark.parametrize("comm_type, command", [
        ("106A", '40080b'),
        ("212F", '40080c'),
        ("424F", '40080d'),
        ("212A", '40080e'),
        ("424A", '40080f'),
    ])
    def test_tg_set_rf(self, chipset, comm_type, command):
        chipset.transport.read.side_effect = [ACK(), RSP('4100')]
        assert chipset.tg_set_rf(comm_type) is None
        assert chipset.transport.write.mock_calls == [call(CMD(command))]
        chipset.transport.read.side_effect = [ACK(), RSP('4101')]
        with pytest.raises(nfc.clf.rcs380.StatusError) as excinfo:
            chipset.tg_set_rf(comm_type)
        assert excinfo.value.errno == 1

    @pytest.mark.parametrize("data, kwargs, command", [
        (None, {}, None),
        (None, {"send_timeout_time_unit": 255}, '4200ff'),
        (None, {"rf_off_error": 255}, '4201ff'),
        (None, {"continuous_receive_mode": 255}, '4202ff'),
        (b'1', {"send_timeout_time_unit": 254, "rf_off_error": 255},
         '423101ff00fe'),
    ])
    def test_tg_set_protocol(self, chipset, data, kwargs, command):
        chipset.transport.read.side_effect = [ACK(), RSP('4300')]
        assert chipset.tg_set_protocol(data, **kwargs) is None
        if command:
            chipset.transport.write.assert_called_with(CMD(command))
            chipset.transport.read.side_effect = [ACK(), RSP('4301')]
            with pytest.raises(nfc.clf.rcs380.StatusError) as excinfo:
                chipset.tg_set_protocol(data, **kwargs)
            assert excinfo.value.errno == 1

    def test_tg_set_auto(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('4500')]
        assert chipset.tg_set_auto(HEX('0102')) is None
        assert chipset.transport.write.mock_calls == [call(CMD('440102'))]
        chipset.transport.read.side_effect = [ACK(), RSP('4501')]
        with pytest.raises(nfc.clf.rcs380.StatusError) as excinfo:
            chipset.tg_set_auto(HEX(''))
        assert excinfo.value.errno == 1

    @pytest.mark.parametrize("kwargs, command", [
        ({}, '48 0000 ffff 00'
         '000000000000 000000000000000000000000000000000000 00 00 0000'),
        ({"guard_time": 1}, '48 0100 ffff 00'
         '000000000000 000000000000000000000000000000000000 00 00 0000'),
        ({"send_timeout": 1}, '48 0000 0100 00'
         '000000000000 000000000000000000000000000000000000 00 00 0000'),
        ({"mdaa": True}, '48 0000 ffff 01'
         '000000000000 000000000000000000000000000000000000 00 00 0000'),
        ({"nfca_params": b'123456'}, '48 0000 ffff 00'
         '313233343536 000000000000000000000000000000000000 00 00 0000'),
        ({"nfcf_params": b'123456789012345678'}, '48 0000 ffff 00'
         '000000000000 313233343536373839303132333435363738 00 00 0000'),
        ({"mf_halted": True}, '48 0000 ffff 00'
         '000000000000 000000000000000000000000000000000000 01 00 0000'),
        ({"arae": True}, '48 0000 ffff 00'
         '000000000000 000000000000000000000000000000000000 00 01 0000'),
        ({"recv_timeout": 1}, '48 0000 ffff 00'
         '000000000000 000000000000000000000000000000000000 00 00 0100'),
        ({"recv_timeout": 258, "arae": True}, '48 0000 ffff 00'
         '000000000000 000000000000000000000000000000000000 00 01 0201'),
        ({"recv_timeout": 256, "transmit_data": b'12'}, '48 0000 ffff 00'
         '000000000000 000000000000000000000000000000000000 00 00 0001 3132'),
    ])
    def test_tg_comm_rf(self, chipset, kwargs, command):
        chipset.transport.read.side_effect = [ACK(), RSP('4900000000000000')]
        assert chipset.tg_comm_rf(**kwargs) == HEX('00000000000000')
        chipset.transport.write.assert_called_with(CMD(command))
        chipset.transport.read.side_effect = [ACK(), RSP('4900000001000000')]
        with pytest.raises(nfc.clf.rcs380.CommunicationError) as excinfo:
            chipset.tg_comm_rf(**kwargs)
        assert excinfo.value == "PROTOCOL_ERROR"

    def test_reset_device(self, mocker, chipset):  # noqa: F811
        mocker.patch('nfc.clf.rcs380.time.sleep')
        chipset.transport.read.side_effect = [ACK(), RSP('13')]
        assert chipset.reset_device(startup_delay=10) is None
        assert chipset.transport.write.mock_calls == [
            call(CMD('120a00')), call(ACK()),
        ]

    @pytest.mark.parametrize("request", [None, 0x60, 0x61, 0x80])
    def test_get_firmware_version(self, chipset, request):
        chipset.transport.read.side_effect = [ACK(), RSP('210123')]
        assert chipset.get_firmware_version(request) == HEX('0123')
        assert chipset.transport.write.mock_calls == [
            call(CMD('20' + (('%02x' % request) if request else '')))
        ]

    def test_get_command_type(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('290000000000000003')]
        assert chipset.get_command_type() == 3
        assert chipset.transport.write.mock_calls == [call(CMD('28'))]

    def test_set_command_type(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('2b00')]
        assert chipset.set_command_type(3) is None
        assert chipset.transport.write.mock_calls == [call(CMD('2a03'))]
        chipset.transport.read.side_effect = [ACK(), RSP('2b01')]
        with pytest.raises(nfc.clf.rcs380.StatusError) as excinfo:
            chipset.set_command_type(5)
        assert excinfo.value.errno == 1


class TestDevice(object):
    def test_close(self, device):
        chipset = device.chipset
        transport = chipset.transport
        transport.read.side_effect = [ACK(), RSP('0700')]
        assert device.close() is None
        assert device.chipset is None
        assert chipset.transport is None
        assert transport.read.mock_calls == [call(), call()]
        assert transport.write.mock_calls == [call(CMD('0600')), call(ACK())]

    def test_mute(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('0700')
        ]
        assert device.mute() is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('0600')
        ]]

    def test_get_max_send_data_size(self, device):
        assert device.get_max_send_data_size(None) == 290

    def test_get_max_recv_data_size(self, device):
        assert device.get_max_recv_data_size(None) == 290

    #
    # SENSE
    #

    def test_sense_tta_with_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 80000000'),
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
        ]]

    def test_sense_tta_with_tt1_target_found(self, device):
        sens_res = '000C'
        rid_res = '1148b2565400'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08' + sens_res),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08' + rid_res),
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX(sens_res)
        assert target.rid_res == HEX(rid_res)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 0102020207081102'),
            CMD('04 360178000000000000'),
        ]]

    def test_sense_tta_with_proprietary_target(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 0000'),
            ACK(), RSP('03 00'),
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('0000')
        assert target.rid_res is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 0102020207081102'),
        ]]

    def test_sense_tta_find_tt1_but_receive_error(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 000C'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 40000000'),
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 0102020207081102'),
            CMD('04 360178000000000000'),
        ]]

    def test_sense_tta_find_tt2_target_uid_4(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 01020304'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 00'),
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304')
        assert target.sel_res == HEX('00')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 04010708'),
            CMD('02 01000200'),
            CMD('04 36019320'),
            CMD('02 01010201'),
            CMD('04 3601937001020304'),
        ]]

    def test_sense_tta_find_tt2_target_uid_7(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 88010203'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04050607'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 00'),
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304050607')
        assert target.sel_res == HEX('00')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 04010708'),
            CMD('02 01000200'),
            CMD('04 36019320'),
            CMD('02 01010201'),
            CMD('04 3601937088010203'),
            CMD('02 01000200'),
            CMD('04 36019520'),
            CMD('02 01010201'),
            CMD('04 3601957004050607'),
        ]]

    def test_sense_tta_find_tt2_target_uid_10(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 88010203'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 88040506'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 07080910'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 00'),
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304050607080910')
        assert target.sel_res == HEX('00')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 04010708'),
            CMD('02 01000200'),
            CMD('04 36019320'),
            CMD('02 01010201'),
            CMD('04 3601937088010203'),
            CMD('02 01000200'),
            CMD('04 36019520'),
            CMD('02 01010201'),
            CMD('04 3601957088040506'),
            CMD('02 01000200'),
            CMD('04 36019720'),
            CMD('02 01010201'),
            CMD('04 3601977007080910'),
        ]]

    def test_sense_tta_find_tt2_excessive_uid(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 88010203'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 88040506'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 07080910'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None

    def test_sense_tta_tt2_request_uid_4(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 00'),
        ]
        uid = '01020304'
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 04010708'),
            CMD('02 01010201'),
            CMD('04 360193700102030404'),
        ]]

    def test_sense_tta_tt2_request_uid_7(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('05 00000000 08 00'),
        ]
        uid = '01020304050607'
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 04010708'),
            CMD('02 01010201'),
            CMD('04 360193708801020388'),
            CMD('04 360195700405060700'),
        ]]

    def test_sense_tta_tt2_request_uid_10(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('05 00000000 08 04'),
            ACK(), RSP('05 00000000 08 00'),
        ]
        uid = '01020304050607080910'
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 04010708'),
            CMD('02 01010201'),
            CMD('04 360193708801020388'),
            CMD('04 36019570880405068f'),
            CMD('04 360197700708091016'),
        ]]

    def test_sense_tta_with_receive_errors(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 40000000'),
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
        ]]

    def test_sense_tta_find_tt2_but_receive_error(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 4400'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 40000000'),
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 01000200050100060707'),
            CMD('04 360126'),
            CMD('02 04010708'),
            CMD('02 01000200'),
            CMD('04 36019320'),
        ]]

    @pytest.mark.parametrize("sens_res", ['00'])
    def test_sense_tta_with_response_errors(self, device, sens_res):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08' + sens_res),
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.read.call_count == 8

    def test_sense_tta_with_invalid_target(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_tta(nfc.clf.RemoteTarget('106B'))
        assert str(excinfo.value) == "unsupported bitrate 106B"

    def test_sense_ttb_with_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 80000000'),
        ]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 03070f07'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0b0109010c010a010014'),
            CMD('04 3601050010'),
        ]]

    def test_sense_ttb_with_tt4_target_found(self, device):
        sensb_res = '50E8253EEC00000011008185'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 ' + sensb_res),
        ]
        target = device.sense_ttb(nfc.clf.RemoteTarget('106B'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.sensb_res == HEX(sensb_res)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 03070f07'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0b0109010c010a010014'),
            CMD('04 3601050010'),
        ]]

    def test_sense_ttb_with_receive_errors(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 40000000'),
        ]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 03070f07'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0b0109010c010a010014'),
            CMD('04 3601050010'),
        ]]

    @pytest.mark.parametrize('sensb_res', [
        '51E8253EEC00000011008185', '50E8253EEC000000110081',
    ])
    def test_sense_ttb_with_response_errors(self, device, sensb_res):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 00000000 08 ' + sensb_res),
        ]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 03070f07'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0b0109010c010a010014'),
            CMD('04 3601050010'),
        ]]

    def test_sense_ttb_with_invalid_target(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_ttb(nfc.clf.RemoteTarget('212F'))
        assert str(excinfo.value) == "unsupported bitrate 212F"

    def test_sense_ttf_with_no_target_found(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 80000000'),
        ]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 01010f01'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0018'),
            CMD('04 6e000600ffff0100'),
        ]]

    def test_sense_ttf_with_tt3_target_found(self, device):
        sensf_res = '14 01 01010701260cca02 0f0d23042f7783ff 12fc'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 0000000008' + sensf_res),
        ]
        target = device.sense_ttf(nfc.clf.RemoteTarget('212F'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '212F'
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 01010f01'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0018'),
            CMD('04 6e00 0600ffff0100'),
        ]]
        return target

    @pytest.mark.parametrize("tg, sensf_req, sensf_res", [
        (nfc.clf.RemoteTarget('212F', sensf_req=None),
         '0600ffff0100', '140101010701260cca020f0d23042f7783ff12fc'),
        (nfc.clf.RemoteTarget('212F', sensf_req=HEX('00ffff0100')),
         '0600ffff0100', '140101010701260cca020f0d23042f7783ff12fc'),
        (nfc.clf.RemoteTarget('212F', sensf_req=HEX('00ffff0000')),
         '0600ffff0000', '120101010701260cca020f0d23042f7783ff'),
    ])
    def test_sense_ttf_with_sensf_req(self, device, tg, sensf_req, sensf_res):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 0000000008' + sensf_res),
        ]
        target = device.sense_ttf(tg)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == tg.brty
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 01010f01'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0018'),
            CMD('04 6e00' + sensf_req),
        ]]

    @pytest.mark.parametrize("brty, rf_settings", [
        ('212F', '01010f01'),
        ('424F', '01020f02'),
    ])
    def test_sense_ttf_with_bitrate_type(self, device, brty, rf_settings):
        sensf_res = '14 01 01010701260cca020f0d23042f7783ff12fc'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 0000000008' + sensf_res),
        ]
        target = device.sense_ttf(nfc.clf.RemoteTarget(brty))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == brty
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00' + rf_settings),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0018'),
            CMD('04 6e00 0600ffff0100'),
        ]]

    def test_sense_ttf_with_receive_errors(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 40000000'),
        ]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 01010f01'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0018'),
            CMD('04 6e000600ffff0100'),
        ]]

    @pytest.mark.parametrize("sensf_res", [
        '110101010701260cca020f0d23042f7783',
        '130101010701260cca020f0d23042f7783ff12fc',
        '140201010701260cca020f0d23042f7783ff12fc',
    ])
    def test_sense_ttf_with_response_errors(self, device, sensf_res):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('01 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('03 00'),
            ACK(), RSP('05 0000000008' + sensf_res),
        ]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.chipset.transport.read.call_count == 8
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 01010f01'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0018'),
            CMD('04 6e00 0600ffff0100'),
        ]]

    def test_sense_ttf_with_invalid_target(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_ttf(nfc.clf.RemoteTarget('106A'))
        assert str(excinfo.value) == "unsupported bitrate 106A"

    def test_sense_dep_is_not_supported(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_dep(nfc.clf.RemoteTarget('106A'))
        assert str(excinfo.value) == (
            "NFC Port-100 v1.11 at usb:001:001 does not "
            "support sense for active DEP Target")

    #
    # LISTEN
    #

    @pytest.mark.parametrize("target, errmsg", [
        (nfc.clf.LocalTarget('106B'),
         "unsupported target bitrate: '106B'"),
        (nfc.clf.LocalTarget('106A', rid_res=HEX('00')),
         "listening for type 1 tag activation is not supported"),
    ])
    def test_listen_tta_target_not_supported(self, device, target, errmsg):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_tta(target, 1.0)
        assert str(excinfo.value) == errmsg

    @pytest.mark.parametrize("target, errmsg", [
        (nfc.clf.LocalTarget('106A'),
         "sens_res is required"),
        (nfc.clf.LocalTarget('106A', sens_res=b'1'),
         "sdd_res is required"),
        (nfc.clf.LocalTarget('106A', sens_res=b'1', sdd_res=b'1'),
         "sel_res is required"),
        (nfc.clf.LocalTarget('106A', sens_res=b'1', sdd_res=b'1',
                             sel_res=b'12'),
         "sens_res must be 2 byte"),
        (nfc.clf.LocalTarget('106A', sens_res=b'12', sdd_res=b'1',
                             sel_res=b'12'),
         "sdd_res must be 4 byte"),
        (nfc.clf.LocalTarget('106A', sens_res=b'12', sdd_res=b'1234',
                             sel_res=b'12'),
         "sel_res must be 1 byte"),
        (nfc.clf.LocalTarget('106A', sens_res=b'12', sdd_res=b'1234',
                             sel_res=b'1'),
         "sdd_res[0] must be 08h"),
    ])
    def test_listen_tta_target_value_error(self, device, target, errmsg):
        with pytest.raises(ValueError) as excinfo:
            device.listen_tta(target, 1.0)
        assert str(excinfo.value) == errmsg

    @pytest.mark.parametrize("tg_comm_rf_response", [
        '4900000080000000', '490c000300000000',
    ])
    def test_listen_tta_tt2_not_activated(self, device, tg_comm_rf_response):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP(tg_comm_rf_response),
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 0.001) is None
        assert device.chipset.transport.read.call_count == 8

    def test_listen_tta_tt2_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000 3132'),
            ACK(), RSP('4300'),
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("08010203")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX("4400")
        assert target.sel_res == HEX("00")
        assert target.sdd_res == HEX("08010203")
        assert target.tt2_cmd == HEX('3132')
        assert device.chipset.transport.read.call_count == 10

    @pytest.mark.parametrize("tg_comm_rf_response", [
        '4900000080000000', '490c000300000000E0',
        '490b000400000000E0', '490b000300000000E1',
    ])
    def test_listen_tta_tt4_not_activated(self, device, tg_comm_rf_response):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP(tg_comm_rf_response),
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        assert device.listen_tta(target, 0.001) is None
        assert device.chipset.transport.read.call_count == 8

    @pytest.mark.parametrize("rats_res", [
        None, HEX('05 78 80 70 02 aabbcc'), HEX('05 38 80 70 aabbcc'),
        HEX('05 18 80 aabbcc'), HEX('05 08 aabbcc'),
    ])
    def test_listen_tta_tt4_activated(self, device, rats_res):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000E070'),
            ACK(), RSP('490b0003000000003132'),
            ACK(), RSP('4300'),
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        target.rats_res = rats_res
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX("4400")
        assert target.sel_res == HEX("20")
        assert target.sdd_res == HEX("08010203")
        assert target.tt4_cmd == HEX('3132')
        assert device.chipset.transport.read.call_count == 12

    def test_listen_tta_tt4_with_deselect(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000E070'),
            ACK(), RSP('490b000300000000C200'),
            ACK(), RSP('490b000300000000E070'),
            ACK(), RSP('490b0003000000003132'),
            ACK(), RSP('4300'),
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        target.rats_res = HEX('05 78 80 70 02')
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX("4400")
        assert target.sel_res == HEX("20")
        assert target.sdd_res == HEX("08010203")
        assert target.tt4_cmd == HEX('3132')
        assert device.chipset.transport.read.call_count == 16

    def test_listen_tta_tt4_skip_tt4_cmd(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000E070'),
            ACK(), RSP('490b0003000000003932'),
            ACK(), RSP('490b0003000000003132'),
            ACK(), RSP('4300'),
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("08010203")
        target.rats_res = HEX('05 78 80 70 02')
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX("4400")
        assert target.sel_res == HEX("20")
        assert target.sdd_res == HEX("08010203")
        assert target.tt4_cmd == HEX('3132')
        assert device.chipset.transport.read.call_count == 14

    def test_listen_tta_not_tt2_or_tt4(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
        ]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_tta(target, 1.0)
        assert str(excinfo.value) == \
            "sel_res does not indicate any tag target support"
        assert device.chipset.transport.read.call_count == 6

    def test_listen_ttb_is_not_supported(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_ttb(nfc.clf.LocalTarget('106B'), 1.0)
        assert str(excinfo.value) == "NFC Port-100 v1.11 at usb:001:001 " \
            "does not support listen as Type A Target"

    @pytest.mark.parametrize("target, errmsg", [
        (nfc.clf.LocalTarget('106F'), "unsupported target bitrate: '106F'"),
    ])
    def test_listen_ttf_target_not_supported(self, device, target, errmsg):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_ttf(target, 1.0)
        assert str(excinfo.value) == errmsg

    @pytest.mark.parametrize("target, errmsg", [
        (nfc.clf.LocalTarget('212F'),
         "sensf_res is required"),
        (nfc.clf.LocalTarget('212F', sensf_res=b''),
         "sensf_res must be 19 byte"),
    ])
    def test_listen_ttf_target_value_error(self, device, target, errmsg):
        with pytest.raises(ValueError) as excinfo:
            device.listen_ttf(target, 1.0)
        assert str(excinfo.value) == errmsg

    def test_listen_ttf_timeout_waiting_for_activation(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490c000080000000'),
        ]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX("01 0102030405060708 FFFFFFFFFFFFFFFF 12FC")
        assert device.listen_ttf(target, 0.001) is None
        assert device.chipset.transport.read.call_count == 8

    @pytest.mark.parametrize("sensf_req", [
        '00ffff0100', '00ffff0200', '0012fc0000',
    ])
    def test_listen_ttf_received_sensf_request(self, device, sensf_req):
        sensf_res = '01 0102030405060708 FFFFFFFFFFFFFFFF 12FC'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490c000000000000'),
            ACK(), RSP('490c000000000000 060011220000'),
            ACK(), RSP('490c000000000000 06' + sensf_req),
            ACK(), RSP('490c000000000000 0a040102030405060708'),
            ACK(), RSP('4300'),
        ]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX(sensf_res)
        target = device.listen_ttf(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '212F'
        assert target.sensf_req == HEX(sensf_req)
        assert target.sensf_res == HEX(sensf_res)
        assert target.tt3_cmd == HEX('040102030405060708')
        assert device.chipset.transport.read.call_count == 16

    def test_listen_dep_timeout_waiting_for_activation(self, device):
        target = nfc.clf.LocalTarget()

        errmsg = "sens_res is required and must be 2 byte"
        with pytest.raises(ValueError) as excinfo:
            device.listen_dep(target, 1.0)
        assert str(excinfo.value) == errmsg
        target.sens_res = HEX('0101')

        errmsg = "sel_res is required and must be 1 byte"
        with pytest.raises(ValueError) as excinfo:
            device.listen_dep(target, 1.0)
        assert str(excinfo.value) == errmsg
        target.sel_res = HEX('40')

        errmsg = "sdd_res is required and must be 4 byte"
        with pytest.raises(ValueError) as excinfo:
            device.listen_dep(target, 1.0)
        assert str(excinfo.value) == errmsg
        target.sdd_res = HEX('08CE9AD6')

        errmsg = "sensf_res is required and must be 19 byte"
        with pytest.raises(ValueError) as excinfo:
            device.listen_dep(target, 1.0)
        assert str(excinfo.value) == errmsg
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')

        errmsg = "atr_res is required and must be >= 17 byte"
        with pytest.raises(ValueError) as excinfo:
            device.listen_dep(target, 1.0)
        assert str(excinfo.value) == errmsg
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')

        # timeout error
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000080000000'),
        ]
        device.listen_dep(target, 0.001)
        assert device.chipset.transport.read.call_count == 8

    def test_listen_dep_returns_tta_card_activation(self, device):
        target = nfc.clf.LocalTarget('106A')
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')
        target.sens_res = HEX('0101')
        target.sel_res = HEX('60')
        target.sdd_res = HEX('00CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000040000000'),
            ACK(), RSP('490b000000000000'),
            ACK(), RSP('490b000300000000 3000'),
            ACK(), RSP('4300'),
        ]
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX('0101')
        assert target.sel_res == HEX('60')
        assert target.sdd_res == HEX('08CE9AD6')
        assert target.tt2_cmd == HEX('3000')
        assert device.chipset.transport.read.call_count == 14

    def test_listen_dep_in_106_activated_in_106(self, device):
        target = nfc.clf.LocalTarget('106A')
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = 'F0 13 D400 30313233343536373839 00000002 aabb'
        dep_req_frame = 'F0 06 D406 00 3132'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + dep_req_frame),
        ]
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX('0101')
        assert target.sel_res == HEX('40')
        assert target.sdd_res == HEX('08CE9AD6')
        assert target.psl_req is None
        assert target.dep_req == HEX('D406003132')
        assert device.chipset.transport.read.call_count == 12

    def test_listen_dep_in_106_activated_to_424(self, device):
        target = nfc.clf.LocalTarget('106A')
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = 'F0 13 D400 3031323334353637383900000002aabb'
        psl_req_frame = 'F0 06 D404 001203'
        dep_req_frame = '06 D406 00 3132'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + psl_req_frame),
            ACK(), RSP('490b000300000000'),
            ACK(), RSP('4100'),
            ACK(), RSP('490b000300000000' + dep_req_frame),
        ]
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '424F'
        assert target.sens_res == HEX('0101')
        assert target.sel_res == HEX('40')
        assert target.sdd_res == HEX('08CE9AD6')
        assert target.psl_req == HEX('D404001203')
        assert target.dep_req == HEX('D406003132')
        assert device.chipset.transport.read.call_count == 18

    def test_listen_dep_in_212_activated_to_424(self, device):
        sensf_res = '0101FEDA852B1DCDF70000000000000000FFFF'
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = '13 D400 3031323334353637383900000002aabb'
        psl_req_frame = '06 D404 001203'
        dep_req_frame = '06 D406 00 3132'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490c000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490c000300000000' + psl_req_frame),
            ACK(), RSP('490c000300000000'),
            ACK(), RSP('4100'),
            ACK(), RSP('490b000300000000' + dep_req_frame),
        ]
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '424F'
        assert target.sensf_res == HEX(sensf_res)
        assert target.psl_req == HEX('D404001203')
        assert target.dep_req == HEX('D406003132')
        assert device.chipset.transport.read.call_count == 18

    def test_listen_dep_in_424_activated_in_424(self, device):
        sensf_res = '0101FEDA852B1DCDF70000000000000000FFFF'
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = '13 D400 3031323334353637383900000002aabb'
        dep_req_frame = '06 D406 00 3132'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490d000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + dep_req_frame),
        ]
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '424F'
        assert target.sensf_res == HEX(sensf_res)
        assert target.psl_req is None
        assert target.dep_req == HEX('D406003132')
        assert device.chipset.transport.read.call_count == 12

    def test_listen_dep_in_424_received_dsl_req(self, device):
        sensf_res = '0101FEDA852B1DCDF70000000000000000FFFF'
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = '13 D400 3031323334353637383900000002aabb'
        dsl_req_frame = '03 D408'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490d000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + dsl_req_frame),
            ACK(), RSP('490c000300000000'),
        ]
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 14

    def test_listen_dep_in_424_received_rls_req(self, device):
        sensf_res = '0101FEDA852B1DCDF70000000000000000FFFF'
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = '13 D400 3031323334353637383900000002aabb'
        rls_req_frame = '03 D40A'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490d000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + rls_req_frame),
            ACK(), RSP('490c000300000000'),
        ]
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 14

    def test_listen_dep_in_212_asymmetric_psl_req(self, device):
        sensf_res = '0101FEDA852B1DCDF70000000000000000FFFF'
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = '13 D400 3031323334353637383900000002aabb'
        psl_req_frame = '06 D404 001103'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490c000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490c000300000000' + psl_req_frame),
        ]
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 12

    @pytest.mark.parametrize("frame", [
        '', '00', 'F000', 'F00200', 'F003D404', 'F003D406', 'F003D408',
        'F003D40a', 'F010D40030313233343536373839000000'
    ])
    def test_listen_dep_invalid_atr_req_frame(self, device, frame):
        target = nfc.clf.LocalTarget('106A')
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + frame),
            ACK(), RSP('4300'),
        ]
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 10

    @pytest.mark.parametrize("frame", [
        '', '00', 'F000', 'F00200', 'F003D4FF',
    ])
    def test_listen_dep_invalid_command_frame(self, device, frame):
        target = nfc.clf.LocalTarget('106A')
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = 'F0 13 D400 3031323334353637383900000002aabb'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + frame),
        ]
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 12

    @pytest.mark.parametrize("frame", [
        'F006D404011203', 'F007D40604010000', 'F004D40801', 'F004D40A01',
    ])
    def test_listen_dep_received_wrong_did(self, device, frame):
        target = nfc.clf.LocalTarget('106A')
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = 'F0 13 D400 3031323334353637383900000002aabb'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + frame),
            ACK(), RSP('490b000300000000 F0 03 D408'),
            ACK(), RSP('490b000300000000'),
        ]
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 16

    def test_listen_dep_timeout_error_after_atr_res(self, device):
        target = nfc.clf.LocalTarget('106A')
        target.sensf_res = HEX('0101FEDA852B1DCDF70000000000000000FFFF')
        target.sens_res = HEX('0101')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('08CE9AD6')
        target.atr_res = HEX('D50101FEDA852B1DCDF75354000000083246666D010113')
        atr_req_frame = 'F0 13 D400 3031323334353637383900000002aabb'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4100'),
            ACK(), RSP('4300'),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + atr_req_frame),
            ACK(), RSP('4300'),
            ACK(), RSP('490b000300000000' + atr_req_frame),
            ACK(), RSP('490b000308000000'),
        ]
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 14

    #
    # SEND RESPONSE RECEIVE COMMAND
    #

    def test_send_cmd_recv_rsp_with_tt2_target(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('0100'),
            ACK(), RSP('0300'),
            ACK(), RSP('0300'),
            ACK(), RSP('0500000000083334cdf5'),
        ]
        target = nfc.clf.RemoteTarget('106A')
        target.sens_res = HEX('4400')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('00')
        assert device.send_cmd_recv_rsp(target, b'12', 1.0) == b'34'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 040102000501'),
            CMD('04 1a273132'),
        ]]

    def test_send_cmd_recv_rsp_with_dep_target(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('0100'),
            ACK(), RSP('0300'),
            ACK(), RSP('0300'),
            ACK(), RSP('0500000000083334'),
        ]
        target = nfc.clf.RemoteTarget('106A')
        target.sens_res = HEX('4400')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        assert device.send_cmd_recv_rsp(target, b'12', 1.0) == b'34'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 04010501'),
            CMD('04 1a273132'),
        ]]

    def test_send_cmd_recv_rsp_with_ttb_target(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('0100'),
            ACK(), RSP('0300'),
            ACK(), RSP('0300'),
            ACK(), RSP('0500000000083334'),
        ]
        target = nfc.clf.RemoteTarget('106B')
        target.sensb_res = HEX('50E8253EEC00000011008185')
        assert device.send_cmd_recv_rsp(target, b'12', 1.0) == b'34'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 03070f07'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0b0109010c010a010014'),
            CMD('04 1a273132'),
        ]]

    @pytest.mark.parametrize("timeout, param", [
        (0, '0000'), (1.0, '1a27'), (0.1, 'f203'), (0.001, '1400'),
    ])
    def test_send_cmd_recv_rsp_with_timeout(self, device, timeout, param):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('0100'),
            ACK(), RSP('0300'),
            ACK(), RSP('0300'),
            ACK(), RSP('0500000000083334'),
        ]
        target = nfc.clf.RemoteTarget('106B')
        target.sensb_res = HEX('50E8253EEC00000011008185')
        assert device.send_cmd_recv_rsp(target, b'12', timeout) == b'34'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 03070f07'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0b0109010c010a010014'),
            CMD('04 %s3132' % param),
        ]]

    @pytest.mark.parametrize("status, error", [
        ('80000000', nfc.clf.TimeoutError),
        ('02000000', nfc.clf.TransmissionError),
    ])
    def test_send_cmd_recv_rsp_with_error_status(self, device, status, error):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('0100'),
            ACK(), RSP('0300'),
            ACK(), RSP('0300'),
            ACK(), RSP('05' + status),
        ]
        target = nfc.clf.RemoteTarget('106B')
        target.sensb_res = HEX('50E8253EEC00000011008185')
        with pytest.raises(error):
            device.send_cmd_recv_rsp(target, b'12', 0)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 03070f07'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 0b0109010c010a010014'),
            CMD('04 00003132'),
        ]]

    def test_send_cmd_recv_rsp_with_crca_error(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('0100'),
            ACK(), RSP('0300'),
            ACK(), RSP('0300'),
            ACK(), RSP('05000000000833340000'),
        ]
        target = nfc.clf.RemoteTarget('106A')
        target.sens_res = HEX('4400')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('00')
        with pytest.raises(nfc.clf.TransmissionError):
            device.send_cmd_recv_rsp(target, b'12', 1.0)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 02030f03'),
            CMD('02 00180101020103000400050006000708'
                '   080009000a000b000c000e040f001000'
                '   110012001306'),
            CMD('02 040102000501'),
            CMD('04 1a273132'),
        ]]

    #
    # SEND COMMAND RECEIVE RESPONSE
    #

    @pytest.mark.parametrize("timeout, param", [
        (1.0, 'e803'), (0.001, '0100'), (None, 'ffff'), (0, '0000'),
    ])
    def test_send_rsp_recv_cmd_with_timeout(self, device, timeout, param):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('49 00 00 00 00000000 3334'),
        ]
        target = nfc.clf.LocalTarget()
        assert device.send_rsp_recv_cmd(target, b'12', timeout) == b'34'
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('48 f401 ffff 00 000000000000'
                '   000000000000000000000000000000000000'
                '   00 00 %s 3132' % param),
        ]]

    @pytest.mark.parametrize("status, error", [
        ('80000000', nfc.clf.TimeoutError),
        ('00040000', nfc.clf.BrokenLinkError),
        ('02000000', nfc.clf.TransmissionError),
    ])
    def test_send_rsp_recv_cmd_with_error_status(self, device, status, error):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('49000000' + status),
        ]
        target = nfc.clf.LocalTarget()
        with pytest.raises(error):
            device.send_rsp_recv_cmd(target, b'12', 0)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('48 f401 ffff 00 000000000000'
                '   000000000000000000000000000000000000'
                '   00 00 0000 3132'),
        ]]


def test_driver_init(transport):
    transport.read.side_effect = [
        HEX('01020304'), IOError,
        ACK(), RSP('2b 00'),
        ACK(), RSP('21 1101'),
        ACK(), RSP('23 0001'),
        ACK(), RSP('07 00'),
        ACK(), RSP('21 1101'),
    ]
    device = nfc.clf.rcs380.init(transport)
    assert isinstance(device, nfc.clf.rcs380.Device)
    assert device.vendor_name == "Manufacturer Name"
    assert device.product_name == "Product Name"
