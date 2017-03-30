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

    @pytest.mark.skip()
    def test_sense_tta_with_tt1_target_found(self, device):
        pass

    @pytest.mark.skip()
    def test_sense_tta_with_tt2_target_found(self, device):
        pass

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

    @pytest.mark.skip()
    def test_sense_tta_with_response_errors(self, device):
        pass

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

    @pytest.mark.skip()
    def test_sense_ttb_with_tt4_target_found(self, device):
        pass

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

    @pytest.mark.skip()
    def test_sense_ttb_with_response_errors(self, device):
        pass

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
