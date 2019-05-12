# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.acr122

import struct
import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.acr122").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


def CMD(hexstr):
    cmd = HEX('D4' + hexstr)
    return struct.pack('<BIxxxxxBxxxB', 0x6F, 5+len(cmd), 0xFF, len(cmd)) + cmd


def RSP(hexstr):
    rsp = HEX('D5' + hexstr + '9000')
    return struct.pack('<BIxxxBx', 0x80, len(rsp), 0x81) + rsp


@pytest.fixture()  # noqa: F811
def transport(mocker):
    mocker.patch('nfc.clf.transport.USB.__init__').return_value = None
    transport = nfc.clf.transport.USB(1, 1)
    mocker.patch.object(transport, 'write', autospec=True)
    mocker.patch.object(transport, 'read', autospec=True)
    transport._manufacturer_name = "Vendor"
    transport._product_name = "Reader"
    transport.context = None
    transport.usb_dev = None
    return transport


@pytest.fixture()
def chipset(transport):
    transport.read.side_effect = [
        HEX('80 0a000000 0000028100 41435231323255323033'),
        HEX('80 02000000 0000008100 3b00'),
        HEX('80 01000000 0000008100 7f'),
        HEX('80 02000000 0000008100 9002'),
    ]
    chipset = nfc.clf.acr122.Chipset(transport)
    assert transport.read.call_count == 4
    assert transport.write.mock_calls == [call(_) for _ in [
        HEX('6f050000000000000000 ff00480000'),       # Get Version String
        HEX('62000000000000000000'),                  # CCID ICC-POWER-ON
        HEX('6f050000000000000000 ff00517f00'),       # Set PICC Parameters
        HEX('6f090000000000000000 ff00400e0400000000'),  # Buzzer and LED
    ]]
    transport.write.reset_mock()
    transport.read.reset_mock()
    return chipset


class TestChipset(object):
    def test_init_wrong_version_string(self, transport):
        transport.read.side_effect = [
            HEX('80 03000000 0000028100 414352'),
        ]
        with pytest.raises(IOError):
            nfc.clf.acr122.Chipset(transport)
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX('6f050000000000000000 ff00480000'),       # Get Version String
        ]]

    def test_init_wrong_version_number(self, transport):
        transport.read.side_effect = [
            HEX('80 0a000000 0000028100 41435231323255313033'),
        ]
        with pytest.raises(IOError):
            nfc.clf.acr122.Chipset(transport)
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX('6f050000000000000000 ff00480000'),       # Get Version String
        ]]

    def test_close(self, chipset):
        transport = chipset.transport
        transport.read.side_effect = [
            HEX('80020000000000008100 9000'),
        ]
        chipset.close()
        assert transport.read.call_count == 1
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX('6f090000000000000000 ff00400c0400000000'),
        ]]

    def test_set_buzzer_and_led_to_active(self, chipset):
        chipset.transport.read.side_effect = [
            HEX('80020000000000008100 9000'),
        ]
        chipset.set_buzzer_and_led_to_active()
        assert chipset.transport.read.call_count == 1
        assert chipset.transport.write.mock_calls == [call(_) for _ in [
            HEX('6f090000000000000000 ff00400d0403000101'),
        ]]

    def test_send_ack(self, chipset):
        chipset.transport.read.side_effect = [
            HEX('80020000000000008100 9000'),
        ]
        chipset.send_ack()
        assert chipset.transport.read.call_count == 1
        assert chipset.transport.write.mock_calls == [call(_) for _ in [
            HEX('6f060000000000000000 0000ff00ff00'),
        ]]

    @pytest.mark.parametrize("rsp_frame", [
        '800300000000000081',
        '00030000000000008100343536',
        '80040000000000008100343536',
    ])
    def test_ccid_xfr_block_frame_error(self, chipset, rsp_frame):
        chipset.transport.read.side_effect = [HEX(rsp_frame)]
        with pytest.raises(IOError):
            chipset.ccid_xfr_block(b'123')
        assert chipset.transport.read.call_count == 1
        assert chipset.transport.write.mock_calls == [call(_) for _ in [
            HEX('6f030000000000000000 313233'),
        ]]

    @pytest.mark.parametrize("response", [
        '80030000000000008100 D501 90',
        '80040000000000008100 D401 9000',
        '80040000000000008100 D500 9000',
        '80040000000000008100 D501 9100',
        '80040000000000008100 D501 9001',
    ])
    def test_command_response_error(self, chipset, response):
        chipset.transport.read.side_effect = [HEX(response)]
        with pytest.raises(IOError):
            chipset.command(0x00, b'123', 1.0)
        print(chipset.transport.write.mock_calls)
        assert chipset.transport.read.call_count == 1
        assert chipset.transport.write.mock_calls == [call(CMD('00313233'))]


class TestDevice(object):
    @pytest.fixture()
    def device(self, chipset):
        chipset.transport.read.side_effect = [
            RSP('01 00'
                '000102030405060708090a0b0c0d0e0f'
                '101112131415161718191a1b1c1d1e1f'
                '202122232425262728292a2b2c2d2e2f'
                '303132333435363738393a3b3c3d3e3f'
                '404142434445464748494a4b4c4d4e4f'
                '505152535455565758595a5b5c5d5e5f'
                '606162636465666768696a6b6c6d6e6f'
                '707172737475767778797a7b7c7d7e7f'
                '808182838485868788898a8b8c8d8e8f'
                '909192939495969798999a9b9c9d9e9f'
                'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
                'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
                'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
                'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
                'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
                'f0f1f2f3f4f5f6f7f8f9fa'),              # Diagnose
            RSP('03 32010407'),                         # GetFirmwareVersion
            RSP('13'),                                  # SetParameters
            RSP('33'),                                  # RFConfiguration
            RSP('33'),                                  # RFConfiguration
            RSP('33'),                                  # RFConfiguration
            RSP('33'),                                  # RFConfiguration
            RSP('33'),                                  # RFConfiguration
            RSP('33'),                                  # RFConfiguration
            RSP('33'),                                  # RFConfiguration
            RSP('33'),                                  # RFConfiguration
        ]
        device = nfc.clf.acr122.Device(chipset)
        device._path = 'usb:001:001'
        assert isinstance(device, nfc.clf.acr122.Device)
        assert chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('00 00'
                '000102030405060708090a0b0c0d0e0f'
                '101112131415161718191a1b1c1d1e1f'
                '202122232425262728292a2b2c2d2e2f'
                '303132333435363738393a3b3c3d3e3f'
                '404142434445464748494a4b4c4d4e4f'
                '505152535455565758595a5b5c5d5e5f'
                '606162636465666768696a6b6c6d6e6f'
                '707172737475767778797a7b7c7d7e7f'
                '808182838485868788898a8b8c8d8e8f'
                '909192939495969798999a9b9c9d9e9f'
                'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
                'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
                'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
                'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
                'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
                'f0f1f2f3f4f5f6f7f8f9fa'),              # Diagnose
            CMD('02'),                                  # GetFirmwareVersion
            CMD('12 00'),                               # SetParameters
            CMD('32 02000b0a'),                         # RFConfiguration
            CMD('32 0400'),                             # RFConfiguration
            CMD('32 05010001'),                         # RFConfiguration
            CMD('32 0a59f43f114d85616f266287'),         # RFConfiguration
            CMD('32 0b69ff3f114185616f'),               # RFConfiguration
            CMD('32 0cff0485'),                         # RFConfiguration
            CMD('32 0d85158a8508b28501da'),             # RFConfiguration
            CMD('32 0102'),                             # RFConfiguration
        ]]
        assert chipset.transport.read.call_count == 11
        chipset.transport.write.reset_mock()
        chipset.transport.read.reset_mock()
        return device

    def test_sense_tta(self, device):
        device.chipset.transport.read.side_effect = [
            RSP('4B 00'),                               # InListPassiveTarget
            RSP('07 26'),                               # ReadRegister
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.read.call_count == 2
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                             # InListPassiveTarget
            CMD('06 6339'),                             # ReadRegister
        ]]

    def test_sense_ttb(self, device):
        device.chipset.transport.read.side_effect = [
            RSP('4B 00'),                               # InListPassiveTarget
        ]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.chipset.transport.read.call_count == 1
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 010300'),                           # InListPassiveTarget
        ]]

    def test_sense_ttf(self, device):
        device.chipset.transport.read.side_effect = [
            RSP('07 03'),                               # ReadRegister
            RSP('4B 00'),                               # InListPassiveTarget
        ]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.chipset.transport.read.call_count == 2
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6304'),                             # ReadRegister
            CMD('4A 010100ffff0100'),                   # InListPassiveTarget
        ]]

    def test_sense_dep(self, device):
        atr_req = HEX('D400 30313233343536373839 00000000')
        device.chipset.transport.read.side_effect = [
            RSP('47 01'),                               # InJumpForPSL
            RSP('09 00'),                               # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        assert device.sense_dep(target) is None
        assert device.chipset.transport.read.call_count == 2
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('46 01000230313233343536373839'),       # InJumpForPSL
            CMD('08 63013b'),                           # WriteRegister
        ]]

    def test_listen_tta(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError):
            device.listen_tta(nfc.clf.LocalTarget(), 1.0)
        assert device.chipset.transport.read.call_count == 0
        assert device.chipset.transport.write.call_count == 0

    def test_listen_ttb(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError):
            device.listen_ttb(nfc.clf.LocalTarget(), 1.0)
        assert device.chipset.transport.read.call_count == 0
        assert device.chipset.transport.write.call_count == 0

    def test_listen_ttf(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError):
            device.listen_ttf(nfc.clf.LocalTarget(), 1.0)
        assert device.chipset.transport.read.call_count == 0
        assert device.chipset.transport.write.call_count == 0

    def test_listen_dep(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError):
            device.listen_dep(nfc.clf.LocalTarget(), 1.0)
        assert device.chipset.transport.read.call_count == 0
        assert device.chipset.transport.write.call_count == 0

    def test_turn_on_led_and_buzzer(self, device):
        device.chipset.transport.read.side_effect = [
            HEX('80020000000000008100 9000'),
        ]
        device.turn_on_led_and_buzzer()
        assert device.chipset.transport.read.call_count == 1
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            HEX('6f090000000000000000 ff00400d0403000101'),
        ]]

    def test_turn_off_led_and_buzzer(self, device):
        device.chipset.transport.read.side_effect = [
            HEX('80020000000000008100 9000'),
        ]
        device.turn_off_led_and_buzzer()
        assert device.chipset.transport.read.call_count == 1
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            HEX('6f090000000000000000 ff00400e0400000000'),
        ]]


def test_init(transport):
    transport.read.side_effect = [
        HEX('80 0a000000 0000028100 41435231323255323033'),
        HEX('80 02000000 0000008100 3b00'),
        HEX('80 01000000 0000008100 7f'),
        HEX('80 02000000 0000008100 9002'),

        RSP('01 00'
            '000102030405060708090a0b0c0d0e0f'
            '101112131415161718191a1b1c1d1e1f'
            '202122232425262728292a2b2c2d2e2f'
            '303132333435363738393a3b3c3d3e3f'
            '404142434445464748494a4b4c4d4e4f'
            '505152535455565758595a5b5c5d5e5f'
            '606162636465666768696a6b6c6d6e6f'
            '707172737475767778797a7b7c7d7e7f'
            '808182838485868788898a8b8c8d8e8f'
            '909192939495969798999a9b9c9d9e9f'
            'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
            'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
            'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
            'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
            'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
            'f0f1f2f3f4f5f6f7f8f9fa'),                # Diagnose
        RSP('03 32010407'),                           # GetFirmwareVersion
        RSP('13'),                                    # SetParameters
        RSP('33'),                                    # RFConfiguration
        RSP('33'),                                    # RFConfiguration
        RSP('33'),                                    # RFConfiguration
        RSP('33'),                                    # RFConfiguration
        RSP('33'),                                    # RFConfiguration
        RSP('33'),                                    # RFConfiguration
        RSP('33'),                                    # RFConfiguration
        RSP('33'),                                    # RFConfiguration
    ]
    device = nfc.clf.acr122.init(transport)
    assert transport.read.call_count == 15
    assert device.vendor_name == "Vendor"
    assert device.product_name == "Reader"
