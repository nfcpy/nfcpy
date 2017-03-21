# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.pn533

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call

import base_clf_pn53x
from base_clf_pn53x import CMD, RSP, ACK, NAK, ERR, HEX  # noqa: F401

import logging
logging.basicConfig(level=logging.DEBUG-1)  # WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.pn533").setLevel(logging_level)


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


class TestChipset(base_clf_pn53x.TestChipset):
    @pytest.fixture()
    def chipset(self, transport):
        return nfc.clf.pn533.Chipset(transport, logger=nfc.clf.pn533.log)

    @pytest.mark.parametrize("response, result", [
        (RSP('05 00 01 01 01 00 00 00'),
         ("error code 0x00", "external field detected", (1, 106, 106, 'A/B'))),
        (RSP('05 0e 00 00'),
         ("Internal buffer overflow", "", None)),
    ])
    def test_get_general_status(self, chipset, response, result):
        chipset.transport.read.side_effect = [ACK(), response]
        assert chipset.get_general_status() == result
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        assert chipset.transport.write.mock_calls == [call(CMD('04'))]

    @pytest.mark.parametrize("args, command, response, value", [
        ((0x0102,), '06 0102', '07 00 AA', 0xAA),
        (("CIU_TMode",), '06 631A', '07 00 BB', 0xBB),
        ((0x0102, "CIU_TMode"), '06 0102631A', '07 00 AABB', [0xAA, 0xBB]),
    ])
    def test_read_register(self, chipset, args, command, response, value):
        chipset.transport.read.side_effect = [ACK(), RSP(response)]
        assert chipset.read_register(*args) == value
        chipset.transport.read.side_effect = [ACK(), RSP('07 01')]
        with pytest.raises(nfc.clf.pn533.Chipset.Error) as excinfo:
            chipset.read_register(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(250)]
        assert chipset.transport.write.mock_calls == 2 * [call(CMD(command))]

    @pytest.mark.parametrize("args, command", [
        ((0x0102, 0x00), '08 0102 00'),
        (("CIU_Mode", 0x01), '08 6301 01'),
        (((0x0102, 0x10), ("CIU_Mode", 0x11)), '08 0102 10 6301 11'),
    ])
    def test_write_register(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK(), RSP('09 00')]
        assert chipset.write_register(*args) is None
        chipset.transport.read.side_effect = [ACK(), RSP('09 01')]
        with pytest.raises(nfc.clf.pn533.Chipset.Error) as excinfo:
            chipset.write_register(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(250)]
        assert chipset.transport.write.mock_calls == 2 * [call(CMD(command))]

    def test_tg_init_as_target(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('8D 01 02 03')]
        mifare = HEX('010203040506')
        felica = HEX('010203040506070809101112131415161718')
        nfcid3 = HEX('01020304050607080910')
        gbytes = HEX('313233')
        args = (0x03, mifare, felica, nfcid3, gbytes, HEX(''), 0.5)
        assert chipset.tg_init_as_target(*args) == HEX('01 02 03')
        assert chipset.transport.read.mock_calls == [call(100), call(500)]
        assert chipset.transport.write.mock_calls == [
            call(CMD('8C 03 010203040506 010203040506070809101112131415161718'
                     '01020304050607080910 03 313233 00'))
        ]


class TestDevice(base_clf_pn53x.TestDevice):
    @pytest.fixture()
    def device(self, transport):
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('01 00'
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
                       'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
                       '000102030405'),                   # Diagnose
            ACK(), RSP('03 33020707'),                    # GetFirmwareVersion
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('13'),                             # SetParameters
            ACK(), RSP('07 ff'),                          # ReadRegister
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        device = nfc.clf.pn533.init(transport)
        device._path = 'usb:001:001'
        assert isinstance(device, nfc.clf.pn533.Device)
        assert isinstance(device.chipset, nfc.clf.pn533.Chipset)
        assert transport.write.mock_calls == [call(_) for _ in [
            ACK(),
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
                'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
                '000102030405'),                          # Diagnose
            CMD('02'),                                    # GetFirmwareVersion
            CMD('32 0102'),                               # RFConfiguration
            CMD('32 02000b0a'),                           # RFConfiguration
            CMD('32 0400'),                               # RFConfiguration
            CMD('32 05010001'),                           # RFConfiguration
            CMD('12 00'),                                 # SetParameters
            CMD('06 a000'),                               # ReadRegister
            CMD('32 0a5af43f114d85616f266287'),           # RFConfiguration
            CMD('32 0b6aff3f104185616f'),                 # RFConfiguration
            CMD('32 0cff0485'),                           # RFConfiguration
            CMD('32 0d85158a850ab28504da'),               # RFConfiguration
        ]]
        transport.write.reset_mock()
        transport.read.reset_mock()
        yield device
        transport.write.reset_mock()
        transport.read.reset_mock()
        transport.read.side_effect = [
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        device.close()
        assert transport.write.mock_calls == [
            call(CMD('32 0102')),                         # RFConfiguration
        ]

    def reg_rsp(self, hexdata):
        return RSP('07 00' + hexdata)

    def test_sense_tta_no_target_found(self, device):
        self.pn53x_test_sense_tta_no_target_found(device)

    def test_sense_ttb_no_target_found(self, device):
        self.pn53x_test_sense_ttb_no_target_found(device)

    def test_sense_ttf_no_target_found(self, device):
        self.pn53x_test_sense_ttf_no_target_found(device)

    def test_sense_dep_no_target_found(self, device):
        self.pn53x_test_sense_dep_no_target_found(device)

    def test_listen_tta_not_activated(self, device):
        self.pn53x_test_listen_tta_not_activated(device)

    def test_listen_ttb_not_supported(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.listen_ttb(nfc.clf.LocalTarget('106B'), 1.0)
        assert "does not support listen as Type B Target" in str(excinfo.value)

    def test_listen_ttf_not_activated(self, device):
        self.pn53x_test_listen_ttf_not_activated(device)
