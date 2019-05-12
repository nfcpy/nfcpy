# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.arygon

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call, MagicMock
from base_clf_pn53x import HEX, RSP, ACK, STD_FRAME, EXT_FRAME

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.arygon").setLevel(logging_level)


def CMD(hexstr):
    cmd = HEX('D4' + hexstr)
    return b'2' + (STD_FRAME(cmd) if len(cmd) < 256 else EXT_FRAME(cmd))


@pytest.fixture()  # noqa: F811
def transport(mocker):
    transport = nfc.clf.transport.TTY()
    mocker.patch.object(transport, 'open', autospec=True)
    mocker.patch.object(transport, 'close', autospec=True)
    mocker.patch.object(transport, 'write', autospec=True)
    mocker.patch.object(transport, 'read', autospec=True)
    transport.tty = MagicMock()
    mocker.patch.object(transport.tty, 'write', autospec=True)
    mocker.patch.object(transport.tty, 'readline', autospec=True)
    return transport


class TestChipsetA(object):
    @pytest.fixture()  # noqa: F811
    def chipset(self, transport):
        return nfc.clf.arygon.ChipsetA(transport, logger=nfc.clf.arygon.log)

    def test_write_frame(self, chipset):
        chipset.write_frame(HEX('010203'))
        assert chipset.transport.write.mock_calls == [call(_) for _ in [
            HEX('32010203'),
        ]]


class TestChipsetB(object):
    @pytest.fixture()  # noqa: F811
    def chipset(self, transport):
        return nfc.clf.arygon.ChipsetB(transport, logger=nfc.clf.arygon.log)

    def test_write_frame(self, chipset):
        chipset.write_frame(HEX('010203'))
        assert chipset.transport.write.mock_calls == [call(_) for _ in [
            HEX('32010203'),
        ]]


class TestDeviceA(object):
    @pytest.fixture()  # noqa: F811
    def device(self, transport):
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
                       'f0f1f2f3f4f5f6f7f8f9fa'),         # Diagnose
            ACK(), RSP('03 0304'),                        # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
            ACK(), RSP('13'),                             # SetTAMAParameters
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        chipset = nfc.clf.arygon.ChipsetA(transport, logger=nfc.clf.arygon.log)
        device = nfc.clf.arygon.DeviceA(chipset, logger=nfc.clf.arygon.log)
        assert isinstance(device, nfc.clf.arygon.DeviceA)
        assert isinstance(device.chipset, nfc.clf.arygon.ChipsetA)
        assert transport.write.mock_calls == [call(_) for _ in [
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
                'f0f1f2f3f4f5f6f7f8f9fa'),                # Diagnose
            CMD('02'),                                    # GetFirmwareVersion
            CMD('14 0100'),                               # SAMConfiguration
            CMD('12 00'),                                 # SetTAMAParameters
            CMD('32 02000b0a'),                           # RFConfiguration
            CMD('32 0400'),                               # RFConfiguration
            CMD('32 05010001'),                           # RFConfiguration
            CMD('32 0102'),                               # RFConfiguration
        ]]
        transport.write.reset_mock()
        transport.read.reset_mock()
        return device

    def test_close(self, device):
        tty = device.chipset.transport.tty
        device.close()
        tty.write.assert_called_once_with(b'0au')


class TestDeviceB(object):
    @pytest.fixture()  # noqa: F811
    def device(self, transport):
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
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('13'),                             # SetParameters
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        chipset = nfc.clf.arygon.ChipsetB(transport, logger=nfc.clf.arygon.log)
        device = nfc.clf.arygon.DeviceB(chipset, logger=nfc.clf.arygon.log)
        assert isinstance(device, nfc.clf.arygon.DeviceB)
        assert isinstance(device.chipset, nfc.clf.arygon.ChipsetB)
        assert transport.write.mock_calls == [call(_) for _ in [
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
            CMD('12 00'),                                 # SetParameters
            CMD('32 02000b0a'),                           # RFConfiguration
            CMD('32 0400'),                               # RFConfiguration
            CMD('32 05010001'),                           # RFConfiguration
            CMD('32 0a59f43f114d85616f266287'),           # RFConfiguration
            CMD('32 0b69ff3f114185616f'),                 # RFConfiguration
            CMD('32 0cff0485'),                           # RFConfiguration
            CMD('32 0d85158a8508b28501da'),               # RFConfiguration
            CMD('32 0102'),                               # RFConfiguration
        ]]
        transport.write.reset_mock()
        transport.read.reset_mock()
        return device

    def test_close(self, device):
        tty = device.chipset.transport.tty
        device.close()
        tty.write.assert_called_once_with(b'0au')


def test_init_adra(transport):
    transport.tty.readline.side_effect = [
        b'\x00\x00', b'FF00000600V3.2', b'FF0000', b'FF0000',
    ]
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
                       'f0f1f2f3f4f5f6f7f8f9fa'),         # Diagnose
            ACK(), RSP('03 0304'),                        # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
            ACK(), RSP('13'),                             # SetTAMAParameters
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
    ]
    device = nfc.clf.arygon.init(transport)
    assert isinstance(device, nfc.clf.arygon.DeviceA)
    assert device.vendor_name == "Arygon"
    assert device.product_name == "ADRA"
    assert transport.tty.write.mock_calls == [
        call(b'0av'), call(b'0av'), call(b'0at05'), call(b'0ah05'),
    ]


def test_init_adrb(transport):
    transport.tty.readline.side_effect = [
        b'FF00000600V3.2', b'FF0000', b'FF0000',
    ]
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
        ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
        ACK(), RSP('13'),                             # SetParameters
        ACK(), RSP('33'),                             # RFConfiguration
        ACK(), RSP('33'),                             # RFConfiguration
        ACK(), RSP('33'),                             # RFConfiguration
        ACK(), RSP('33'),                             # RFConfiguration
        ACK(), RSP('33'),                             # RFConfiguration
        ACK(), RSP('33'),                             # RFConfiguration
        ACK(), RSP('33'),                             # RFConfiguration
        ACK(), RSP('33'),                             # RFConfiguration
    ]
    device = nfc.clf.arygon.init(transport)
    assert isinstance(device, nfc.clf.arygon.DeviceB)
    assert device.vendor_name == "Arygon"
    assert device.product_name == "ADRB"
    assert transport.tty.write.mock_calls == [
        call(b'0av'), call(b'0at05'), call(b'0ah05'),
    ]


@pytest.mark.parametrize("read_calls, write_calls", [
    ([b'\x00', b'\x00'],
     [b'0av', b'0av']),
    ([b'FF00000600V3.2', b'\x00', b'\x00'],
     [b'0av', b'0at05', b'0av']),
    ([b'FF00000600V3.2', b'FF0000', b'\x00', b'\x00'],
     [b'0av', b'0at05', b'0ah05', b'0av']),
    ([b'\x00', b'FF00000600V3.2', b'\x00'],
     [b'0av', b'0av', b'0at05']),
    ([b'\x00', b'FF00000600V3.2', b'FF0000', b'\x00'],
     [b'0av', b'0av', b'0at05', b'0ah05']),
])
def test_init_none(transport, read_calls, write_calls):
    transport.tty.readline.side_effect = read_calls
    with pytest.raises(IOError):
        nfc.clf.arygon.init(transport)
    assert transport.tty.write.mock_calls == [call(_) for _ in write_calls]
