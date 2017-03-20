# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.pn532

import sys
import errno
import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call, MagicMock, PropertyMock

import base_clf_pn53x
from base_clf_pn53x import CMD, RSP, ACK, NAK, ERR, HEX  # noqa: F401

import logging
logging.basicConfig(level=logging.DEBUG-1)  # WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.pn533").setLevel(logging_level)


@pytest.fixture()  # noqa: F811
def transport(mocker):
    transport = nfc.clf.transport.TTY()
    mocker.patch.object(transport, 'open', autospec=True)
    mocker.patch.object(transport, 'close', autospec=True)
    mocker.patch.object(transport, 'write', autospec=True)
    mocker.patch.object(transport, 'read', autospec=True)
    transport.tty = MagicMock()
    type(transport.tty).port = PropertyMock(return_value='/dev/ttyS0')
    type(transport.tty).baudrate = PropertyMock(return_value=115200)
#    transport._manufacturer_name = "Manufacturer Name"
#    transport._product_name = "Product Name"
    return transport


class TestChipset(base_clf_pn53x.TestChipset):
    @pytest.fixture()
    def chipset(self, transport):
        return nfc.clf.pn532.Chipset(transport, logger=nfc.clf.pn532.log)

    @pytest.mark.parametrize("baudrate, cmd", [
        (9600, CMD('10 00')),
        (19200, CMD('10 01')),
        (38400, CMD('10 02')),
        (57600, CMD('10 03')),
        (115200, CMD('10 04')),
        (230400, CMD('10 05')),
        (460800, CMD('10 06')),
        (921600, CMD('10 07')),
        (1288000, CMD('10 08')),
    ])
    def test_set_serial_baudrate(self, chipset, baudrate, cmd):
        chipset.transport.read.side_effect = [ACK(), RSP('11')]
        assert chipset.set_serial_baudrate(baudrate) is None
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        assert chipset.transport.write.mock_calls == [call(cmd), call(ACK())]

    @pytest.mark.parametrize("mode, timeout, irq, command", [
        ("normal", 0, False, CMD('14 01 00 00')),
        ("virtual", 1, True, CMD('14 02 01 01')),
        ("wired", 2, False, CMD('14 03 02 00')),
        ("dual", 3, True, CMD('14 04 03 01')),
    ])
    def test_sam_configuration(self, chipset, mode, timeout, irq, command):
        chipset.transport.read.side_effect = [ACK(), RSP('15')]
        assert chipset.sam_configuration(mode, timeout, irq) is None
        assert chipset.transport.write.mock_calls == [call(command)]
        assert chipset.transport.read.mock_calls == [call(100), call(100)]

    @pytest.mark.parametrize("wakeup_enable, generate_irq, command", [
        ("INT0", False, CMD('16 01 00')),
        ("INT1", False, CMD('16 02 00')),
        ("RF",   False, CMD('16 08 00')),
        ("HSU",  False, CMD('16 10 00')),
        ("SPI",  False, CMD('16 20 00')),
        ("GPIO", False, CMD('16 40 00')),
        ("I2C",  False, CMD('16 80 00')),
        ("HSU, SPI, I2C", True, CMD('16 B0 01')),
    ])
    def test_power_down(self, chipset, wakeup_enable, generate_irq, command):
        chipset.transport.read.side_effect = [ACK(), RSP('17 00')]
        assert chipset.power_down(wakeup_enable, generate_irq) is None
        assert chipset.transport.write.mock_calls == [call(command)]
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        chipset.transport.read.side_effect = [ACK(), RSP('17 01')]
        with pytest.raises(chipset.Error) as excinfo:
            chipset.power_down(wakeup_enable, generate_irq)
        assert excinfo.value.errno == 1

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
        sys.platform = "testing"
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
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
        device = nfc.clf.pn532.init(transport)
        assert isinstance(device, nfc.clf.pn532.Device)
        assert isinstance(device.chipset, nfc.clf.pn532.Chipset)
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
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
        yield device
        transport.write.reset_mock()
        transport.read.reset_mock()
        transport.read.side_effect = [
            ACK(), RSP('11'),                             # SetSerialBaudrate
            ACK(), RSP('17 00'),                          # PowerDown
        ]
        device.close()
        assert transport.write.mock_calls == [call(_) for _ in [
            ACK(),                                        # cancel last cmd
            CMD('10 04'), ACK(),                          # SetSerialBaudrate
            CMD('16 b000'),                               # PowerDown
        ]]

    def test_init_linux_stty_set_none(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        mocker.patch('os.system').return_value = -1
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
        ]
        device = nfc.clf.pn532.init(transport)
        assert isinstance(device, nfc.clf.pn532.Device)
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
        ]]

    def test_init_linux_stty_set_460800(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        stty = mocker.patch('os.system')
        stty.side_effect = [-1, 0, None]
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
            ACK(), RSP('11'),                             # SetSerialBaudrate
        ]
        device = nfc.clf.pn532.init(transport)
        assert isinstance(device, nfc.clf.pn532.Device)
        assert stty.mock_calls == [
            call('stty -F /dev/ttyS0 921600 2> /dev/null'),
            call('stty -F /dev/ttyS0 460800 2> /dev/null'),
            call('stty -F /dev/ttyS0 115200 2> /dev/null'),
        ]
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
            HEX(10 * '00') + CMD('10 06'), ACK(),         # SetSerialBaudrate
        ]]

    def test_init_raspi_tty_ser(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["Hardware BCM270"]
        type(transport.tty).port = PropertyMock(return_value='/dev/ttyS0')
        stty = mocker.patch('os.system')
        stty.return_value = -1
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
        ]
        device = nfc.clf.pn532.init(transport)
        assert isinstance(device, nfc.clf.pn532.Device)
        assert stty.mock_calls == []
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
        ]]
        assert transport.read.mock_calls == [
            call(timeout=100), call(timeout=100),
            call(timeout=100), call(timeout=100),
        ]

    def test_init_raspi_tty_usb(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["Hardware BCM270"]
        type(transport.tty).port = PropertyMock(return_value='/dev/ttyUSB0')
        stty = mocker.patch('os.system')
        stty.return_value = -1

        sys.platform = "linux"
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
        ]
        device = nfc.clf.pn532.init(transport)
        assert stty.mock_calls == [
            call('stty -F /dev/ttyUSB0 921600 2> /dev/null'),
            call('stty -F /dev/ttyUSB0 460800 2> /dev/null'),
            call('stty -F /dev/ttyUSB0 230400 2> /dev/null'),
            call('stty -F /dev/ttyUSB0 115200 2> /dev/null'),
        ]
        assert isinstance(device, nfc.clf.pn532.Device)
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
        ]]
        assert transport.read.mock_calls == [
            call(timeout=1500), call(timeout=100),
            call(timeout=100), call(timeout=100),
        ]

    def test_init_raspi_tty_ama(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["Hardware BCM270"]
        type(transport.tty).port = PropertyMock(return_value='/dev/ttyAMA0')
        stty = mocker.patch('os.system')
        stty.return_value = -1

        sys.platform = "linux"
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
        ]
        device = nfc.clf.pn532.init(transport)
        assert stty.mock_calls == [
            call('stty -F /dev/ttyAMA0 921600 2> /dev/null'),
            call('stty -F /dev/ttyAMA0 460800 2> /dev/null'),
            call('stty -F /dev/ttyAMA0 230400 2> /dev/null'),
            call('stty -F /dev/ttyAMA0 115200 2> /dev/null'),
        ]
        assert isinstance(device, nfc.clf.pn532.Device)
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
        ]]
        assert transport.read.mock_calls == [
            call(timeout=100), call(timeout=100),
            call(timeout=100), call(timeout=100),
        ]

    def test_init_linux_version_ack_err(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        mocker.patch('os.system').return_value = -1
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ERR(),                                        # GetFirmwareVersion
        ]
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn532.init(transport)
        assert excinfo.value.errno == errno.ENODEV
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
        ]]

    def test_init_linux_version_rsp_err(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        mocker.patch('os.system').return_value = -1
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), ERR(),                                 # GetFirmwareVersion
        ]
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn532.init(transport)
        assert excinfo.value.errno == errno.ENODEV
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
        ]]

    def test_init_linux_sam_cfg_ack_err(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        mocker.patch('os.system').return_value = -1
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ERR(),                                        # SAMConfiguration
        ]
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn532.init(transport)
        assert excinfo.value.errno == errno.ENODEV
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
        ]]

    def test_init_linux_sam_cfg_rsp_err(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        mocker.patch('os.system').return_value = -1
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), ERR(),                                 # SAMConfiguration
        ]
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn532.init(transport)
        assert excinfo.value.errno == errno.ENODEV
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
        ]]

    def test_init_linux_setbaud_ack_err(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        stty = mocker.patch('os.system')
        stty.side_effect = [-1, 0, None]
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
            ERR(),                                        # SetSerialBaudrate
        ]
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn532.init(transport)
        assert excinfo.value.errno == errno.ENODEV
        assert stty.mock_calls == [
            call('stty -F /dev/ttyS0 921600 2> /dev/null'),
            call('stty -F /dev/ttyS0 460800 2> /dev/null'),
            call('stty -F /dev/ttyS0 115200 2> /dev/null'),
        ]
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
            HEX(10 * '00') + CMD('10 06'),                # SetSerialBaudrate
        ]]

    def test_init_linux_setbaud_rsp_err(self, mocker, transport):  # noqa: F811
        mocker.patch('nfc.clf.pn532.Device.__init__').return_value = None
        mocker.patch('nfc.clf.pn532.open').return_value = ["cpuinfo"]
        stty = mocker.patch('os.system')
        stty.side_effect = [-1, 0, None]
        sys.platform = "linux"

        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('03 32010607'),                    # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
            ACK(), ERR(),                                 # SetSerialBaudrate
        ]
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn532.init(transport)
        assert excinfo.value.errno == errno.ENODEV
        assert stty.mock_calls == [
            call('stty -F /dev/ttyS0 921600 2> /dev/null'),
            call('stty -F /dev/ttyS0 460800 2> /dev/null'),
            call('stty -F /dev/ttyS0 115200 2> /dev/null'),
        ]
        assert transport.write.mock_calls == [call(_) for _ in [
            HEX(10 * '00') + CMD('02'),                   # GetFirmwareVersion
            HEX(10 * '00') + CMD('14 010000'),            # SAMConfiguration
            HEX(10 * '00') + CMD('10 06'),                # SetSerialBaudrate
        ]]

    def test_init_transport_type_not_tty(self, transport):
        transport.TYPE = "USB"
        with pytest.raises(IOError) as excinfo:
            nfc.clf.pn532.init(transport)
        assert excinfo.value.errno == errno.ENODEV

    def test_close(self, device):
        device.chipset.transport.TYPE = "test"
        transport = device.chipset.transport
        chipset = device.chipset
        transport.read.side_effect = [ACK(), RSP('1700')]
        device.close()
        assert transport.write.mock_calls == [call(ACK()), call(CMD('16b000'))]
        device.chipset = chipset
        device.chipset.transport = transport
        device.chipset.transport.TYPE = "TTY"
