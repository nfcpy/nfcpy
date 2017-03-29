# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.transport

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call, MagicMock
import termios
import errno

# import logging
# logging.basicConfig(level=logging.DEBUG-1)
# logging_level = logging.getLogger().getEffectiveLevel()
# logging.getLogger("nfc.clf").setLevel(logging_level)
# logging.getLogger("nfc.clf.transport").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


class TestTTY(object):
    @pytest.mark.parametrize("path, nodes, tcgetattr, found", [  # noqa: F811
        ('tty', ['stderr', 'urandom'], [],
         None),
        ('tty', ['stderr', 'ttyS0', 'ttyACM0', 'urandom'], [True, True],
         (['/dev/ttyACM0', '/dev/ttyS0'], '', True)),
        ('tty', ['stderr', 'ttyACM0', 'ttyAMA0', 'urandom'], [True, True],
         (['/dev/ttyACM0', '/dev/ttyAMA0'], '', True)),
        ('tty', ['stderr', 'ttyAMA0', 'ttyUSB0', 'urandom'], [True, True],
         (['/dev/ttyAMA0', '/dev/ttyUSB0'], '', True)),
        ('tty', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, termios.error],
         (['/dev/ttyS0'], '', True)),
        ('tty:S0', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, True],
         (['/dev/ttyS0'], '', False)),
        ('tty:S', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, True],
         (['/dev/ttyS0', '/dev/ttyS1'], '', True)),
        ('tty:0', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, True],
         None),
        ('tty:S0:drv', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, True],
         (['/dev/ttyS0'], 'drv', False)),
        ('tty:S:drv', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, True],
         (['/dev/ttyS0', '/dev/ttyS1'], 'drv', True)),
        ('tty:0:drv', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, True],
         None),
        ('tty::drv', ['stderr', 'ttyS0', 'ttyS1', 'urandom'], [True, True],
         (['/dev/ttyS0', '/dev/ttyS1'], 'drv', True)),
        ('tty', ['stderr', 'ttyS0', 'ttyACM0', 'urandom'], [IOError, True],
         (['/dev/ttyS0'], '', True)),
        ('tty:S0', ['stderr', 'ttyS0', 'ttyACM0', 'urandom'], [IOError],
         IOError),
        ('com', [('COM1',), ('COM2',), ('COM3',)], [],
         (['COM1', 'COM2', 'COM3'], '', True)),
        ('com:2', [('COM1',), ('COM2',), ('COM3',)], [],
         (['COM2'], '', False)),
        ('com:COM3', [('COM1',), ('COM2',), ('COM3',)], [],
         (['COM3'], '', False)),
        ('com:X', [('COM1',), ('COM2',), ('COM3',)], [],
         None),
        ('com_', [('COM1',), ('COM2',), ('COM3',)], [],
         None),
        ('', [('COM1',), ('COM2',), ('COM3',)], [],
         None),
    ])
    def test_find(self, mocker, path, nodes, tcgetattr, found):
        module = 'nfc.clf.transport'
        mocker.patch(module+'.open')
        mocker.patch(module+'.termios.tcgetattr').side_effect = tcgetattr
        mocker.patch(module+'.os.listdir').return_value = nodes
        mocker.patch(module+'.serial.tools.list_ports.comports') \
              .return_value = nodes
        if not found == IOError:
            assert nfc.clf.transport.TTY.find(path) == found
        else:
            with pytest.raises(IOError):
                nfc.clf.transport.TTY.find(path)

    @pytest.fixture()  # noqa: F811
    def serial(self, mocker):
        return mocker.patch('nfc.clf.transport.serial.Serial', autospec=True)

    @pytest.fixture()  # noqa: F811
    def tty(self, serial):
        tty = nfc.clf.transport.TTY('/dev/ttyUSB0')
        serial.assert_called_with('/dev/ttyUSB0', 115200, timeout=0.05)
        serial.return_value.port = '/dev/ttyUSB0'
        serial.return_value.baudrate = 115200
        return tty

    def test_manufacturer_name(self, serial, tty):
        assert tty.manufacturer_name is None

    def test_product_name(self, serial, tty):
        assert tty.product_name is None

    def test_port(self, serial, tty):
        assert tty.port == '/dev/ttyUSB0'
        tty.tty = None
        assert tty.port == ''

    def test_baudrate(self, serial, tty):
        assert tty.baudrate == 115200
        tty.baudrate = 9600
        assert tty.baudrate == 9600
        tty.tty = None
        assert tty.baudrate == 0
        tty.baudrate = 9600
        assert tty.baudrate == 0

    def test_read(self, serial, tty):
        serial.return_value.read.side_effect = [
            HEX('0000ff00ff00'),
        ]
        assert tty.read(0) == b'\x00\x00\xff\x00\xff\x00'
        assert serial.return_value.read.mock_calls == [call(6)]
        assert tty.tty.timeout == 0.05

        serial.return_value.read.reset_mock()
        serial.return_value.read.side_effect = [
            HEX('0000ff03fbd5'), HEX('01020000'),
        ]
        assert tty.read(51) == b'\x00\x00\xff\x03\xfb\xd5\x01\x02\x00\x00'
        assert serial.return_value.read.mock_calls == [call(6), call(4)]
        assert tty.tty.timeout == 0.051

        serial.return_value.read.reset_mock()
        serial.return_value.read.side_effect = [
            HEX('0000ffffff01'), HEX('01fed5'), bytearray(256) + HEX('2b00'),
        ]
        tty.read(100)
        assert serial.return_value.read.mock_calls == [
            call(6), call(3), call(258),
        ]
        assert tty.tty.timeout == 0.1

        serial.return_value.read.reset_mock()
        serial.return_value.read.side_effect = [HEX('')]
        with pytest.raises(IOError) as excinfo:
            tty.read(1100)
        assert excinfo.value.errno == errno.ETIMEDOUT
        assert serial.return_value.read.mock_calls == [call(6)]
        assert tty.tty.timeout == 1.1

        tty.tty = None
        assert tty.read(1000) is None

    def test_write(self, serial, tty):
        tty.write(b'12')
        serial.return_value.flushInput.assert_called_with()
        serial.return_value.write.assert_called_with(b'12')

        serial.return_value.write.side_effect = [
            nfc.clf.transport.serial.SerialTimeoutException,
        ]
        with pytest.raises(IOError) as excinfo:
            tty.write(b'12')
        assert excinfo.value.errno == errno.EIO

        tty.tty = None
        assert tty.write(b'12') is None

    def test_close(self, serial, tty):
        tty.close()
        serial.return_value.flushOutput.assert_called_with()
        serial.return_value.close.assert_called_with()
        assert tty.tty is None
        tty.close()


class TestUSB(object):
    class Endpoint(object):
        def __init__(self, addr, attr, maxp=64):
            self.addr, self.attr, self.maxp = addr, attr, maxp

        def getAddress(self):
            return self.addr

        def getAttributes(self):
            return self.attr

        def getMaxPacketSize(self):
            return self.maxp

    class Settings(object):
        def __init__(self, endpoints):
            self.endpoints = endpoints

        def iterEndpoints(self):
            return iter(self.endpoints)

    class Device(object):
        def __init__(self, vid, pid, bus, dev, settings=None):
            self.vid, self.pid, self.bus, self.dev = vid, pid, bus, dev
            self.settings = settings

        def iterSettings(self):
            return iter(self.settings)

        def getVendorID(self):
            return self.vid

        def getProductID(self):
            return self.pid

        def getBusNumber(self):
            return self.bus

        def getDeviceAddress(self):
            return self.dev

        def getManufacturer(self):
            return 'Vendor'

        def getProduct(self):
            return 'Product'

        def open(self):
            return MagicMock(spec=nfc.clf.transport.libusb.USBDeviceHandle)

    @pytest.fixture()  # noqa: F811
    def usb_context(self, mocker):
        libusb = 'nfc.clf.transport.libusb'
        return mocker.patch(libusb + '.USBContext', autospec=True)

    @pytest.mark.parametrize("path, devices, found", [
        ('tty', [], None),
        ('usb_', [], None),
        ('usb', [Device(1, 2, 3, 4), Device(5, 6, 7, 8)],
         [(1, 2, 3, 4), (5, 6, 7, 8)]),
        ('usb:0001', [Device(1, 2, 3, 4), Device(1, 6, 7, 8)],
         [(1, 2, 3, 4), (1, 6, 7, 8)]),
        ('usb:0001:0002', [Device(1, 2, 3, 4), Device(1, 6, 7, 8)],
         [(1, 2, 3, 4)]),
        ('usb:003', [Device(1, 2, 3, 4), Device(5, 6, 3, 8)],
         [(1, 2, 3, 4), (5, 6, 3, 8)]),
        ('usb:003:004', [Device(1, 2, 3, 4), Device(5, 6, 3, 8)],
         [(1, 2, 3, 4)]),
    ])
    def test_find(self, usb_context, path, devices, found):
        usb_context_enter = usb_context.return_value.__enter__
        usb_context_enter.return_value.getDeviceList.return_value = devices
        if not found == IOError:
            assert nfc.clf.transport.USB.find(path) == found
        else:
            with pytest.raises(IOError):
                nfc.clf.transport.USB.find(path)

    @pytest.mark.parametrize("vid, pid, bus, dev, settings", [
        (0x1000, 0x2000, 1, 2, []),
        (0x1000, 0x2000, 2, 1, []),
        (0x1000, 0x2000, 1, 2,
         [Settings([Endpoint(0x0004, 0x0001), Endpoint(0x0084, 0x0002)])]),
        (0x1000, 0x2000, 1, 2,
         [Settings([Endpoint(0x0004, 0x0002), Endpoint(0x0084, 0x0001)])]),
    ])
    def test_init_fail_attr(self, usb_context, vid, pid, bus, dev, settings):
        usb_context.return_value.getDeviceList.return_value = [
            self.Device(vid, pid, bus, dev, settings)
        ]
        with pytest.raises(IOError) as excinfo:
            nfc.clf.transport.USB(1, 2)
        assert excinfo.value.errno == errno.ENODEV

    def test_init_fail_name(self, usb_context):
        device = self.Device(0x1000, 0x2000, 1, 2, [
            self.Settings([
                self.Endpoint(0x0004, 0x0002),
                self.Endpoint(0x0084, 0x0002),
            ])
        ])
        device.getManufacturer = MagicMock()
        device.getManufacturer.side_effect = [
            nfc.clf.transport.libusb.USBErrorIO
        ]
        usb_context.return_value.getDeviceList.return_value = [device]
        usb = nfc.clf.transport.USB(1, 2)
        assert usb.manufacturer_name is None
        assert usb.product_name is None

    def test_init_fail_open(self, usb_context):
        device = self.Device(0x1000, 0x2000, 1, 2, [
            self.Settings([
                self.Endpoint(0x0004, 0x0002),
                self.Endpoint(0x0084, 0x0002),
            ])
        ])
        device.open = MagicMock()
        device.open.side_effect = [
            nfc.clf.transport.libusb.USBErrorAccess,
            nfc.clf.transport.libusb.USBErrorBusy,
            nfc.clf.transport.libusb.USBErrorNoDevice,
        ]
        usb_context.return_value.getDeviceList.return_value = [device]

        with pytest.raises(IOError) as excinfo:
            nfc.clf.transport.USB(1, 2)
        assert excinfo.value.errno == errno.EACCES

        with pytest.raises(IOError) as excinfo:
            nfc.clf.transport.USB(1, 2)
        assert excinfo.value.errno == errno.EBUSY

        with pytest.raises(IOError) as excinfo:
            nfc.clf.transport.USB(1, 2)
        assert excinfo.value.errno == errno.ENODEV

    @pytest.fixture()  # noqa: F811
    def usb(self, usb_context):
        usb_context.return_value.getDeviceList.return_value = [
            self.Device(0x1000, 0x2000, 1, 2, [
                self.Settings([
                    self.Endpoint(0x0004, 0x0002),
                    self.Endpoint(0x0084, 0x0002),
                    self.Endpoint(0x1004, 0x0002),
                    self.Endpoint(0x1084, 0x0002),
                ])
            ])
        ]
        usb = nfc.clf.transport.USB(1, 2)
        return usb

    def test_manufacturer_name(self, usb):
        assert usb.manufacturer_name == "Vendor"

    def test_product_name(self, usb):
        assert usb.product_name == "Product"

    def test_read(self, usb):
        usb.usb_dev.bulkRead.side_effect = [
            b'12',
            b'34',
            nfc.clf.transport.libusb.USBErrorTimeout,
            nfc.clf.transport.libusb.USBErrorNoDevice,
            nfc.clf.transport.libusb.USBError,
            b'',
        ]
        assert usb.read() == b'12'
        usb.usb_dev.bulkRead.assert_called_with(0x84, 300, 0)

        assert usb.read(100) == b'34'
        usb.usb_dev.bulkRead.assert_called_with(0x84, 300, 100)

        with pytest.raises(IOError) as excinfo:
            usb.read()
        assert excinfo.value.errno == errno.ETIMEDOUT

        with pytest.raises(IOError) as excinfo:
            usb.read()
        assert excinfo.value.errno == errno.ENODEV

        with pytest.raises(IOError) as excinfo:
            usb.read()
        assert excinfo.value.errno == errno.EIO

        with pytest.raises(IOError) as excinfo:
            usb.read()
        assert excinfo.value.errno == errno.EIO

        usb.usb_inp = None
        assert usb.read() is None

    def test_write(self, usb):
        usb.write(b'12')
        usb.usb_dev.bulkWrite.assert_called_with(0x04, b'12', 0)

        usb.write(b'12', 100)
        usb.usb_dev.bulkWrite.assert_called_with(0x04, b'12', 100)

        usb.write(64 * b'1', 100)
        usb.usb_dev.bulkWrite.assert_has_calls([
            call(0x04, 64 * b'1', 100),
            call(0x04, b'', 100),
        ])

        usb.usb_dev.bulkWrite.side_effect = [
            nfc.clf.transport.libusb.USBErrorTimeout,
            nfc.clf.transport.libusb.USBErrorNoDevice,
            nfc.clf.transport.libusb.USBError,
        ]
        with pytest.raises(IOError) as excinfo:
            usb.write(b'12')
        assert excinfo.value.errno == errno.ETIMEDOUT

        with pytest.raises(IOError) as excinfo:
            usb.write(b'12')
        assert excinfo.value.errno == errno.ENODEV

        with pytest.raises(IOError) as excinfo:
            usb.write(b'12')
        assert excinfo.value.errno == errno.EIO

        usb.usb_out = None
        assert usb.write(b'12') is None
