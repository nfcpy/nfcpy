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

import logging
logging.basicConfig(level=logging.DEBUG-1)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.transport").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


class TestTTY(object):
    @pytest.mark.parametrize("path, avail, found", [  # noqa: F811
        ('tty', [], ([], '', True)),
        ('tty', ['cu.usbserial-1'], (['/dev/cu.usbserial-1'], '', True)),
        ('tty', ['ttyUSB1'], (['/dev/ttyUSB1'], '', True)),
        ('tty', ['ttyAMA1'], (['/dev/ttyAMA1'], '', True)),
        ('tty', ['ttyACM1'], (['/dev/ttyACM1'], '', True)),
        ('tty', ['ttyS1'], (['/dev/ttyS1'], '', True)),
        ('tty', ['ttyS0', 'ttyS1'], (['/dev/ttyS0', '/dev/ttyS1'], '', True)),
        ('tty::driver', ['ttyS1'], (['/dev/ttyS1'], 'driver', True)),
        ('tty:abcd', [], None),
        ('ttz', [], None),
    ])
    def test_find_tty_any(self, mocker, path, avail, found):
        tty_nodes = list(sorted([
            'cu.usbserial-0', 'cu.usbserial-1', 'cu.usbserial-FTSI7O',
            'ttyACM0', 'ttyACM1', 'ttyACM10', 'ttyACM2',
            'ttyAMA0', 'ttyAMA1', 'ttyAMA10', 'ttyAMA2',
            'ttyUSB0', 'ttyUSB1', 'ttyUSB10', 'ttyUSB2',
            'ttyS0', 'ttyS1', 'ttyS10', 'ttyS2'], key=lambda d: (len(d), d)))
        dev_nodes = (['console', 'stderr', 'stdin', 'stdout', 'urandom'] +
                     tty_nodes + ['tty', 'tty0', 'tty1', 'tty10', 'tty2'])
        mocker.patch('nfc.clf.transport.open').return_value = True
        mocker.patch('nfc.clf.transport.termios.tcgetattr').side_effect = [
            (termios.error, [])[dev in avail] for dev in tty_nodes]
        mocker.patch('nfc.clf.transport.os.listdir').return_value = dev_nodes
        assert nfc.clf.transport.TTY.find(path) == found

    def test_find_tty_err(self, mocker):  # noqa: F811
        mod = 'nfc.clf.transport'
        mocker.patch(mod + '.open').return_value = True
        mocker.patch(mod + '.termios.tcgetattr').side_effect = IOError
        mocker.patch(mod + '.os.listdir').return_value = ['ttyS0', 'ttyS1']
        assert nfc.clf.transport.TTY.find('tty:S') == ([], '', True)
        with pytest.raises(IOError):
            assert nfc.clf.transport.TTY.find('tty:S0')
        with pytest.raises(IOError):
            assert nfc.clf.transport.TTY.find('tty:S1')

    @pytest.mark.parametrize("path, avail, found", [  # noqa: F811
        ('tty:S', [False, False, False, False], ([], '', True)),
        ('tty:S', [False, True, False, False], (['/dev/ttyS1'], '', True)),
        ('tty:S1', [True], (['/dev/ttyS1'], '', False)),
        ('tty:S10', [True], (['/dev/ttyS10'], '', False)),
        ('tty:S', [True, False, True, False],
         (['/dev/ttyS0', '/dev/ttyS2'], '', True)),
        ('tty:S:driver', [False, False, False, True],
         (['/dev/ttyS10'], 'driver', True)),
        ('tty:S:driver', [False, True, False, True],
         (['/dev/ttyS1', '/dev/ttyS10'], 'driver', True)),
        ('tty:ttyS1', [True], (['/dev/ttyS1'], '', False)),
    ])
    def test_find_tty_ser(self, mocker, path, avail, found):
        tty_nodes = ['ttyS0', 'ttyS1', 'ttyS2', 'ttyS10']
        mocker.patch('nfc.clf.transport.open').return_value = True
        mocker.patch('nfc.clf.transport.termios.tcgetattr').side_effect = [
            ([] if is_avail else termios.error) for is_avail in avail]
        mocker.patch('nfc.clf.transport.os.listdir').return_value = tty_nodes
        assert nfc.clf.transport.TTY.find(path) == found

    @pytest.mark.parametrize("path, avail, found", [  # noqa: F811
        ('tty:ACM', [False, False, False, False], ([], '', True)),
        ('tty:ACM', [False, True, False, False], (['/dev/ttyACM1'], '', True)),
        ('tty:ACM1', [True], (['/dev/ttyACM1'], '', False)),
        ('tty:ACM10', [True], (['/dev/ttyACM10'], '', False)),
        ('tty:ACM1:driver', [True], (['/dev/ttyACM1'], 'driver', False)),
        ('tty:ACM', [True, False, True, False],
         (['/dev/ttyACM0', '/dev/ttyACM2'], '', True)),
        ('tty:ACM:driver', [False, True, False, False],
         (['/dev/ttyACM1'], 'driver', True)),
        ('tty:ttyACM1', [True], (['/dev/ttyACM1'], '', False)),
    ])
    def test_find_tty_acm(self, mocker, path, avail, found):
        tty_nodes = ['ttyACM0', 'ttyACM1', 'ttyACM2', 'ttyACM10']
        mocker.patch('nfc.clf.transport.open').return_value = True
        mocker.patch('nfc.clf.transport.termios.tcgetattr').side_effect = [
            ([] if is_avail else termios.error) for is_avail in avail]
        mocker.patch('nfc.clf.transport.os.listdir').return_value = tty_nodes
        assert nfc.clf.transport.TTY.find(path) == found

    @pytest.mark.parametrize("path, avail, found", [  # noqa: F811
        ('tty:AMA', [False, False, False, False], ([], '', True)),
        ('tty:AMA', [False, True, False, False], (['/dev/ttyAMA1'], '', True)),
        ('tty:AMA1', [True], (['/dev/ttyAMA1'], '', False)),
        ('tty:AMA10', [True], (['/dev/ttyAMA10'], '', False)),
        ('tty:AMA1:driver', [True], (['/dev/ttyAMA1'], 'driver', False)),
        ('tty:AMA', [True, False, True, False],
         (['/dev/ttyAMA0', '/dev/ttyAMA2'], '', True)),
        ('tty:AMA:driver', [False, True, False, False],
         (['/dev/ttyAMA1'], 'driver', True)),
        ('tty:ttyAMA1', [True], (['/dev/ttyAMA1'], '', False)),
    ])
    def test_find_tty_ama(self, mocker, path, avail, found):
        tty_nodes = ['ttyAMA0', 'ttyAMA1', 'ttyAMA2', 'ttyAMA10']
        mocker.patch('nfc.clf.transport.open').return_value = True
        mocker.patch('nfc.clf.transport.termios.tcgetattr').side_effect = [
            ([] if is_avail else termios.error) for is_avail in avail]
        mocker.patch('nfc.clf.transport.os.listdir').return_value = tty_nodes
        assert nfc.clf.transport.TTY.find(path) == found

    @pytest.mark.parametrize("path, avail, found", [  # noqa: F811
        ('tty:USB', [False, False, False, False], ([], '', True)),
        ('tty:USB', [False, True, False, False], (['/dev/ttyUSB1'], '', True)),
        ('tty:USB1', [True], (['/dev/ttyUSB1'], '', False)),
        ('tty:USB10', [True], (['/dev/ttyUSB10'], '', False)),
        ('tty:USB1:driver', [True], (['/dev/ttyUSB1'], 'driver', False)),
        ('tty:USB', [True, False, True, False],
         (['/dev/ttyUSB0', '/dev/ttyUSB2'], '', True)),
        ('tty:USB:driver', [False, True, False, False],
         (['/dev/ttyUSB1'], 'driver', True)),
        ('tty:ttyUSB1', [True], (['/dev/ttyUSB1'], '', False)),
    ])
    def test_find_tty_usb(self, mocker, path, avail, found):
        tty_nodes = ['ttyUSB0', 'ttyUSB1', 'ttyUSB2', 'ttyUSB10']
        mocker.patch('nfc.clf.transport.open').return_value = True
        mocker.patch('nfc.clf.transport.termios.tcgetattr').side_effect = [
            ([] if is_avail else termios.error) for is_avail in avail]
        mocker.patch('nfc.clf.transport.os.listdir').return_value = tty_nodes
        assert nfc.clf.transport.TTY.find(path) == found

    @pytest.mark.parametrize("path, avail, found", [  # noqa: F811
        ('tty:usbserial', [False, False, False], ([], '', True)),
        ('tty:usbserial', [False, True, False],
         (['/dev/cu.usbserial-1'], '', True)),
        ('tty:usbserial', [True, True, False],
         (['/dev/cu.usbserial-0', '/dev/cu.usbserial-1'], '', True)),
        ('tty:usbserial-1', [True], (['/dev/cu.usbserial-1'], '', False)),
        ('tty:usbserial-FTSI7X', [True],
         (['/dev/cu.usbserial-FTSI7X'], '', False)),
        ('tty:usbserial:driver', [False, True, False],
         (['/dev/cu.usbserial-1'], 'driver', True)),
    ])
    def test_find_tty_mac(self, mocker, path, avail, found):
        tty_nodes = 'cu.usbserial-0', 'cu.usbserial-1', 'cu.usbserial-FTSI7X',
        mocker.patch('nfc.clf.transport.open').return_value = True
        mocker.patch('nfc.clf.transport.termios.tcgetattr').side_effect = [
            ([] if is_avail else termios.error) for is_avail in avail]
        mocker.patch('nfc.clf.transport.os.listdir').return_value = tty_nodes
        assert nfc.clf.transport.TTY.find(path) == found

    @pytest.mark.parametrize("path, found", [  # noqa: F811
        ('com', (['COM1', 'COM2', 'COM3'], '', True)),
        ('com:2', (['COM2'], '', False)),
        ('com:2:driver', (['COM2'], 'driver', False)),
        ('com:COM3', (['COM3'], '', False)),
        ('com:COM3:driver', (['COM3'], 'driver', False)),
        ('com:X', None),
    ])
    def test_find_com_port(self, mocker, path, found):
        mocker.patch('nfc.clf.transport.serial.tools.list_ports.comports') \
              .return_value = [('COM1',), ('COM2',), ('COM3',)]
        assert nfc.clf.transport.TTY.find(path) == found

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
