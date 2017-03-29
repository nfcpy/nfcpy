# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.transport

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call
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
        ('comport', [('COM1',), ('COM2',), ('COM3',)], [],
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
