# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.pn532

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
