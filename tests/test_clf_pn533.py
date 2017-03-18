# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.pn533

import sys
import pytest
from pytest_mock import mocker  # noqa: F401
from mock import Mock, call
# from binascii import hexlify

import base_clf_pn53x
from base_clf_pn53x import CMD, RSP, ACK, NAK, ERR, HEX  # noqa: F401

import logging
logging.basicConfig(level=logging.DEBUG-1)  # WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.pn533").setLevel(logging_level)

sys.modules['usb1'] = Mock  # fake usb1 for testing on travis-ci


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
        chipset.transport.read.side_effect = [ACK, response]
        assert chipset.get_general_status() == result
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        assert chipset.transport.write.mock_calls == [call(CMD('04'))]

    @pytest.mark.parametrize("args, command, response, value", [
        ((0x0102,), '06 0102', '07 00 AA', 0xAA),
        (("CIU_TMode",), '06 631A', '07 00 BB', 0xBB),
        ((0x0102, "CIU_TMode"), '06 0102631A', '07 00 AABB', [0xAA, 0xBB]),
    ])
    def test_read_register(self, chipset, args, command, response, value):
        chipset.transport.read.side_effect = [ACK, RSP(response)]
        assert chipset.read_register(*args) == value
        chipset.transport.read.side_effect = [ACK, RSP('07 01')]
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
        chipset.transport.read.side_effect = [ACK, RSP('09 00')]
        assert chipset.write_register(*args) is None
        chipset.transport.read.side_effect = [ACK, RSP('09 01')]
        with pytest.raises(nfc.clf.pn533.Chipset.Error) as excinfo:
            chipset.write_register(*args)
        assert excinfo.value.errno == 1
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(250)]
        assert chipset.transport.write.mock_calls == 2 * [call(CMD(command))]
