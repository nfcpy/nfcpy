# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.device

import sys
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.DEBUG)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.device").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()  # noqa: F811
def device(mocker):
    mocker.patch('nfc.clf.device.Device.__init__').return_value = None
    return nfc.clf.device.Device()


class TestDevice(object):
    def test_init(self):
        with pytest.raises(NotImplementedError):
            nfc.clf.device.Device()

    def test_close(self, device):
        with pytest.raises(NotImplementedError):
            device.close()

    def test_str(self, device):
        device._chipset_name = "IC"
        device._path = 'usb:001:001'
        assert device.vendor_name == ''
        assert device.product_name == ''
        assert str(device) == "IC at usb:001:001"
        device._vendor_name = "Vendor"
        device._device_name = "Device"
        assert device.vendor_name == 'Vendor'
        assert device.product_name == 'Device'
        assert str(device) == "Vendor Device IC at usb:001:001"

    def test_mute(self, device):
        with pytest.raises(NotImplementedError):
            device.mute()

    def test_sense_tta(self, device):
        with pytest.raises(NotImplementedError):
            device.sense_tta(nfc.clf.RemoteTarget('106A'))

    def test_sense_ttb(self, device):
        with pytest.raises(NotImplementedError):
            device.sense_ttb(nfc.clf.RemoteTarget('106B'))

    def test_sense_ttf(self, device):
        with pytest.raises(NotImplementedError):
            device.sense_ttf(nfc.clf.RemoteTarget('212F'))

    def test_sense_dep(self, device):
        with pytest.raises(NotImplementedError):
            device.sense_dep(nfc.clf.RemoteTarget('106A'))

    def test_listen_tta(self, device):
        with pytest.raises(NotImplementedError):
            device.listen_tta(nfc.clf.LocalTarget(), 1.0)

    def test_listen_ttb(self, device):
        with pytest.raises(NotImplementedError):
            device.listen_ttb(nfc.clf.LocalTarget(), 1.0)

    def test_listen_ttf(self, device):
        with pytest.raises(NotImplementedError):
            device.listen_ttf(nfc.clf.LocalTarget(), 1.0)

    def test_listen_dep(self, device):
        with pytest.raises(NotImplementedError):
            device.listen_dep(nfc.clf.LocalTarget(), 1.0)

    def test_send_cmd_recv_rsp(self, device):
        with pytest.raises(NotImplementedError):
            device.send_cmd_recv_rsp(nfc.clf.RemoteTarget('106A'), b'', 1.0)

    def test_send_rsp_recv_cmd(self, device):
        with pytest.raises(NotImplementedError):
            device.send_rsp_recv_cmd(nfc.clf.LocalTarget(), b'', 1.0)

    def test_get_max_send_data_size(self, device):
        with pytest.raises(NotImplementedError):
            device.get_max_send_data_size(nfc.clf.LocalTarget())

    def test_get_max_recv_data_size(self, device):
        with pytest.raises(NotImplementedError):
            device.get_max_recv_data_size(nfc.clf.LocalTarget())

    def test_turn_on_led_and_buzzer(self, device):
        assert device.turn_on_led_and_buzzer() is None

    def test_turn_off_led_and_buzzer(self, device):
        assert device.turn_off_led_and_buzzer() is None

    def test_add_crc_a(self, device):
        assert device.add_crc_a(HEX('0000')) == HEX('0000A01E')

    def test_check_crc_a(self, device):
        assert device.check_crc_a(HEX('0000A01E')) is True

    def test_add_crc_b(self, device):
        assert device.add_crc_b(HEX('0000')) == HEX('0000470F')

    def test_check_crc_b(self, device):
        assert device.check_crc_b(HEX('0000470F')) is True


@pytest.mark.parametrize("found, instance_type", [  # noqa: F811
    (None, type(None)),
    (list(), type(None)),
    ([(0x0000, 0x0000, 0, 0)], type(None)),
    ([(0x054c, 0x0193, 1, 2)], nfc.clf.device.Device),
])
def test_connect_usb(mocker, device, found, instance_type):
    sys_platform, sys.platform = sys.platform, 'testing'
    mocker.patch('nfc.clf.transport.USB')
    mocker.patch('nfc.clf.transport.USB.find').return_value = found
    mocker.patch('nfc.clf.transport.TTY')
    mocker.patch('nfc.clf.transport.TTY.find').return_value = None
    mocker.patch('nfc.clf.pn531.init').return_value = device
    device = nfc.clf.device.connect('usb')
    assert isinstance(device, instance_type)
    sys.platform = sys_platform


def test_connect_usb_driver_init_error(mocker):  # noqa: F811
    found = [(0x054c, 0x0193, 1, 2)]
    sys_platform, sys.platform = sys.platform, 'testing'
    mocker.patch('nfc.clf.transport.USB')
    mocker.patch('nfc.clf.transport.USB.find').return_value = found
    mocker.patch('nfc.clf.transport.TTY')
    mocker.patch('nfc.clf.transport.TTY.find').return_value = None
    mocker.patch('nfc.clf.pn531.init').side_effect = IOError()
    assert nfc.clf.device.connect('usb') is None
    with pytest.raises(IOError):
        nfc.clf.device.connect('usb:001:002')
    sys.platform = sys_platform


@pytest.mark.parametrize("access", [  # noqa: F811
    True, False
])
def test_connect_usb_linux_check_access(mocker, device, access):
    found = [(0x054c, 0x0193, 1, 2)]
    sys_platform, sys.platform = sys.platform, 'linux'
    mocker.patch('nfc.clf.transport.USB')
    mocker.patch('nfc.clf.transport.USB.find').return_value = found
    mocker.patch('nfc.clf.transport.TTY')
    mocker.patch('nfc.clf.transport.TTY.find').return_value = None
    mocker.patch('nfc.clf.pn531.init').return_value = device
    mocker.patch('os.access').return_value = access
    device = nfc.clf.device.connect('usb')
    assert isinstance(device, nfc.clf.device.Device) == access
    if access is False:
        with pytest.raises(IOError):
            nfc.clf.device.connect('usb:001:002')
    sys.platform = sys_platform


@pytest.mark.parametrize("found, result_type", [  # noqa: F811
    (None, type(None)),
    (([], None, True), type(None)),
    ((['/dev/ttyS0'], 'pn532', True), nfc.clf.device.Device),
])
def test_connect_tty(mocker, device, found, result_type):
    sys_platform, sys.platform = sys.platform, 'testing'
    mocker.patch('nfc.clf.transport.USB')
    mocker.patch('nfc.clf.transport.USB.find').return_value = None
    mocker.patch('nfc.clf.transport.TTY')
    mocker.patch('nfc.clf.transport.TTY.find').return_value = found
    mocker.patch('nfc.clf.pn532.init').return_value = device
    device = nfc.clf.device.connect('tty')
    assert isinstance(device, result_type)
    sys.platform = sys_platform


def test_connect_tty_driver_init_error(mocker):  # noqa: F811
    found = (['/dev/ttyS0'], 'pn532', True)
    sys_platform, sys.platform = sys.platform, 'testing'
    mocker.patch('nfc.clf.transport.USB')
    mocker.patch('nfc.clf.transport.USB.find').return_value = None
    mocker.patch('nfc.clf.transport.TTY')
    mocker.patch('nfc.clf.transport.TTY.find').return_value = found
    mocker.patch('nfc.clf.pn532.init').side_effect = IOError()
    assert nfc.clf.device.connect('tty') is None
    found = (['/dev/ttyS0'], 'pn532', False)
    mocker.patch('nfc.clf.transport.TTY.find').return_value = found
    with pytest.raises(IOError):
        nfc.clf.device.connect('tty')
    sys.platform = sys_platform


def test_connect_udp(mocker, device):  # noqa: F811
    mocker.patch('nfc.clf.transport.USB')
    mocker.patch('nfc.clf.transport.USB.find').return_value = None
    mocker.patch('nfc.clf.transport.TTY')
    mocker.patch('nfc.clf.transport.TTY.find').return_value = None
    mocker.patch('nfc.clf.udp.init').return_value = device
    device = nfc.clf.device.connect('udp')
    assert isinstance(device, nfc.clf.device.Device)
    assert device.path == "udp:localhost:54321"
    device = nfc.clf.device.connect('udp:remotehost:12345')
    assert isinstance(device, nfc.clf.device.Device)
    assert device.path == "udp:remotehost:12345"
