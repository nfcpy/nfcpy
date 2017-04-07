# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.udp

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call

import logging
logging.basicConfig(level=logging.DEBUG-1)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.udp").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


def FRAME(brty, hexstr):
    hexstr = hexstr.replace(' ', '')
    return ('{:s} {:s}'.format(brty, hexstr), ('127.0.0.1', 54321))


def CMD106A(hexstr):
    return FRAME('106A', hexstr)


def RSP106A(hexstr):
    return FRAME('106A', hexstr)


def CMD106B(hexstr):
    return FRAME('106B', hexstr)


def RSP106B(hexstr):
    return FRAME('106B', hexstr)


def CMD212F(hexstr):
    return FRAME('212F', hexstr)


def RSP212F(hexstr):
    return FRAME('212F', hexstr)


def CMD424F(hexstr):
    return FRAME('424F', hexstr)


def RSP424F(hexstr):
    return FRAME('424F', hexstr)


def CALLS(exchange):
    return [call(*cmd) for cmd, rsp in exchange]


@pytest.fixture()  # noqa: F811
def device(mocker):
    nameinfo = ('127.0.0.1', '54321')
    mocker.patch('nfc.clf.udp.select.select').return_value = ([1], [], [])
    mocker.patch('nfc.clf.udp.socket.getnameinfo').return_value = nameinfo
    mocker.patch('nfc.clf.udp.socket.socket')
    device = nfc.clf.udp.Device('localhost', 54321)
    assert device.addr == ('127.0.0.1', 54321)
    device._device_name = "IP-Stack"
    device._chipset_name = "UDP"
    return device


class TestDevice(object):
    def test_init(self, device):
        pass

    def test_close(self, device):
        assert device.close() is None

    #
    # SENSE
    #

    def test_sense_tta_with_no_target_found(self, device):
        device.socket.sendto.side_effect = [len(CMD106A('26')[0])]
        device.socket.recvfrom.side_effect = [nfc.clf.TimeoutError]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        device.socket.sendto.assert_called_once_with(*CMD106A('26'))

    def test_sense_tta_with_tt1_target_found(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('000C')),
            (CMD106A('78000000000000'), RSP106A('110001020304')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '106A'
        assert target.rid_res == HEX('110001020304')
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_with_proprietary_target(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('0000')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('0000')
        assert target.rid_res is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_find_tt1_but_receive_error(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('000C')),
            (CMD106A('78000000000000'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_find_tt2_target_uid_4(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('01020304')),
            (CMD106A('937001020304'), RSP106A('00')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304')
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_find_tt2_target_uid_7(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('88010203')),
            (CMD106A('937088010203'), RSP106A('04')),
            (CMD106A('9520'), RSP106A('04050607')),
            (CMD106A('957004050607'), RSP106A('00')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304050607')
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_find_tt2_target_uid_10(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('88010203')),
            (CMD106A('937088010203'), RSP106A('04')),
            (CMD106A('9520'), RSP106A('88040506')),
            (CMD106A('957088040506'), RSP106A('04')),
            (CMD106A('9720'), RSP106A('07080910')),
            (CMD106A('977007080910'), RSP106A('00')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304050607080910')
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_find_tt2_excessive_uid(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('88010203')),
            (CMD106A('937088010203'), RSP106A('04')),
            (CMD106A('9520'), RSP106A('88040506')),
            (CMD106A('957088040506'), RSP106A('04')),
            (CMD106A('9720'), RSP106A('07080910')),
            (CMD106A('977007080910'), RSP106A('04')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_tt2_request_uid_4(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('93700102030404'), RSP106A('00')),
        ]
        uid = '01020304'
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_tt2_request_uid_7(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('93708801020388'), RSP106A('04')),
            (CMD106A('95700405060700'), RSP106A('00')),
        ]
        uid = '01020304050607'
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_tt2_request_uid_10(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('93708801020388'), RSP106A('04')),
            (CMD106A('9570880405068f'), RSP106A('04')),
            (CMD106A('97700708091016'), RSP106A('00')),
        ]
        uid = '01020304050607080910'
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_find_tt2_but_receive_error(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_tta_with_invalid_target(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_tta(nfc.clf.RemoteTarget('106B'))
        assert str(excinfo.value) == "unsupported bitrate 106B"

    def test_sense_ttb_with_no_target_found(self, device):
        device.socket.sendto.side_effect = [len(CMD106B('050010')[0])]
        device.socket.recvfrom.side_effect = [nfc.clf.TimeoutError]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        device.socket.sendto.assert_called_once_with(*CMD106B('050010'))

    def test_sense_ttb_with_tt4_target_found(self, device):
        sensb_res = '50E8253EEC00000011008185'
        exchange = [(CMD106B('050010'), RSP106B(sensb_res))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttb(nfc.clf.RemoteTarget('106B'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.sensb_res == HEX(sensb_res)
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_ttb_with_receive_errors(self, device):
        exchange = [(CMD106B('050010'), RSP106B(''))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    @pytest.mark.parametrize('sensb_res', [
        '51E8253EEC00000011008185', '50E8253EEC000000110081',
    ])
    def test_sense_ttb_with_response_errors(self, device, sensb_res):
        exchange = [(CMD106B('050010'), RSP106B(sensb_res))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_ttb_with_invalid_target(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_ttb(nfc.clf.RemoteTarget('106A'))
        assert str(excinfo.value) == "unsupported bitrate 106A"

    def test_sense_ttf_with_no_target_found(self, device):
        device.socket.sendto.side_effect = [len(CMD212F('0600ffff0100')[0])]
        device.socket.recvfrom.side_effect = [nfc.clf.TimeoutError]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        device.socket.sendto.assert_called_once_with(*CMD212F('0600ffff0100'))

    def test_sense_ttf_with_tt3_target_found(self, device):
        sensf_res = '14 01 01010701260cca02 0f0d23042f7783ff 12fc'
        exchange = [(CMD212F('0600ffff0100'), RSP212F(sensf_res))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttf(nfc.clf.RemoteTarget('212F'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '212F'
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    @pytest.mark.parametrize("tg, sensf_req, sensf_res", [
        (nfc.clf.RemoteTarget('212F', sensf_req=None),
         '0600ffff0100', '140101010701260cca020f0d23042f7783ff12fc'),
        (nfc.clf.RemoteTarget('212F', sensf_req=HEX('00ffff0100')),
         '0600ffff0100', '140101010701260cca020f0d23042f7783ff12fc'),
        (nfc.clf.RemoteTarget('212F', sensf_req=HEX('00ffff0000')),
         '0600ffff0000', '120101010701260cca020f0d23042f7783ff'),
    ])
    def test_sense_ttf_with_sensf_req(self, device, tg, sensf_req, sensf_res):
        exchange = [(CMD212F(sensf_req), RSP212F(sensf_res))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttf(tg)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == tg.brty
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    @pytest.mark.parametrize("brty, rf_settings", [
        ('212F', '01010f01'),
        ('424F', '01020f02'),
    ])
    def test_sense_ttf_with_bitrate_type(self, device, brty, rf_settings):
        sensf_res = '14 01 01010701260cca020f0d23042f7783ff12fc'
        exchange = [(FRAME(brty, '0600ffff0100'), FRAME(brty, sensf_res))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttf(nfc.clf.RemoteTarget(brty))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == brty
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_ttf_with_receive_errors(self, device):
        exchange = [(CMD212F('0600ffff0100'), RSP212F(''))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    @pytest.mark.parametrize("sensf_res", [
        '110101010701260cca020f0d23042f7783',
        '130101010701260cca020f0d23042f7783ff12fc',
        '140201010701260cca020f0d23042f7783ff12fc',
    ])
    def test_sense_ttf_with_response_errors(self, device, sensf_res):
        exchange = [(CMD212F('0600ffff0100'), RSP212F(sensf_res))]
        device.socket.sendto.side_effect = [len(cmd[0]) for cmd, _ in exchange]
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.socket.sendto.mock_calls == CALLS(exchange)

    def test_sense_ttf_with_invalid_target(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_ttf(nfc.clf.RemoteTarget('106A'))
        assert str(excinfo.value) == "unsupported bitrate 106A"

    def test_sense_dep_is_not_supported(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_dep(nfc.clf.RemoteTarget('106A'))
        assert str(excinfo.value) == (
            "IP-Stack UDP at 127.0.0.1:54321 does not "
            "support sense for active DEP Target")
