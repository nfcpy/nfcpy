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


def CMD_CALLS(exchange):
    return [call(*cmd) for cmd, rsp in exchange]


def RSP_CALLS(exchange):
    return [call(*rsp) for cmd, rsp in exchange]


def CMD_SIZES(exchange):
    return [len(cmd[0]) for cmd, rsp in exchange]


def RSP_SIZES(exchange):
    return [len(rsp[0]) for cmd, rsp in exchange]


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
    yield device
    device.close()


def test_init(mocker):  # noqa: F811
    nameinfo = ('127.0.0.1', '54321')
    mocker.patch('nfc.clf.udp.select.select').return_value = ([1], [], [])
    mocker.patch('nfc.clf.udp.socket.getnameinfo').return_value = nameinfo
    mocker.patch('nfc.clf.udp.socket.socket')
    device = nfc.clf.udp.init('localhost', 54321)
    assert isinstance(device, nfc.clf.udp.Device)


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
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '106A'
        assert target.rid_res == HEX('110001020304')
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)
        return target

    def test_sense_tta_with_proprietary_target(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('0000')),
        ]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('0000')
        assert target.rid_res is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_tta_find_tt1_but_receive_error(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('000C')),
            (CMD106A('78000000000000'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_tta_find_tt2_target_uid_4(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('01020304')),
            (CMD106A('937001020304'), RSP106A('00')),
        ]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '106A'
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304')
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_tta_find_tt2_target_uid_7(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('88010203')),
            (CMD106A('937088010203'), RSP106A('04')),
            (CMD106A('9520'), RSP106A('04050607')),
            (CMD106A('957004050607'), RSP106A('00')),
        ]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304050607')
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

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
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX('01020304050607080910')
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

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
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_tta_tt2_request_uid_4(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('93700102030404'), RSP106A('00')),
        ]
        uid = '01020304'
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_tta_tt2_request_uid_7(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('93708801020388'), RSP106A('04')),
            (CMD106A('95700405060700'), RSP106A('00')),
        ]
        uid = '01020304050607'
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_tta_tt2_request_uid_10(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('93708801020388'), RSP106A('04')),
            (CMD106A('9570880405068f'), RSP106A('04')),
            (CMD106A('97700708091016'), RSP106A('00')),
        ]
        uid = '01020304050607080910'
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = nfc.clf.RemoteTarget('106A', sel_req=HEX(uid))
        target = device.sense_tta(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == "106A"
        assert target.sens_res == HEX('4400')
        assert target.sdd_res == HEX(uid)
        assert target.sel_res == HEX('00')
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_tta_find_tt2_but_receive_error(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

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
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttb(nfc.clf.RemoteTarget('106B'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.sensb_res == HEX(sensb_res)
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_ttb_with_receive_errors(self, device):
        exchange = [(CMD106B('050010'), RSP106B(''))]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    @pytest.mark.parametrize('sensb_res', [
        '51E8253EEC00000011008185', '50E8253EEC000000110081',
    ])
    def test_sense_ttb_with_response_errors(self, device, sensb_res):
        exchange = [(CMD106B('050010'), RSP106B(sensb_res))]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttb(nfc.clf.RemoteTarget('106B')) is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

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
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttf(nfc.clf.RemoteTarget('212F'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '212F'
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

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
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttf(tg)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == tg.brty
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    @pytest.mark.parametrize("brty, rf_settings", [
        ('212F', '01010f01'),
        ('424F', '01020f02'),
    ])
    def test_sense_ttf_with_bitrate_type(self, device, brty, rf_settings):
        sensf_res = '14 01 01010701260cca020f0d23042f7783ff12fc'
        exchange = [(FRAME(brty, '0600ffff0100'), FRAME(brty, sensf_res))]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        target = device.sense_ttf(nfc.clf.RemoteTarget(brty))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == brty
        assert target.sensf_res == HEX(sensf_res)[1:]
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    def test_sense_ttf_with_receive_errors(self, device):
        exchange = [(CMD212F('0600ffff0100'), RSP212F(''))]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

    @pytest.mark.parametrize("sensf_res", [
        '110101010701260cca020f0d23042f7783',
        '130101010701260cca020f0d23042f7783ff12fc',
        '140201010701260cca020f0d23042f7783ff12fc',
    ])
    def test_sense_ttf_with_response_errors(self, device, sensf_res):
        exchange = [(CMD212F('0600ffff0100'), RSP212F(sensf_res))]
        device.socket.sendto.side_effect = CMD_SIZES(exchange)
        device.socket.recvfrom.side_effect = [rsp for cmd, rsp in exchange]
        assert device.sense_ttf(nfc.clf.RemoteTarget('212F')) is None
        assert device.socket.sendto.mock_calls == CMD_CALLS(exchange)

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

    #
    # LISTEN
    #

    def test_listen_tta_tt2_uid4_activated(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('0400')),
            (CMD106A('9320'), RSP106A('3132333404')),
            (CMD106A('93703132333404'), RSP106A('00')),
            (CMD106A('3000'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = RSP_SIZES(exchange[:-1])
        device.socket.recvfrom.side_effect = [cmd for cmd, rsp in exchange]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("0400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("31323334")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.tt2_cmd == HEX('3000')
        assert device.socket.sendto.mock_calls == RSP_CALLS(exchange[:-1])
        return target

    def test_listen_tta_tt2_uid7_activated(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('88313233b8')),
            (CMD106A('937088313233b8'), RSP106A('04')),
            (CMD106A('9520'), RSP106A('3435363700')),
            (CMD106A('95703435363700'), RSP106A('00')),
            (CMD106A('3000'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = RSP_SIZES(exchange[:-1])
        device.socket.recvfrom.side_effect = [cmd for cmd, rsp in exchange]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("31323334353637")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.tt2_cmd == HEX('3000')
        assert device.socket.sendto.mock_calls == RSP_CALLS(exchange[:-1])

    def test_listen_tta_tt2_uid10_activated(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('88313233b8')),
            (CMD106A('937088313233b8'), RSP106A('04')),
            (CMD106A('9520'), RSP106A('88343536bf')),
            (CMD106A('957088343536bf'), RSP106A('04')),
            (CMD106A('9720'), RSP106A('3738393006')),
            (CMD106A('95703738393006'), RSP106A('00')),
            (CMD106A('3000'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = RSP_SIZES(exchange[:-1])
        device.socket.recvfrom.side_effect = [cmd for cmd, rsp in exchange]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("31323334353637383930")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.tt2_cmd == HEX('3000')
        assert device.socket.sendto.mock_calls == RSP_CALLS(exchange[:-1])

    def test_listen_tta_tt2_excessive_uid(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('88313233b8')),
            (CMD106A('937088313233b8'), RSP106A('04')),
            (CMD106A('9520'), RSP106A('88343536bf')),
            (CMD106A('957088343536bf'), RSP106A('04')),
            (CMD106A('9720'), RSP106A('3738393006')),
            (CMD106A('95703738393006'), RSP106A('04')),
            (CMD106A('3000'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = RSP_SIZES(exchange)
        device.socket.recvfrom.side_effect = [
            cmd for cmd, rsp in exchange] + [nfc.clf.TimeoutError]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("3132333435363738393031")
        assert device.listen_tta(target, 1.0) is None
        assert device.socket.sendto.mock_calls == RSP_CALLS(exchange[:-1])

    def test_listen_tta_tt4_activated(self, device):
        exchange = [
            (CMD106A('26'), RSP106A('0400')),
            (CMD106A('9320'), RSP106A('3132333404')),
            (CMD106A('93703132333404'), RSP106A('00')),
            (CMD106A('E000'), RSP106A('')),
        ]
        device.socket.sendto.side_effect = RSP_SIZES(exchange[:-1])
        device.socket.recvfrom.side_effect = [cmd for cmd, rsp in exchange]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("0400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("31323334")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.tt4_cmd == HEX('E000')
        assert device.socket.sendto.mock_calls == RSP_CALLS(exchange[:-1])

    def test_listen_tta_dep_activated(self, device):
        atr_req_frame = 'F0 13 D400 30313233343536373839 00000002 aabb'
        exchange = [
            (CMD106A('26'), RSP106A('4400')),
            (CMD106A('9320'), RSP106A('3132333404')),
            (CMD106A('93703132333404'), RSP106A('00')),
            (CMD106A(atr_req_frame), RSP106A('')),
        ]
        device.socket.sendto.side_effect = RSP_SIZES(exchange[:-1])
        device.socket.recvfrom.side_effect = [cmd for cmd, rsp in exchange]
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("31323334")
        target = device.listen_tta(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.atr_req == HEX(atr_req_frame)[2:]
        assert device.socket.sendto.mock_calls == RSP_CALLS(exchange[:-1])

    def test_listen_tta_timeout_error(self, device):
        device.socket.recvfrom.side_effect = nfc.clf.TimeoutError
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("31323334")
        assert device.listen_tta(target, 1.0) is None

    def test_listen_tta_communication_error(self, device):
        device.socket.recvfrom.side_effect = nfc.clf.CommunicationError
        target = nfc.clf.LocalTarget('106A')
        target.sens_res = HEX("4400")
        target.sel_res = HEX("00")
        target.sdd_res = HEX("31323334")
        assert device.listen_tta(target, 0.01) is None

    def test_listen_tta_socket_bind_error(self, device):
        device.socket.bind.side_effect \
            = nfc.clf.udp.socket.error(nfc.clf.udp.errno.EADDRINUSE, "test")
        assert device.listen_tta(nfc.clf.LocalTarget('106A'), 1.0) is None

    def test_listen_ttb_tt4_activated(self, device):
        device.socket.sendto.side_effect = [
            len('106B 50e8253eec00000011008185')
        ]
        device.socket.recvfrom.side_effect = [
            CMD106B('000000'), CMD106B('050000'), CMD106B('E03132'),
        ]
        target = nfc.clf.LocalTarget('106B')
        target.sensb_res = HEX('50e8253eec00000011008185')
        target = device.listen_ttb(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106B'
        assert target.tt4_cmd == HEX('E03132')
        assert device.socket.sendto.mock_calls == [
            call(*RSP106B('50e8253eec00000011008185'))
        ]

    def test_listen_ttb_timeout_error(self, device):
        device.socket.recvfrom.side_effect = nfc.clf.TimeoutError
        target = nfc.clf.LocalTarget('106B')
        target.sensb_res = HEX('50e8253eec00000011008185')
        assert device.listen_ttb(target, 1.0) is None

    def test_listen_ttb_communication_error(self, device):
        device.socket.recvfrom.side_effect = nfc.clf.CommunicationError
        target = nfc.clf.LocalTarget('106B')
        target.sensb_res = HEX('50e8253eec00000011008185')
        assert device.listen_ttb(target, 0.01) is None

    def test_listen_ttb_socket_bind_error(self, device):
        device.socket.bind.side_effect \
            = nfc.clf.udp.socket.error(nfc.clf.udp.errno.EADDRINUSE, "test")
        assert device.listen_ttb(nfc.clf.LocalTarget('106B'), 1.0) is None

    @pytest.mark.parametrize("sensf_req, sensf_res", [
        ('0600ffff0000', '120101010701260cca020f0d23042f7783ff'),
        ('0600ffff0100', '140101010701260cca020f0d23042f7783ff12fc'),
        ('0600ffff0200', '140101010701260cca020f0d23042f7783ff0001'),
    ])
    def test_listen_ttf_tt3_activated(self, device, sensf_req, sensf_res):
        device.socket.sendto.side_effect = [
            len('106B ' + sensf_res)
        ]
        device.socket.recvfrom.side_effect = [
            CMD212F('000000'), CMD212F('030000'), CMD212F(sensf_req),
            CMD212F('0a 02 01010701260cca02'),
        ]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX('01 01010701260cca02 0f0d23042f7783ff 12fc')
        target = device.listen_ttf(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '212F'
        assert target.tt3_cmd == HEX('02 01010701260cca02')
        assert device.socket.sendto.mock_calls == [
            call(*RSP212F(sensf_res))
        ]

    def test_listen_ttf_dep_activated(self, device):
        atr_req_frame = '13 D400 30313233343536373839 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('212F 120101010701260cca020f0d23042f7783ff')
        ]
        device.socket.recvfrom.side_effect = [
            CMD212F('060000000000'), CMD212F('0600ffff0000'),
            CMD212F('030000'), CMD212F(atr_req_frame),
        ]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX('01 3031323334353637 0f0d23042f7783ff 12fc')
        target = device.listen_ttf(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '212F'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [
            call(*RSP212F('12 01 3031323334353637 0f0d23042f7783ff'))
        ]

    def test_listen_ttf_timeout_error(self, device):
        device.socket.recvfrom.side_effect = nfc.clf.TimeoutError
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX('01 3031323334353637 0f0d23042f7783ff 12fc')
        assert device.listen_ttf(target, 1.0) is None

    def test_listen_ttf_communication_error(self, device):
        device.socket.recvfrom.side_effect = nfc.clf.CommunicationError
        target = nfc.clf.LocalTarget('212F')
        target.sensf_res = HEX('01 3031323334353637 0f0d23042f7783ff 12fc')
        assert device.listen_ttf(target, 0.01) is None

    def test_listen_ttf_socket_bind_error(self, device):
        device.socket.bind.side_effect \
            = nfc.clf.udp.socket.error(nfc.clf.udp.errno.EADDRINUSE, "test")
        assert device.listen_ttf(nfc.clf.LocalTarget('212F'), 1.0) is None

    def test_listen_dep_activated_tta_passive(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        dep_req_frame = '06 D40600 0000'
        device.socket.sendto.side_effect = [
            len('106A 0000'),
            len('106A 0102030404'),
            len('106A 60'),
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A('000000'),  # garbage
            CMD106A('26'),
            CMD106A('9320'),
            CMD106A('93700102030404'),
            CMD106A('f0' + atr_req_frame),
            CMD106A('f0' + dep_req_frame),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert target.dep_req == HEX(dep_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('0000'),
            RSP106A('0102030404'),
            RSP106A('60'),
            RSP106A('f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]]

    def test_listen_dep_activated_tta_active(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        dep_req_frame = '06 D40600 0000'
        device.socket.sendto.side_effect = [
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A('f0' + atr_req_frame),
            CMD106A('f0' + dep_req_frame),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert target.dep_req == HEX(dep_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]]

    def test_listen_dep_activated_ttf_passive(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        dep_req_frame = '06 D40600 0000'
        device.socket.sendto.side_effect = [
            len('424F 120101010701260cca020f0d23042f7783ff'),
            len('424F 12d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD424F('000000'),  # garbage
            CMD424F('030000'),  # garbage
            CMD424F('0600ffff0000'),
            CMD424F(atr_req_frame),
            CMD424F(dep_req_frame),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '424F'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert target.dep_req == HEX(dep_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP424F('12 01 01fe303132333435 0f0d23042f7783ff'),
            RSP424F('12 d501 d0d1d2d3d4d5d6d7d8d9 0000000800'),
        ]]

    def test_listen_dep_activated_ttf_active(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        dep_req_frame = '06 D40600 0000'
        device.socket.sendto.side_effect = [
            len('424F 12d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD424F(atr_req_frame),
            CMD424F(dep_req_frame),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '424F'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert target.dep_req == HEX(dep_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP424F('12 d501 d0d1d2d3d4d5d6d7d8d9 0000000800'),
        ]]

    def test_listen_dep_activated_106_psl_106(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        dep_req_frame = '06 D40600 0000'
        device.socket.sendto.side_effect = [
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('106A f004d50500'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A('f0' + atr_req_frame),
            CMD106A('f0' + '06D404000003'),
            CMD106A('f0' + dep_req_frame),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '106A'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert target.dep_req == HEX(dep_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            RSP106A('f004d50500'),
        ]]

    def test_listen_dep_activated_106_psl_424(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        dep_req_frame = '06 D40600 0000'
        device.socket.sendto.side_effect = [
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('106A f004d50500'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A('f0' + atr_req_frame),
            CMD106A('f0' + '06D404001203'),
            CMD424F(dep_req_frame),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '424F'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert target.dep_req == HEX(dep_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            RSP106A('f004d50500'),
        ]]

    def test_listen_dep_activated_212_psl_424(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        dep_req_frame = '06 D40600 0000'
        device.socket.sendto.side_effect = [
            len('212F 12d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('212F 04d50500'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD212F(atr_req_frame),
            CMD212F('06D404001203'),
            CMD424F(dep_req_frame),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == '424F'
        assert target.atr_req == HEX(atr_req_frame)[1:]
        assert target.dep_req == HEX(dep_req_frame)[1:]
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP212F('12d501d0d1d2d3d4d5d6d7d8d90000000800'),
            RSP212F('04d50500'),
        ]]

    def test_listen_dep_activated_tta_deselect(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('106A f003d509'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A('f0' + atr_req_frame),
            CMD106A('f0' + '03d408'),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('f0 12 d501d0d1d2d3d4d5d6d7d8d90000000800'),
            RSP106A('f0 03 d509'),
        ]]

    def test_listen_dep_activated_tta_release(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('106A f003d509'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A('f0' + atr_req_frame),
            CMD106A('f0' + '03d40a'),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('f0 12 d501d0d1d2d3d4d5d6d7d8d90000000800'),
            RSP106A('f0 03 d50b'),
        ]]

    def test_listen_dep_activated_ttf_deselect(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('424F 12d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('424F 03d509'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD424F(atr_req_frame),
            CMD424F('03d408'),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP424F('12 d501 d0d1d2d3d4d5d6d7d8d9 0000000800'),
            RSP424F('03 d509'),
        ]]

    def test_listen_dep_activated_ttf_release(self, device):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('424F 12d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('424F 03d50b'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD424F(atr_req_frame),
            CMD424F('03d40a'),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP424F('12 d501 d0d1d2d3d4d5d6d7d8d9 0000000800'),
            RSP424F('03 d50b'),
        ]]

    @pytest.mark.parametrize('garbage', [
        '030000', '000000'
    ])
    def test_listen_dep_activated_ttf_garbage(self, device, garbage):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('424F 12d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD424F(atr_req_frame),
            CMD424F(garbage),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP424F('12 d501 d0d1d2d3d4d5d6d7d8d9 0000000800'),
        ]]

    @pytest.mark.parametrize('garbage', [
        'f0030000', 'f0000000', 'ff000000'
    ])
    def test_listen_dep_activated_tta_garbage(self, device, garbage):
        atr_req_frame = 'F0 13 D400 01fe303132333435ffff 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A(atr_req_frame),
            CMD106A(garbage),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('f0 12 d501 d0d1d2d3d4d5d6d7d8d9 0000000800'),
        ]]

    @pytest.mark.parametrize('garbage', [
        '010000', '000000'
    ])
    def test_listen_dep_activated_106_psl_garbage(self, device, garbage):
        atr_req_frame = '13 D400 01fe303132333435ffff 00000002 aabb'
        device.socket.sendto.side_effect = [
            len('106A f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            len('106A f004d50500'),
        ]
        device.socket.recvfrom.side_effect = [
            CMD106A('f0' + atr_req_frame),
            CMD106A('f0' + '06D404001203'),
            CMD424F(garbage),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == [call(*_) for _ in [
            RSP106A('f012d501d0d1d2d3d4d5d6d7d8d90000000800'),
            RSP106A('f004d50500'),
        ]]

    def test_listen_dep_communication_error(self, device):
        device.socket.recvfrom.side_effect = [
            FRAME('RFOFF', ''),
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == []

    def test_listen_dep_timeout_error(self, device):
        device.socket.recvfrom.return_value = CMD106A('00')
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 0.001) is None
        assert device.socket.sendto.mock_calls == []

    def test_listen_dep_socket_bind_error(self, device):
        device.socket.bind.side_effect \
            = nfc.clf.udp.socket.error(nfc.clf.udp.errno.EADDRINUSE, "test")
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe303132333435 0f0d23042f7783ff ffff')
        target.sens_res = HEX('0000')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('60')
        target.atr_res = HEX('D501 d0d1d2d3d4d5d6d7d8d9 0000000800')
        assert device.listen_dep(target, 1.0) is None
        assert device.socket.sendto.mock_calls == []

    #
    # SEND/RECV DATA
    #

    def test_send_cmd_recv_rsp(self, device):
        target = self.test_sense_tta_with_tt1_target_found(device)
        cdata, rdata = ('01020304', '05060708')

        device.socket.sendto.side_effect = [len(CMD106A(cdata)[0])]
        device.socket.recvfrom.side_effect = [RSP106A(rdata)]
        assert device.send_cmd_recv_rsp(target, HEX(cdata), 1) == HEX(rdata)
        device.socket.sendto.assert_called_with(*CMD106A(cdata))

        device.socket.sendto.side_effect = []
        device.socket.recvfrom.side_effect = [RSP106A(rdata)]
        assert device.send_cmd_recv_rsp(target, None, 1) == HEX(rdata)

        device.socket.sendto.side_effect = [len(CMD106A(cdata)[0])]
        device.socket.recvfrom.side_effect = []
        assert device.send_cmd_recv_rsp(target, HEX(cdata), 0) is None
        device.socket.sendto.assert_called_with(*CMD106A(cdata))

        device.socket.sendto.side_effect = [len(CMD106A(cdata)[0])]
        device.socket.recvfrom.side_effect = [RSP106A('')]
        with pytest.raises(nfc.clf.TransmissionError):
            device.send_cmd_recv_rsp(target, HEX(cdata), 1)
        device.socket.sendto.assert_called_with(*CMD106A(cdata))

        device.socket.sendto.side_effect = [len(CMD106A(cdata)[0])+1]
        device.socket.recvfrom.side_effect = []
        with pytest.raises(nfc.clf.TransmissionError):
            device.send_cmd_recv_rsp(target, HEX(cdata), 1)
        device.socket.sendto.assert_called_with(*CMD106A(cdata))

        device.socket.sendto.side_effect = [len(CMD106A(cdata)[0])]
        device.socket.recvfrom.side_effect = [RSP424F(rdata), RSP106A(rdata)]
        assert device.send_cmd_recv_rsp(target, HEX(cdata), 1) == HEX(rdata)
        device.socket.sendto.assert_called_with(*CMD106A(cdata))

    def test_send_rsp_recv_cmd(self, device):
        target = self.test_listen_tta_tt2_uid4_activated(device)
        cdata, rdata = ('01020304', '05060708')

        device.socket.sendto.side_effect = [len(RSP106A(rdata)[0])]
        device.socket.recvfrom.side_effect = [CMD106A(cdata)]
        assert device.send_rsp_recv_cmd(target, HEX(rdata), 1) == HEX(cdata)
        device.socket.sendto.assert_called_with(*RSP106A(rdata))

        device.socket.sendto.side_effect = [len(RSP106A(rdata)[0])]
        device.socket.recvfrom.side_effect = [CMD106A(cdata)]
        assert device.send_rsp_recv_cmd(target, HEX(rdata), None) == HEX(cdata)
        device.socket.sendto.assert_called_with(*RSP106A(rdata))

        device.socket.sendto.side_effect = []
        device.socket.recvfrom.side_effect = [CMD106A(cdata)]
        assert device.send_rsp_recv_cmd(target, None, 1) == HEX(cdata)

        device.socket.sendto.side_effect = [len(RSP106A(rdata)[0])]
        device.socket.recvfrom.side_effect = []
        assert device.send_rsp_recv_cmd(target, HEX(rdata), 0) is None
        device.socket.sendto.assert_called_with(*RSP106A(rdata))

        device.socket.sendto.side_effect = [len(RSP106A(rdata)[0])]
        device.socket.recvfrom.side_effect = [CMD106A('')]
        with pytest.raises(nfc.clf.TransmissionError):
            device.send_rsp_recv_cmd(target, HEX(rdata), 1)
        device.socket.sendto.assert_called_with(*RSP106A(rdata))

    def test_recv_data_timeout_error(self, mocker, device):  # noqa: F811
        target = self.test_sense_tta_with_tt1_target_found(device)
        mocker.patch('nfc.clf.udp.select.select').return_value = ([], [], [])
        with pytest.raises(nfc.clf.TimeoutError):
            device.send_cmd_recv_rsp(target, None, 0.001)

    def test_get_max_send_data_size(self, device):
        assert device.get_max_send_data_size(None) == 290

    def test_get_max_recv_data_size(self, device):
        assert device.get_max_recv_data_size(None) == 290

    #
    # INTERNAL METHODS
    #

    def test_bind_socket(self, device):
        assert device._bind_socket(nfc.clf.udp.time.time() - 1) is None
        device.socket.bind.side_effect \
            = nfc.clf.udp.socket.error(nfc.clf.udp.errno.EADDRINUSE, "test")
        assert device._bind_socket(nfc.clf.udp.time.time() + 1) is False
        device.socket.bind.side_effect \
            = nfc.clf.udp.socket.error(nfc.clf.udp.errno.ENODEV, "test")
        with pytest.raises(nfc.clf.udp.socket.error) as excinfo:
            device._bind_socket(nfc.clf.udp.time.time() + 1)
        assert excinfo.value.errno == nfc.clf.udp.errno.ENODEV
