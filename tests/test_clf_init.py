# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf

import errno
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.DEBUG)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.dep").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s) if s is not None else None


def test_print_data():
    assert nfc.clf.print_data(None) == 'None'
    assert nfc.clf.print_data(b'1') == '31'
    assert nfc.clf.print_data(bytearray.fromhex('01')) == '01'


class TestContactlessFrontend(object):
    @pytest.fixture()  # noqa: F811
    def device_connect(self, mocker):
        return mocker.patch('nfc.clf.device.connect')

    @pytest.fixture()  # noqa: F811
    def device(self, mocker):
        device = mocker.Mock(spec=nfc.clf.device.Device)
        device.path = "usb:001:001"
        device.vendor_name = "Vendor"
        device.product_name = "Product"
        return device

    @pytest.fixture()  # noqa: F811
    def clf(self, device_connect, device):
        device_connect.return_value = device
        clf = nfc.clf.ContactlessFrontend('test')
        device_connect.assert_called_once_with('test')
        assert isinstance(clf, nfc.clf.ContactlessFrontend)
        assert isinstance(clf.device, nfc.clf.device.Device)
        clf.device.sense_tta.return_value = None
        clf.device.sense_ttb.return_value = None
        clf.device.sense_ttf.return_value = None
        clf.device.sense_dep.return_value = None
        clf.device.listen_tta.return_value = None
        clf.device.listen_ttb.return_value = None
        clf.device.listen_ttf.return_value = None
        clf.device.listen_dep.return_value = None
        assert str(clf) == "Vendor Product on usb:001:001"
        return clf

    @pytest.fixture()  # noqa: F811
    def terminate(self, mocker):
        return mocker.Mock(return_value=False)

    def test_init(self, device_connect):
        device_connect.return_value = None
        with pytest.raises(IOError) as excinfo:
            nfc.clf.ContactlessFrontend('test')
        assert excinfo.value.errno == errno.ENODEV

    def test_open(self, device_connect, device):
        device_connect.return_value = None
        assert nfc.clf.ContactlessFrontend().open('test') is False

        device_connect.return_value = device
        assert nfc.clf.ContactlessFrontend().open('test') is True

        with pytest.raises(TypeError) as excinfo:
            nfc.clf.ContactlessFrontend().open(int())
        assert str(excinfo.value) == "expecting a string type argument *path*"

        with pytest.raises(ValueError) as excinfo:
            nfc.clf.ContactlessFrontend().open('')
        assert str(excinfo.value) == "argument *path* must not be empty"

    def test_close(self, clf):
        clf.device.close.side_effect = IOError
        clf.close()

    #
    # CONNECT
    #

    def test_connect_without_device(self, clf):
        clf.device = None
        with pytest.raises(IOError) as excinfo:
            clf.connect()
        assert excinfo.value.errno == errno.ENODEV

    @pytest.mark.parametrize("options, errstr", [
        ({'rdwr': str()}, "'rdwr' must be a dictionary"),
        ({'llcp': int()}, "'llcp' must be a dictionary"),
        ({'card': set()}, "'card' must be a dictionary"),
    ])
    def test_connect_with_invalid_options(self, clf, options, errstr):
        with pytest.raises(TypeError) as excinfo:
            clf.connect(**options)
        assert str(excinfo.value) == "argument " + errstr

    def test_connect_with_empty_options(self, clf):
        assert clf.connect() is None

    def test_connect_with_startup_false(self, clf):
        assert clf.connect(llcp={'on-startup': lambda llc: False}) is None
        assert clf.connect(rdwr={'on-startup': lambda llc: False}) is None
        assert clf.connect(card={'on-startup': lambda llc: False}) is None

    def test_connect_with_terminate_true(self, clf, terminate):
        terminate.return_value = True
        assert clf.connect(llcp={}, terminate=terminate) is None
        assert clf.connect(rdwr={}, terminate=terminate) is None
        assert clf.connect(card={}, terminate=terminate) is None

    @pytest.mark.parametrize("error", [
        IOError, nfc.clf.UnsupportedTargetError, KeyboardInterrupt,
    ])
    def test_connect_false_on_error(self, clf, error):
        clf.device.sense_tta.side_effect = error
        clf.device.sense_ttb.side_effect = error
        clf.device.sense_ttf.side_effect = error
        clf.device.sense_dep.side_effect = error
        assert clf.connect(rwdr={}, llcp={}) is False

    def test_connect_rdwr_defaults(self, clf, terminate):
        terminate.side_effect = [False, True]
        rdwr_options = {'iterations': 1}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is None

    def test_connect_rdwr_remote_is_tta_tt1(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('106A')
        target.sens_res = HEX('000C')
        target.rid_res = HEX('1148B2565400')
        clf.device.sense_tta.return_value = target
        rdwr_options = {'iterations': 1}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is True

    def test_connect_rdwr_remote_is_tta_tt2(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('106A')
        target.sens_res = HEX('4400')
        target.sel_res = HEX('00')
        target.sdd_res = HEX('0416C6C2D73881')
        clf.device.sense_tta.return_value = target
        rdwr_options = {'iterations': 1, 'targets': ['106A']}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is True

    def test_connect_rdwr_remote_is_tta_dep(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('106A')
        target.sens_res = HEX('4400')
        target.sel_res = HEX('40')
        target.sdd_res = HEX('0416C6C2D73881')
        clf.device.sense_tta.return_value = target
        rdwr_options = {'iterations': 1, 'targets': ['106A']}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is None

    def test_connect_rdwr_remote_is_ttb_tt4(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('106B')
        target.sensb_res = HEX('50E8253EEC00000011008185')
        clf.device.sense_ttb.return_value = target
        clf.device.send_cmd_recv_rsp.return_value = HEX('00')
        rdwr_options = {'iterations': 1, 'targets': ['106B']}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is True

    def test_connect_rdwr_remote_is_ttf_tt3(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('212F')
        target.sensf_res = HEX('01 01010701260cca02 0f0d23042f7783ff 12fc')
        clf.device.sense_ttf.return_value = target
        rdwr_options = {'iterations': 1, 'targets': ['212F']}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is True

    def test_connect_rdwr_remote_is_ttf_dep(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('212F')
        target.sensf_res = HEX('01 01FE0701260cca02 0f0d23042f7783ff 12fc')
        clf.device.sense_ttf.return_value = target
        rdwr_options = {'on-connect': lambda tag: False}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is None

    def test_connect_rdwr_do_beep_on_connect(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('212F')
        target.sensf_res = HEX('01 01010701260cca02 ffffffffffffffff 12fc')
        clf.device.sense_ttf.return_value = target
        rdwr_options = {'iterations': 1, 'beep-on-connect': True}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is True
        print(clf.device.send_cmd_recv_rsp.mock_calls)
        assert clf.device.turn_on_led_and_buzzer.call_count == 1

    def test_connect_rdwr_no_beep_on_connect(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('212F')
        target.sensf_res = HEX('01 01010701260cca02 ffffffffffffffff 12fc')
        clf.device.sense_ttf.return_value = target
        rdwr_options = {'iterations': 1, 'beep-on-connect': False}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is True
        assert clf.device.turn_on_led_and_buzzer.call_count == 0

    def test_connect_rdwr_one_presence_loop(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.RemoteTarget('212F')
        target.sensf_res = HEX('01 01010701260cca02 ffffffffffffffff 12fc')
        clf.device.sense_ttf.return_value = target
        clf.device.send_cmd_recv_rsp.side_effect = [
            HEX('12 01 01010701260cca02 ffffffffffffffff'),
        ]
        rdwr_options = {'iterations': 1}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is True

    def test_connect_rdwr_on_connect_false(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.RemoteTarget('212F')
        target.sensf_res = HEX('01 01010701260cca02 ffffffffffffffff 12fc')
        clf.device.sense_ttf.return_value = target
        rdwr_options = {'iterations': 1, 'on-connect': lambda tag: False}
        tag = clf.connect(rdwr=rdwr_options, terminate=terminate)
        assert isinstance(tag, nfc.tag.Tag)

    def test_connect_rdwr_tag_activation_fails(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('106B')
        target.sensb_res = HEX('50E8253EEC00000011008185')
        clf.device.sense_ttb.return_value = target
        clf.device.send_cmd_recv_rsp.side_effect = nfc.clf.TimeoutError
        rdwr_options = {'iterations': 1}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is None

    def _test_connect_card_defaults(self, clf, terminate):
        terminate.side_effect = [False, True]
        card_options = {'on-startup': lambda _: nfc.clf.LocalTarget('212F')}
        assert clf.connect(card=card_options, terminate=terminate) is None

    def test_connect_card_as_tt3_target(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_req = HEX('0012FC0103')
        target.sensf_res = HEX('0102FE010203040506FFFFFFFFFFFFFFFF12FC')
        target.tt3_cmd = HEX('0602fe010203040506010b00018000')
        clf.device.listen_ttf.return_value = target
        clf.device.send_rsp_recv_cmd.return_value = HEX('0012FC0103')
        card_options = {'target': target, 'on-startup': lambda t: target}
        assert clf.connect(card=card_options, terminate=terminate) is True

    def test_connect_card_and_broken_link_error(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_req = HEX('0012FC0103')
        target.sensf_res = HEX('0102FE010203040506FFFFFFFFFFFFFFFF12FC')
        target.tt3_cmd = HEX('0602fe010203040506010b00018000')
        clf.device.listen_ttf.return_value = target
        clf.device.send_rsp_recv_cmd.side_effect = nfc.clf.BrokenLinkError
        card_options = {'target': target, 'on-startup': lambda t: target}
        assert clf.connect(card=card_options, terminate=terminate) is True

    def test_connect_card_and_communication_error(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_req = HEX('0012FC0103')
        target.sensf_res = HEX('0102FE010203040506FFFFFFFFFFFFFFFF12FC')
        target.tt3_cmd = HEX('0602fe010203040506010b00018000')
        clf.device.listen_ttf.return_value = target
        clf.device.send_rsp_recv_cmd.side_effect = nfc.clf.CommunicationError
        card_options = {'target': target, 'on-startup': lambda t: target}
        assert clf.connect(card=card_options, terminate=terminate) is True

    def test_connect_card_and_leave_on_connect(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_req = HEX('0012FC0103')
        target.sensf_res = HEX('0102FE010203040506FFFFFFFFFFFFFFFF12FC')
        target.tt3_cmd = HEX('0602fe010203040506010b00018000')
        clf.device.listen_ttf.return_value = target
        card_options = {'target': target, 'on-startup': lambda t: target,
                        'on-connect': lambda tag: False}
        tag = clf.connect(card=card_options, terminate=terminate)
        assert isinstance(tag, nfc.tag.TagEmulation)

    def test_connect_card_emulate_tag_returns_none(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_req = HEX('0012FC0103')
        target.sensf_res = HEX('0102FE010203040506FFFFFFFFFFFFFFFF12FC')
        target.tt3_cmd = HEX('')
        clf.device.listen_ttf.return_value = target
        card_options = {'target': target, 'on-startup': lambda t: target}
        assert clf.connect(card=card_options, terminate=terminate) is None

    def test_connect_card_with_on_discover_false(self, clf, terminate):
        terminate.side_effect = [False, False, True]
        target = nfc.clf.LocalTarget('212F')
        target.sensf_req = HEX('0012FC0103')
        target.sensf_res = HEX('0102FE010203040506FFFFFFFFFFFFFFFF12FC')
        target.tt3_cmd = HEX('0602fe010203040506010b00018000')
        clf.device.listen_ttf.return_value = target
        card_options = {'target': target, 'on-startup': lambda t: target,
                        'on-discover': lambda tag: False}
        assert clf.connect(card=card_options, terminate=terminate) is None

    def test_connect_llcp_role_initiator(self, clf, terminate):
        terminate.side_effect = [False, True]
        target = nfc.clf.RemoteTarget('212F')
        target.sensf_res = HEX('01 01fe000000000000 ffffffffffffffff')
        clf.device.sense_ttf.return_value = target
        clf.device.send_cmd_recv_rsp.side_effect = [
            HEX('18 d501 01fe0000000000005354 0000000032 46666d010113'),
            HEX('06 d507 000000'),
            HEX('03 d509'),
        ]
        llcp_options = {'role': 'initiator', 'brs': 1}
        assert clf.connect(llcp=llcp_options, terminate=terminate) is True

    def test_connect_llcp_role_target(self, clf, terminate):
        terminate.side_effect = [False, True]
        atr_req = 'd400 01fe0000000000005354 00000032 46666d010113'
        atr_res = 'd501 01fe1111111111115354 0000000032 46666d010113'
        target = nfc.clf.LocalTarget('212F')
        target.atr_req = HEX(atr_req)
        target.atr_res = HEX(atr_res)
        target.dep_req = HEX('d406 000000')
        clf.device.listen_dep.return_value = target
        clf.device.send_rsp_recv_cmd.side_effect = [
            HEX('03 d408'),
            nfc.clf.TimeoutError,
        ]
        llcp_options = {'role': 'target'}
        assert clf.connect(llcp=llcp_options, terminate=terminate) is True

    def test_connect_llcp_on_connect_false(self, clf, terminate):
        terminate.side_effect = [False, True]
        atr_req = 'd400 01fe0000000000005354 00000032 46666d010113'
        atr_res = 'd501 01fe1111111111115354 0000000032 46666d010113'
        target = nfc.clf.LocalTarget('212F')
        target.atr_req = HEX(atr_req)
        target.atr_res = HEX(atr_res)
        target.dep_req = HEX('d406 000000')
        clf.device.listen_dep.return_value = target
        clf.device.send_rsp_recv_cmd.side_effect = [
            HEX('03 d408'),
            nfc.clf.TimeoutError,
        ]
        llcp_options = {'role': 'target', 'on-connect': lambda clf: False}
        llc = clf.connect(llcp=llcp_options, terminate=terminate)
        assert isinstance(llc, nfc.llcp.llc.LogicalLinkController)

    def test_connect_llcp_role_invalid(self, clf, terminate):
        terminate.side_effect = [False, True]
        llcp_options = {'role': 'invalid'}
        assert clf.connect(llcp=llcp_options, terminate=terminate) is None

    #
    # SENSE
    #

    def test_sense_without_targets(self, clf):
        assert clf.sense() is None

    def test_sense_without_device(self, clf):
        clf.device = None
        with pytest.raises(IOError) as excinfo:
            clf.sense(nfc.clf.RemoteTarget('106A'))
        assert excinfo.value.errno == errno.ENODEV

    def test_sense_with_invalid_targets(self, clf):
        with pytest.raises(ValueError) as excinfo:
            clf.sense(nfc.clf.RemoteTarget('106A'), nfc.clf.LocalTarget())
        assert str(excinfo.value).startswith("invalid target argument type")

    def test_sense_with_unknown_technology(self, clf):
        valid_target = nfc.clf.RemoteTarget('106A')
        wrong_target = nfc.clf.RemoteTarget('106X')
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            clf.sense(wrong_target)
        assert str(excinfo.value) == "unknown technology type in '106X'"
        assert clf.sense(wrong_target, valid_target) is None
        clf.device.sense_tta.assert_called_once_with(valid_target)

    def test_sense_with_communication_error(self, clf):
        clf.device.sense_tta.side_effect = nfc.clf.CommunicationError
        target = nfc.clf.RemoteTarget('106A')
        assert clf.sense(target) is None
        clf.device.sense_tta.assert_called_once_with(target)

    @pytest.mark.parametrize("sens, sel, sdd, rid", [
        ('000C', None, None, '1148B2565400'),
        ('4400', '00', '0416C6C2D73881', None),
        ('E00C', '00', '0416C6C2D73881', '1148B2565400'),
    ])
    def test_sense_tta_found_valid_target(self, clf, sens, sel, sdd, rid):
        req_target = nfc.clf.RemoteTarget('106A')
        res_target = nfc.clf.RemoteTarget('106A')
        res_target.sens_res = HEX(sens)
        res_target.sel_res = HEX(sel)
        res_target.sdd_res = HEX(sdd)
        res_target.rid_res = HEX(rid)
        clf.device.sense_tta.return_value = res_target
        res_target = clf.sense(req_target)
        assert isinstance(res_target, nfc.clf.RemoteTarget)
        clf.device.sense_tta.assert_called_once_with(req_target)

    @pytest.mark.parametrize("sens, sel, sdd, rid", [
        ('E00C', '00', '0416C6C2D73881', '000000000000'),
        ('E00C', '00', '0416C6C2D73881', '0000000000'),
        ('E00C', '00', '0416C6C2D73881', None),
        ('E000', '00', '0416C6C2D73881', '100000000000'),
        ('E00000', '00', '0416C6C2D73881', None),
        ('E0', '00', '0416C6C2D73881', None),
    ])
    def test_sense_tta_found_error_target(self, clf, sens, sel, sdd, rid):
        req_target = nfc.clf.RemoteTarget('106A')
        res_target = nfc.clf.RemoteTarget('106A')
        res_target.sens_res = HEX(sens)
        res_target.sel_res = HEX(sel)
        res_target.sdd_res = HEX(sdd)
        res_target.rid_res = HEX(rid)
        clf.device.sense_tta.return_value = res_target
        assert clf.sense(req_target) is None
        clf.device.sense_tta.assert_called_once_with(req_target)

    def test_sense_tta_invalid_sel_req(self, clf):
        target = nfc.clf.RemoteTarget('106A')
        target.sel_req = HEX('0011')
        with pytest.raises(ValueError) as excinfo:
            clf.sense(target)
        assert str(excinfo.value) == "sel_req must be 4, 7, or 10 byte"

    def test_sense_dep_invalid_atr_req(self, clf):
        target = nfc.clf.RemoteTarget('106A')
        target.atr_req = bytearray(15)
        with pytest.raises(ValueError) as excinfo:
            clf.sense(target)
        assert str(excinfo.value) == "minimum atr_req length is 16 byte"
        target.atr_req = bytearray(65)
        with pytest.raises(ValueError) as excinfo:
            clf.sense(target)
        assert str(excinfo.value) == "maximum atr_req length is 64 byte"

    def test_sense_ttb_found_tt4_target(self, clf):
        req_target = nfc.clf.RemoteTarget('106B')
        res_target = nfc.clf.RemoteTarget('106B')
        res_target.sensb_res = HEX('50E8253EEC00000011008185')
        clf.device.sense_ttb.return_value = res_target
        res_target = clf.sense(req_target)
        assert isinstance(res_target, nfc.clf.RemoteTarget)
        clf.device.sense_ttb.assert_called_once_with(req_target)

    #
    # LISTEN
    #

    def test_listen_without_device(self, clf):
        clf.device = None
        with pytest.raises(IOError) as excinfo:
            clf.listen(nfc.clf.LocalTarget('106A'), 1.0)
        assert excinfo.value.errno == errno.ENODEV

    def test_listen_for_tta_target(self, clf):
        target = nfc.clf.LocalTarget('106A')
        clf.device.listen_tta.return_value = target
        assert clf.listen(target, 1.0) is target

    def test_listen_for_ttb_target(self, clf):
        target = nfc.clf.LocalTarget('106B')
        clf.device.listen_ttb.return_value = target
        assert clf.listen(target, 1.0) is target

    def test_listen_for_ttf_target(self, clf):
        target = nfc.clf.LocalTarget('212F')
        clf.device.listen_ttf.return_value = target
        assert clf.listen(target, 1.0) is target

    def test_listen_for_dep_target(self, clf):
        target = nfc.clf.LocalTarget('106A')
        target.atr_req = HEX('D400 30313233343536373839 00000000')
        target.atr_res = HEX('D501 66f6e98d1c13dfe56de4 0000000700')
        clf.device.listen_dep.return_value = target
        assert clf.listen(target, 1.0) is target
        target.atr_req = HEX('D400 30313233343536373839 000000')
        assert clf.listen(target, 1.0) is None
        target.atr_req = None
        assert clf.listen(target, 1.0) is None

    def test_listen_for_xxx_target(self, clf):
        target = nfc.clf.LocalTarget('xxx')
        with pytest.raises(ValueError) as excinfo:
            clf.listen(target, 1.0)
        assert str(excinfo.value) == "unsupported bitrate technology type xxx"

    #
    # EXCHANGE
    #

    def test_exchange_without_device(self, clf):
        clf.device = None
        with pytest.raises(IOError) as excinfo:
            clf.exchange(HEX(''), 1.0)
        assert excinfo.value.errno == errno.ENODEV

    def test_exchange_without_target(self, clf):
        assert clf.exchange(HEX(''), 1.0) is None

    #
    # MISCELLEANEOUS
    #

    def test_max_send_data_size_without_device(self, clf):
        clf.device = None
        with pytest.raises(IOError) as excinfo:
            clf.max_send_data_size()
        assert excinfo.value.errno == errno.ENODEV

    def test_max_recv_data_size_without_device(self, clf):
        clf.device = None
        with pytest.raises(IOError) as excinfo:
            clf.max_recv_data_size()
        assert excinfo.value.errno == errno.ENODEV

    def test_format_string_without_device(self, clf):
        clf.device = None
        assert str(clf).startswith("<nfc.clf.ContactlessFrontend object")

    def test_with_statement_enter_exit(self, clf):
        device = clf.device
        with clf as contactless_frontend:
            assert contactless_frontend is clf
        assert device.close.call_count == 1


class TestRemoteTarget(object):
    @pytest.mark.parametrize("brty, send, recv, kwargs", [
        ('106A', '106A', '106A', {}),
        ('106A/212F', '106A', '212F', {}),
        ('106A', '106A', '106A', {'sens_req': HEX('0102'), 'integer': 5}),
    ])
    def test_init(self, brty, send, recv, kwargs):
        target = nfc.clf.RemoteTarget(brty, **kwargs)
        assert str(target).startswith(send)
        assert target.brty == send
        assert target.brty_send == send
        assert target.brty_recv == recv
        assert target.some_attribute is None
        for attr in kwargs:
            assert getattr(target, attr) == kwargs[attr]

    @pytest.mark.parametrize("brty", [
        '106', 'A106', '106/106',
    ])
    def test_init_fail(self, brty):
        with pytest.raises(ValueError) as excinfo:
            nfc.clf.RemoteTarget(brty)
        assert str(excinfo.value) == \
            "brty pattern does not match for '%s'" % brty

    @pytest.mark.parametrize("target1, target2", [
        (nfc.clf.RemoteTarget('106A'), nfc.clf.RemoteTarget('106A')),
        (nfc.clf.RemoteTarget('106A/106A'), nfc.clf.RemoteTarget('106A')),
        (nfc.clf.RemoteTarget('106A', a=1), nfc.clf.RemoteTarget('106A', a=1)),
    ])
    def test_is_equal(self, target1, target2):
        assert target1 == target2

    @pytest.mark.parametrize("target1, target2", [
        (nfc.clf.RemoteTarget('106A'), nfc.clf.RemoteTarget('212F')),
        (nfc.clf.RemoteTarget('106A/212F'), nfc.clf.RemoteTarget('106A')),
        (nfc.clf.RemoteTarget('106A', a=1), nfc.clf.RemoteTarget('106A', b=1)),
    ])
    def test_not_equal(self, target1, target2):
        assert target1 != target2


class TestLocalTarget(object):
    @pytest.mark.parametrize("brty, kwargs", [
        ('106A', {}),
        ('212A', {'sens_req': HEX('0102'), 'integer': 5}),
    ])
    def test_init(self, brty, kwargs):
        target = nfc.clf.LocalTarget(brty, **kwargs)
        assert target.brty == brty
        assert str(target).startswith(brty)
        assert target.some_attribute is None
        for attr in kwargs:
            assert getattr(target, attr) == kwargs[attr]

    @pytest.mark.parametrize("target1, target2", [
        (nfc.clf.LocalTarget(), nfc.clf.LocalTarget('106A')),
        (nfc.clf.LocalTarget('212F'), nfc.clf.LocalTarget('212F')),
        (nfc.clf.LocalTarget('106A', a=1), nfc.clf.LocalTarget('106A', a=1)),
    ])
    def test_is_equal(self, target1, target2):
        assert target1 == target2

    @pytest.mark.parametrize("target1, target2", [
        (nfc.clf.LocalTarget(), nfc.clf.LocalTarget('212F')),
        (nfc.clf.LocalTarget('212F'), nfc.clf.LocalTarget('106A')),
        (nfc.clf.LocalTarget('106A', a=1), nfc.clf.LocalTarget('106A', b=1)),
    ])
    def test_not_equal(self, target1, target2):
        assert target1 != target2
