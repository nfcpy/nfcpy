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


def HEX(s):
    return bytearray.fromhex(s)


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
        return mocker.Mock(spec=nfc.clf.device.Device)

    @pytest.fixture()  # noqa: F811
    def clf(self, device_connect, device):
        device_connect.return_value = device
        clf = nfc.clf.ContactlessFrontend('test')
        device_connect.assert_called_once_with('test')
        assert isinstance(clf, nfc.clf.ContactlessFrontend)
        assert isinstance(clf.device, nfc.clf.device.Device)
        return clf

    @pytest.fixture()  # noqa: F811
    def terminate(self, mocker):
        return mocker.Mock(return_value=True)

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
        assert clf.connect(llcp={}, terminate=terminate) is None
        assert clf.connect(rdwr={}, terminate=terminate) is None
        assert clf.connect(card={}, terminate=terminate) is None

    def test_connect_llcp_initiator(self, clf, terminate):
        terminate.side_effect = [False, True]
        clf.device.sense_tta.return_value = None
        clf.device.sense_ttb.return_value = None
        clf.device.sense_ttf.return_value = None
        clf.device.sense_dep.return_value = None
        llcp_options = {'role': 'initiator'}
        assert clf.connect(llcp=llcp_options, terminate=terminate) is None

    def test_connect_rdwr_defaults(self, clf, terminate):
        terminate.side_effect = [False, True]
        clf.device.sense_tta.return_value = None
        clf.device.sense_ttb.return_value = None
        clf.device.sense_ttf.return_value = None
        rdwr_options = {'iterations': 1}
        assert clf.connect(rdwr=rdwr_options, terminate=terminate) is None

    def test_connect_card_defaults(self, clf, terminate):
        terminate.side_effect = [False, True]
        clf.device.listen_tta.return_value = None
        clf.device.listen_ttb.return_value = None
        clf.device.listen_ttf.return_value = None
        card_options = {'on-startup': lambda _: nfc.clf.LocalTarget('212F')}
        assert clf.connect(card=card_options, terminate=terminate) is None

    @pytest.mark.parametrize("error", [
        IOError, nfc.clf.UnsupportedTargetError, KeyboardInterrupt,
    ])
    def test_connect_false_on_error(self, clf, error):
        clf.device.sense_tta.side_effect = error
        clf.device.sense_ttb.side_effect = error
        clf.device.sense_ttf.side_effect = error
        clf.device.sense_dep.side_effect = error
        llcp_options = {'role': 'initiator'}
        assert clf.connect(llcp=llcp_options) is False


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
