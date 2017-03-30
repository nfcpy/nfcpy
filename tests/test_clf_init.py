# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf

import pytest
from pytest_mock import mocker  # noqa: F401


def HEX(s):
    return bytearray.fromhex(s)


def test_print_data():
    assert nfc.clf.print_data(None) == 'None'
    assert nfc.clf.print_data(b'1') == '31'
    assert nfc.clf.print_data(bytearray.fromhex('01')) == '01'


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
