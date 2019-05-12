# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.tag

import ndef
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()
def clf():
    return nfc.ContactlessFrontend()


@pytest.fixture()
def target():
    return nfc.clf.RemoteTarget("106A")


@pytest.fixture()
def tag(clf, target):
    tag = nfc.tag.Tag(clf, target)
    assert isinstance(tag, nfc.tag.Tag)
    return tag


def test_read_ndef(mocker, tag):  # noqa: F811
    with pytest.raises(NotImplementedError) as excinfo:
        tag.ndef
    assert str(excinfo.value) == \
        "_read_ndef_data is not implemented for this tag type"

    read_ndef_data = mocker.patch("nfc.tag.Tag.NDEF._read_ndef_data")

    read_ndef_data.return_value = None
    assert tag.ndef is None

    read_ndef_data.return_value = HEX('')
    assert isinstance(tag.ndef, nfc.tag.Tag.NDEF)
    assert tag.ndef.octets == HEX('')
    assert tag.ndef.records == []
    assert tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())

    read_ndef_data.return_value = HEX('D00000')
    assert tag.ndef.has_changed is True
    assert isinstance(tag.ndef, nfc.tag.Tag.NDEF)
    assert tag.ndef.octets == HEX('D00000')
    assert tag.ndef.records == [ndef.Record()]
    assert tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())

    read_ndef_data.return_value = HEX('D50000')
    assert tag.ndef.has_changed is True
    assert isinstance(tag.ndef, nfc.tag.Tag.NDEF)
    assert tag.ndef.octets == HEX('D50000')
    assert tag.ndef.records == [ndef.Record('unknown')]
    assert tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record('unknown'))

    read_ndef_data.return_value = None
    assert tag.ndef.has_changed is True
    assert tag.ndef is None


def test_write_ndef(mocker, tag):  # noqa: F811
    read_ndef_data = mocker.patch("nfc.tag.Tag.NDEF._read_ndef_data")
    read_ndef_data.return_value = HEX('')
    assert isinstance(tag.ndef, nfc.tag.Tag.NDEF)

    with pytest.raises(AttributeError) as excinfo:
        tag.ndef.octets = HEX('D00000')
    assert str(excinfo.value) == "tag ndef area is not writeable"

    tag.ndef._writeable = True
    with pytest.raises(ValueError) as excinfo:
        tag.ndef.octets = HEX('D00000')
    assert str(excinfo.value) == "data length exceeds tag capacity"

    tag.ndef._capacity = 3
    with pytest.raises(NotImplementedError) as excinfo:
        tag.ndef.octets = HEX('D00000')
    assert str(excinfo.value) == \
        "_write_ndef_data is not implemented for this tag type"

    mocker.patch("nfc.tag.Tag.NDEF._write_ndef_data")

    tag.ndef.octets = HEX('D00000')
    assert tag.ndef.octets == HEX('D00000')

    tag.ndef.records = [ndef.Record('unknown')]
    assert tag.ndef.octets == HEX('D50000')

    tag.ndef.message = nfc.ndef.Message(nfc.ndef.Record())
    assert tag.ndef.octets == HEX('D00000')


def test_tag_dump(tag):
    assert tag.dump() == []


def test_tag_protect(tag):
    assert tag.protect() is None


def test_tag_authenticate(tag):
    assert tag.authenticate(b'password') is None
    assert tag.is_authenticated is False


def test_activate_unknown_106A(clf, target):
    target.sens_res = HEX("0000")
    target.sel_res = HEX("C0")
    assert nfc.tag.activate(clf, target) is None


def test_activate_unknown_106X(clf, target):
    target._brty_send = '106X'
    assert nfc.tag.activate(clf, target) is None


def test_activate(mocker, clf, target):  # noqa: F811
    mocker.patch('nfc.tag.activate_tt3').side_effect = nfc.clf.TimeoutError
    target._brty_send = '106F'
    assert nfc.tag.activate(clf, target) is None


@pytest.mark.parametrize("brty", ["106A", "106B"])
def test_tag_emulate_unsupported(clf, brty):
    target = nfc.clf.LocalTarget(brty)
    assert nfc.tag.emulate(clf, target) is None
