# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.dep

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call

import logging
logging.basicConfig(level=logging.DEBUG-1)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.dep").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()
def target():
    target = nfc.clf.RemoteTarget("106A")
    target.sens_res = HEX("4400")
    target.sel_res = HEX("00")
    target.sdd_res = HEX("0102030405060708")
    return target


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch.object(clf, 'sense', autospec=True)
    clf.sense.return_value = None
    return clf


class TestInitiator:
    atr_res = 'D501 01FE0102030405060708 0000000832 46666D010113'
    atr_res_frame = '18' + atr_res

    @pytest.fixture()
    def dep(self, clf):
        return nfc.dep.Initiator(clf)

    def test_activate_active_no_target_found(self, dep):
        assert dep.activate(acm=True) is None
        assert dep.clf.sense.call_count == 3

    @pytest.mark.parametrize("brty", ["106A", "212F", "424F"])
    def test_activate_active_target_without_psl(self, dep, brty):
        target = nfc.clf.RemoteTarget(brty, atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == brty
        assert dep.acm is True

    @pytest.mark.parametrize("brs, brty", [(1, "212F"), (2, "424F")])
    def test_activate_active_target_106_with_psl(self, dep, brs, brty):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX('F0 04 D50500')]
        assert dep.activate(None, brs=brs) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == brty
        assert dep.acm is True

    @pytest.mark.parametrize("brs, brty", [(1, "212F"), (2, "424F")])
    def test_activate_active_target_212_with_psl(self, dep, brs, brty):
        target = nfc.clf.RemoteTarget("212F", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX('04 D50500')]
        assert dep.activate(None, brs=brs) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == brty
        assert dep.acm is True

    def test_activate_psl_res_communication_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [nfc.clf.CommunicationError]
        assert dep.activate() is None

    def test_activate_passive_no_target_found(self, dep):
        assert dep.activate(acm=False) is None
        assert dep.clf.sense.call_count == 2

    def test_activate_passive_target_106(self, dep):
        target = nfc.clf.RemoteTarget("106A")
        target.sens_res = HEX('0101')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('40')
        dep.clf.sense.side_effect = [None, target]
        dep.clf.exchange.side_effect = [HEX('F0' + self.atr_res_frame)]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == "106A"
        assert dep.acm is False

    def test_activate_passive_target_212(self, dep):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX('01 01FE010203040506 0000000000000000')
        dep.clf.sense.side_effect = [None, None, target]
        dep.clf.exchange.side_effect = [HEX(self.atr_res_frame)]
        assert dep.activate(None, brs=1) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == "212F"
        assert dep.acm is False

    def test_activate_atr_res_communication_error(self, dep):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX('01 01FE010203040506 0000000000000000')
        dep.clf.sense.side_effect = [None, None, target]
        dep.clf.exchange.side_effect = [nfc.clf.CommunicationError]
        assert dep.activate(None, brs=1) is None

    def test_activate_active_target_unsupported_error(self, dep):
        dep.clf.sense.side_effect = [
            nfc.clf.UnsupportedTargetError, None, None, None, None,
        ]
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 3
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 5

    def test_activate_active_target_communication_error(self, dep):
        dep.clf.sense.side_effect = [
            nfc.clf.CommunicationError, None, None, None, None, None,
        ]
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 3
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 6

    @pytest.mark.parametrize("release, command, response", [
        (True, 'F004D40A00', 'F004D50B00'),
        (True, 'F004D40A00', 'F004D50B01'),
        (False, 'F004D40800', 'F004D50900'),
        (False, 'F004D40800', 'F004D50901'),
        (True, 'F004D40A00', 'F004D50900'),
        (False, 'F004D40800', 'F004D50B00'),
    ])
    def test_deactivate_with_rls_or_dsl(self, dep, release, command, response):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX(response)]
        assert dep.activate(None, did=0, brs=0) == HEX('46666D010113')
        assert dep.deactivate(release) is None
        assert dep.clf.exchange.mock_calls == [call(HEX(command), 0.1)]
