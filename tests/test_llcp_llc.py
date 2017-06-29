# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

# import time
# import errno
import pytest
# import threading

import nfc.clf
import nfc.dep
import nfc.llcp.llc

import logging
logging.basicConfig(level=logging.DEBUG-1)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.llcp").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.clf.ContactlessFrontend()
    mocker.patch.object(clf, 'sense', autospec=True)
    mocker.patch.object(clf, 'listen', autospec=True)
    mocker.patch.object(clf, 'exchange', autospec=True)
    clf.sense.return_value = None
    clf.listen.return_value = None
    return clf


@pytest.fixture
def llc():
    return nfc.llcp.llc.LogicalLinkController()


# =============================================================================
# Service Access Point
# =============================================================================
class TestServiceAccessPoint:
    @pytest.fixture
    def sap(self, llc):
        sap = nfc.llcp.llc.ServiceAccessPoint(16, llc)
        assert str(sap) == "SAP 16"
        assert sap.mode == 0
        return sap

    def test(self, sap):
        pass


# =============================================================================
# Logical Link Controller
# =============================================================================
class TestLogicalLinkController:
    atr_res = 'D501 01FE0102030405060708 0000000832 46666D010113'
    atr_res_frame = '18' + atr_res

    @pytest.fixture()  # noqa: F811
    def mac(self, mocker, clf):
        dep = nfc.dep.Initiator(clf)
        target = nfc.clf.RemoteTarget("424F", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX('04 D50500')]
        assert dep.activate(None, brs=2) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == '424F'
        assert dep.acm is True
        return dep

    def test_activate(self, llc, mac):
        # llc.activate(mac)
        pass
