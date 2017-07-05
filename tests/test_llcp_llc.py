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
logging.getLogger("nfc.dep").setLevel(logging_level)


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
    llc = nfc.llcp.llc.LogicalLinkController()
    assert llc.cfg['recv-miu'] == 248
    assert llc.cfg['send-lto'] == 500
    assert llc.cfg['send-lsc'] == 3
    assert llc.cfg['send-agf'] is True
    assert llc.cfg['llcp-sec'] is True
    return llc


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
    @pytest.mark.parametrize("options, miu, lto, lsc, agf, sec", [
        ({}, 248, 500, 3, True, True),
        ({'miu': 128}, 128, 500, 3, True, True),
        ({'lto': 100}, 248, 100, 3, True, True),
        ({'lsc': 1}, 248, 500, 1, True, True),
        ({'agf': False}, 248, 500, 3, False, True),
        ({'sec': False}, 248, 500, 3, True, False),
    ])
    def test_init(self, options, miu, lto, lsc, agf, sec):
        llc = nfc.llcp.llc.LogicalLinkController(**options)
        assert llc.cfg['recv-miu'] == miu
        assert llc.cfg['send-lto'] == lto
        assert llc.cfg['send-lsc'] == lsc
        assert llc.cfg['send-agf'] == agf
        assert llc.cfg['llcp-sec'] == sec and nfc.llcp.llc.sec.OpenSSL
        OpenSSL = nfc.llcp.llc.sec.OpenSSL
        nfc.llcp.llc.sec.OpenSSL = None
        llc = nfc.llcp.llc.LogicalLinkController(**options)
        assert llc.cfg['llcp-sec'] is False
        nfc.llcp.llc.sec.OpenSSL = OpenSSL

    @pytest.mark.parametrize("miu, lto, lsc, sec, gb", [
        (128, 100, 0, False, HEX('')),
        (128, 100, 0, False, HEX('46666D 010113 03020003')),
        (128, 100, 0, True, HEX('46666D 010113 03020003 070104')),
        (128, 100, 1, True, HEX('46666D 010113 03020003 070105')),
        (248, 100, 3, True, HEX('46666D 010113 02020078 03020003 070107')),
        (128, 500, 3, True, HEX('46666D 010113 03020003 040132 070107')),
    ])
    def test_activate_as_initiator(self, clf, miu, lto, lsc, sec, gb):
        options = {'miu': miu, 'lto': lto, 'lsc': lsc, 'sec': sec}
        llc = nfc.llcp.llc.LogicalLinkController(**options)
        atr_res = HEX('D501 00010203040506070809 0000000832') + gb
        clf.sense.return_value = nfc.clf.RemoteTarget("106A", atr_res=atr_res)
        assert llc.activate(nfc.dep.Initiator(clf), brs=0) is bool(gb)
        assert not gb or clf.sense.mock_calls[0][1][0].atr_req[16:] == gb
        atr_res = HEX('D501 00010203040506070809 0000000B32') + gb
        clf.sense.return_value = nfc.clf.RemoteTarget("106A", atr_res=atr_res)
        assert llc.activate(nfc.dep.Initiator(clf), brs=0) is bool(gb)
        assert not gb or clf.sense.mock_calls[0][1][0].atr_req[16:] == gb

    @pytest.mark.parametrize("miu, lto, lsc, sec, gb", [
        (128, 100, 0, False, HEX('')),
        (128, 100, 0, False, HEX('46666D 010113 03020003')),
        (128, 100, 0, True, HEX('46666D 010113 03020003 070104')),
        (128, 100, 1, True, HEX('46666D 010113 03020003 070105')),
        (248, 100, 3, True, HEX('46666D 010113 02020078 03020003 070107')),
        (128, 500, 3, True, HEX('46666D 010113 03020003 040132 070107')),
    ])
    def test_activate_as_target(self, clf, miu, lto, lsc, sec, gb):
        options = {'miu': miu, 'lto': lto, 'lsc': lsc, 'sec': sec}
        llc = nfc.llcp.llc.LogicalLinkController(**options)
        atr_req = HEX('D400 00010203040506070809 00000032') + gb
        dep_req = HEX('D406 000000')
        target = nfc.clf.LocalTarget("106A", atr_req=atr_req, dep_req=dep_req)
        clf.listen.return_value = target
        assert llc.activate(nfc.dep.Target(clf), rwt=9) is bool(gb)
        assert not gb or clf.listen.mock_calls[0][1][0].atr_res[17:] == gb
        assert not gb or llc.mac.rwt == 4096/13.56E6 * pow(2, 9)

    @pytest.mark.parametrize("options, gb, string", [
        ({}, HEX('46666D 010113 02020078 040132'),
         "LLC: Local(MIU=248, LTO=500ms) Remote(MIU=248, LTO=500ms)"),
        ({'miu': 128, 'lto': 100}, HEX('46666D 010113'),
         "LLC: Local(MIU=128, LTO=100ms) Remote(MIU=128, LTO=100ms)"),
    ])
    def test_format_str(self, clf, options, gb, string):
        llc = nfc.llcp.llc.LogicalLinkController(**options)
        atr_res = HEX('D501 00010203040506070809 0000000832') + gb
        clf.sense.return_value = nfc.clf.RemoteTarget("106A", atr_res=atr_res)
        assert llc.activate(nfc.dep.Initiator(clf), brs=0) is True
        assert str(llc) == string
