# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import threading
import pytest
import mock

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


@pytest.fixture(scope="module")
def cipher():
    return nfc.llcp.sec.cipher_suite("ECDH_anon_WITH_AEAD_AES_128_CCM_4")


@pytest.fixture()
def clf(mocker):
    clf = nfc.clf.ContactlessFrontend()
    mocker.patch.object(clf, 'sense', autospec=True)
    mocker.patch.object(clf, 'listen', autospec=True)
    mocker.patch.object(clf, 'exchange', autospec=True)
    clf.sense.return_value = None
    clf.listen.return_value = None
    clf.exchange.side_effect = nfc.clf.CommunicationError
    return clf


# =============================================================================
# Service Access Point
# =============================================================================
class TestServiceAccessPoint:
    @pytest.fixture
    def llc(self,):
        llc = nfc.llcp.llc.LogicalLinkController()
        assert llc.cfg['recv-miu'] == 248
        assert llc.cfg['send-lto'] == 500
        assert llc.cfg['send-lsc'] == 3
        assert llc.cfg['send-agf'] is True
        assert llc.cfg['llcp-sec'] is True
        return llc

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

    @pytest.mark.parametrize("socket_type, socket_class", [
        (nfc.llcp.llc.RAW_ACCESS_POINT, nfc.llcp.tco.RawAccessPoint),
        (nfc.llcp.llc.LOGICAL_DATA_LINK, nfc.llcp.tco.LogicalDataLink),
        (nfc.llcp.llc.DATA_LINK_CONNECTION, nfc.llcp.tco.DataLinkConnection),
        (3, type(None)),
    ])
    def test_socket(self, socket_type, socket_class):
        sock = nfc.llcp.llc.LogicalLinkController().socket(socket_type)
        assert isinstance(sock, socket_class)

    # -------------------------------------------------------------------------
    # Test As Initiator
    # -------------------------------------------------------------------------
    class TestAsInitiator:
        @pytest.fixture
        def target(self):
            atr_res = 'D501000102030405060708090000000832 46666D 010113'
            return nfc.clf.RemoteTarget("106A", atr_res=HEX(atr_res))

        @pytest.fixture
        def sec_target(self):
            atr_res = 'D501000102030405060708090000000832 46666D 010113 070107'
            return nfc.clf.RemoteTarget("106A", atr_res=HEX(atr_res))

        @pytest.fixture
        def mac(self, mocker, clf, target):
            clf.sense.return_value = target
            mac = nfc.dep.Initiator(clf)
            mocker.patch.object(mac, 'exchange', autospec=True)
            mac.exchange.return_value = None
            return mac

        @pytest.fixture
        def sec_mac(self, mocker, clf, sec_target):
            clf.sense.return_value = sec_target
            mac = nfc.dep.Initiator(clf)
            mocker.patch.object(mac, 'exchange', autospec=True)
            mac.exchange.return_value = None
            return mac

        @pytest.fixture
        def llc(self, mac):
            llc = nfc.llcp.llc.LogicalLinkController()
            assert llc.activate(mac, brs=0) is True
            return llc

        @pytest.fixture
        def sec_llc(self, sec_mac):
            llc = nfc.llcp.llc.LogicalLinkController()
            assert llc.activate(sec_mac, brs=0) is True
            return llc

        @pytest.mark.parametrize("miu, lto, lsc, sec, gb", [
            (128, 100, 0, False, HEX('')),
            (128, 100, 0, False, HEX('46666D 010113 03020003')),
            (128, 100, 0, True, HEX('46666D 010113 03020003 070104')),
            (128, 100, 1, True, HEX('46666D 010113 03020003 070105')),
            (248, 100, 3, True, HEX('46666D 010113 02020078 03020003 070107')),
            (128, 500, 3, True, HEX('46666D 010113 03020003 040132 070107')),
        ])
        def test_activate(self, clf, miu, lto, lsc, sec, gb):
            options = {'miu': miu, 'lto': lto, 'lsc': lsc, 'sec': sec}
            llc = nfc.llcp.llc.LogicalLinkController(**options)
            atr_res = HEX('D501 00010203040506070809 0000000832') + gb
            target = nfc.clf.RemoteTarget("106A", atr_res=atr_res)
            clf.sense.return_value = target
            assert llc.activate(nfc.dep.Initiator(clf), brs=0) is bool(gb)
            assert not gb or clf.sense.mock_calls[0][1][0].atr_req[16:] == gb
            atr_res = HEX('D501 00010203040506070809 0000000B32') + gb
            target = nfc.clf.RemoteTarget("106A", atr_res=atr_res)
            clf.sense.return_value = target
            assert llc.activate(nfc.dep.Initiator(clf), brs=0) is bool(gb)
            assert not gb or clf.sense.mock_calls[0][1][0].atr_req[16:] == gb

        def test_run_with_secure_llc(self, sec_llc, cipher):
            ecpk = HEX('0A40') + cipher.public_key_x + cipher.public_key_y
            rand = HEX('0B08') + cipher.random_nonce
            sec_llc.mac.exchange.side_effect = [
                HEX('0280') + ecpk + rand, HEX('0000'), None
            ]
            sec_llc.run_as_initiator()
            assert sec_llc.secure_data_transfer is True
            sec_llc.mac.exchange.assert_called_with(HEX('0000'), 0.11)

        @pytest.mark.parametrize("dpu, ecpk, rand", [
            (HEX('0000'), HEX('0A40' + 64 * '00'), HEX('0B08' + 8 * '00')),
            (HEX('0280'), HEX('0A40' + 64 * '00'), HEX('0B07' + 7 * '00')),
            (HEX('0280'), HEX('0A3F' + 63 * '00'), HEX('0B08' + 8 * '00')),
            (HEX('0280'), HEX('0A40' + 64 * '00'), HEX('')),
            (HEX('0280'), HEX(''), HEX('0B08' + 8 * '00')),
        ])
        def test_run_with_dps_error(self, sec_llc, dpu, ecpk, rand):
            sec_llc.mac.exchange.side_effect = [dpu + ecpk + rand]
            sec_llc.run_as_initiator()
            assert sec_llc.link.SHUTDOWN is True

        def test_run_with_long_symmetry(self, llc):
            llc.mac.exchange.side_effect = 10 * [HEX('0000')] + [None]
            llc.run_as_initiator()
            assert llc.mac.exchange.mock_calls == 11 * [
                mock.call(HEX('0000'), 0.11)
            ]

        def test_run_with_local_terminate(self, llc):
            llc.mac.exchange.side_effect = [HEX('01C0')]
            llc.run_as_initiator(terminate=lambda: True)
            assert llc.mac.exchange.mock_calls == [
                mock.call(HEX('0140'), 0.5),
            ]

        def test_run_with_remote_terminate(self, llc):
            llc.mac.exchange.side_effect = [HEX('0000'), HEX('0140')]
            llc.run_as_initiator()
            assert llc.mac.exchange.mock_calls == [
                mock.call(HEX('0000'), 0.11),
                mock.call(HEX('0000'), 0.11),
            ]

        def test_run_with_kbd_interrupt(self, llc):
            llc.mac.exchange.side_effect \
                = [HEX('0000'), KeyboardInterrupt, None]
            with pytest.raises(KeyboardInterrupt):
                llc.run_as_initiator()
            assert llc.mac.exchange.mock_calls == [
                mock.call(HEX('0000'), 0.11),
                mock.call(HEX('0000'), 0.11),
                mock.call(HEX('0140'), 0.5),
            ]

        def test_run_with_io_error(self, llc):
            llc.mac.exchange.side_effect = [HEX('0000'), IOError]
            with pytest.raises(SystemExit):
                llc.run_as_initiator()
            assert llc.mac.exchange.mock_calls == [
                mock.call(HEX('0000'), 0.11),
                mock.call(HEX('0000'), 0.11),
            ]

        @pytest.mark.parametrize("error", [
            nfc.llcp.sec.KeyAgreementError,
            nfc.llcp.sec.DecryptionError,
            nfc.llcp.sec.EncryptionError,
        ])
        def test_run_with_sec_error(self, llc, error):
            llc.mac.exchange.side_effect = [error]
            with pytest.raises(SystemExit):
                llc.run_as_initiator()
            assert llc.mac.exchange.mock_calls == [
                mock.call(HEX('0000'), 0.11),
            ]

        @pytest.mark.parametrize("name, sap", [
            ('urn:nfc:sn:sdp', 1),
            ('urn:nfc:sn:snep', 4),
            ('urn:nfc:sn:unknown', 0),
        ])
        def test_resolve(self, llc, name, sap):
            def collect_and_dispatch(llc):
                tid = llc.collect().sdreq[0][0]
                pdu = nfc.llcp.pdu.ServiceNameLookup(1, 1, sdres=[(tid, sap)])
                llc.dispatch(pdu)
            threading.Timer(0.01, collect_and_dispatch, (llc,)).start()
            assert llc.resolve(name) == sap

    # -------------------------------------------------------------------------
    # Test As Target
    # -------------------------------------------------------------------------
    class TestAsTarget:
        @pytest.fixture
        def target(self):
            atr_req = 'D400 0001020304050607080900000032 46666D 010113'
            return nfc.clf.RemoteTarget("106A", atr_req=HEX(atr_req),
                                        dep_req=HEX('D406 000000'))

        @pytest.fixture
        def sec_target(self):
            atr_req = 'D400 0001020304050607080900000032 46666D 010113 070107'
            return nfc.clf.RemoteTarget("106A", atr_req=HEX(atr_req),
                                        dep_req=HEX('D406 000000'))

        @pytest.fixture
        def mac(self, mocker, clf, target):
            clf.listen.return_value = target
            mac = nfc.dep.Target(clf)
            mocker.patch.object(mac, 'exchange', autospec=True)
            mac.exchange.return_value = None
            return mac

        @pytest.fixture
        def sec_mac(self, mocker, clf, sec_target):
            clf.listen.return_value = sec_target
            mac = nfc.dep.Target(clf)
            mocker.patch.object(mac, 'exchange', autospec=True)
            mac.exchange.return_value = None
            return mac

        @pytest.fixture
        def llc(self, mac):
            llc = nfc.llcp.llc.LogicalLinkController()
            assert llc.activate(mac) is True
            return llc

        @pytest.fixture
        def sec_llc(self, sec_mac):
            llc = nfc.llcp.llc.LogicalLinkController()
            assert llc.activate(sec_mac) is True
            return llc

        @pytest.mark.parametrize("miu, lto, lsc, sec, gb", [
            (128, 100, 0, False, HEX('')),
            (128, 100, 0, False, HEX('46666D 010113 03020003')),
            (128, 100, 0, True, HEX('46666D 010113 03020003 070104')),
            (128, 100, 1, True, HEX('46666D 010113 03020003 070105')),
            (248, 100, 3, True, HEX('46666D 010113 02020078 03020003 070107')),
            (128, 500, 3, True, HEX('46666D 010113 03020003 040132 070107')),
        ])
        def test_activate(self, clf, miu, lto, lsc, sec, gb):
            options = {'miu': miu, 'lto': lto, 'lsc': lsc, 'sec': sec}
            llc = nfc.llcp.llc.LogicalLinkController(**options)
            target = nfc.clf.LocalTarget("106A")
            target.atr_req = HEX('D400 00010203040506070809 00000032') + gb
            target.dep_req = HEX('D406 000000')
            clf.listen.return_value = target
            assert llc.activate(nfc.dep.Target(clf), rwt=9) is bool(gb)
            assert not gb or clf.listen.mock_calls[0][1][0].atr_res[17:] == gb
            assert not gb or llc.mac.rwt == 4096/13.56E6 * pow(2, 9)

        def test_run_with_secure_llc(self, sec_llc, cipher):
            ecpk = HEX('0A40') + cipher.public_key_x + cipher.public_key_y
            rand = HEX('0B08') + cipher.random_nonce
            sec_llc.mac.exchange.side_effect = [
                HEX('0280') + ecpk + rand, HEX('0000'), None
            ]
            sec_llc.run_as_target()
            assert sec_llc.secure_data_transfer is True
            sec_llc.mac.exchange.assert_called_with(HEX('0000'), 0.11)

        @pytest.mark.parametrize("dpu, ecpk, rand", [
            (HEX('0000'), HEX('0A40' + 64 * '00'), HEX('0B08' + 8 * '00')),
            (HEX('0280'), HEX('0A40' + 64 * '00'), HEX('0B07' + 7 * '00')),
            (HEX('0280'), HEX('0A3F' + 63 * '00'), HEX('0B08' + 8 * '00')),
            (HEX('0280'), HEX('0A40' + 64 * '00'), HEX('')),
            (HEX('0280'), HEX(''), HEX('0B08' + 8 * '00')),
        ])
        def test_run_with_dps_error(self, sec_llc, dpu, ecpk, rand):
            sec_llc.mac.exchange.side_effect = [dpu + ecpk + rand]
            sec_llc.run_as_target()
            assert sec_llc.link.SHUTDOWN is True

        def test_run_with_long_symmetry(self, llc):
            llc.mac.exchange.side_effect = 10 * [HEX('0000')] + [None]
            llc.run_as_target()
            assert llc.mac.exchange.mock_calls == [
                mock.call(None, 0.11)
            ] + 10 * [
                mock.call(HEX('0000'), 0.11)
            ]

        def test_run_with_local_terminate(self, llc):
            llc.mac.exchange.side_effect = [HEX('0000')]
            llc.run_as_target(terminate=lambda: True)
            assert llc.mac.exchange.mock_calls == [
                mock.call(None, 0.11),
            ]

        def test_run_with_remote_terminate(self, llc):
            llc.mac.exchange.side_effect = [HEX('0000'), HEX('0140')]
            llc.run_as_target()
            assert llc.mac.exchange.mock_calls == [
                mock.call(None, 0.11),
                mock.call(HEX('0000'), 0.11),
            ]

        def test_run_with_kbd_interrupt(self, llc):
            llc.mac.exchange.side_effect \
                = [HEX('0000'), KeyboardInterrupt]
            with pytest.raises(KeyboardInterrupt):
                llc.run_as_target()
            assert llc.mac.exchange.mock_calls == [
                mock.call(None, 0.11),
                mock.call(HEX('0000'), 0.11),
            ]

        def test_run_with_io_error(self, llc):
            llc.mac.exchange.side_effect = [HEX('0000'), IOError]
            with pytest.raises(SystemExit):
                llc.run_as_target()
            assert llc.mac.exchange.mock_calls == [
                mock.call(None, 0.11),
                mock.call(HEX('0000'), 0.11),
            ]

        @pytest.mark.parametrize("error", [
            nfc.llcp.sec.KeyAgreementError,
            nfc.llcp.sec.DecryptionError,
            nfc.llcp.sec.EncryptionError,
        ])
        def test_run_with_sec_error(self, llc, error):
            llc.mac.exchange.side_effect = [error]
            with pytest.raises(SystemExit):
                llc.run_as_target()
            assert llc.mac.exchange.mock_calls == [
                mock.call(None, 0.11),
            ]
