# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import threading
import pytest
import errno
import mock
import time

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
        assert str(llc.link) == "CONNECTED"
        assert str(llc.pcnt) == "sent/rcvd 0/0"

    # -------------------------------------------------------------------------
    # class BaseTestAs - tests run equal for Initiator and Target LLC
    # -------------------------------------------------------------------------
    class BaseTestAs:
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

        @pytest.mark.parametrize("socket_type, socket_class", [
            (nfc.llcp.llc.RAW_ACCESS_POINT, nfc.llcp.tco.RawAccessPoint),
            (nfc.llcp.LOGICAL_DATA_LINK, nfc.llcp.tco.LogicalDataLink),
            (nfc.llcp.DATA_LINK_CONNECTION, nfc.llcp.tco.DataLinkConnection),
            (3, type(None)),
        ])
        def test_socket(self, llc, socket_type, socket_class):
            assert isinstance(llc.socket(socket_type), socket_class)

        @pytest.fixture
        def raw(self, llc):
            return llc.socket(nfc.llcp.llc.RAW_ACCESS_POINT)

        @pytest.fixture
        def ldl(self, llc):
            return llc.socket(nfc.llcp.LOGICAL_DATA_LINK)

        @pytest.fixture
        def dlc(self, llc):
            return llc.socket(nfc.llcp.DATA_LINK_CONNECTION)

        def test_setsockopt(self, llc, dlc):
            assert llc.setsockopt(dlc, nfc.llcp.SO_RCVMIU, 128) == 128
            assert llc.setsockopt(dlc, nfc.llcp.SO_RCVMIU, 248) == 248
            assert llc.setsockopt(dlc, nfc.llcp.SO_RCVMIU, 249) == 248
            assert llc.setsockopt(dlc, nfc.llcp.SO_RCVBUF, 10) == 10
            assert llc.setsockopt(dlc, nfc.llcp.SO_RCVBUF, 15) == 15
            assert llc.setsockopt(dlc, nfc.llcp.SO_RCVBUF, 16) == 15
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.setsockopt(object(), nfc.llcp.SO_RCVMIU, 128)
            assert excinfo.value.errno == errno.ENOTSOCK

        def test_getsockopt(self, llc, raw, ldl, dlc):
            assert llc.getsockopt(raw, nfc.llcp.SO_RCVMIU) == 248
            assert llc.getsockopt(raw, nfc.llcp.SO_SNDMIU) == 248
            assert llc.getsockopt(ldl, nfc.llcp.SO_RCVMIU) == 248
            assert llc.getsockopt(ldl, nfc.llcp.SO_SNDMIU) == 248
            assert llc.getsockopt(dlc, nfc.llcp.SO_RCVMIU) == 128
            assert llc.getsockopt(dlc, nfc.llcp.SO_SNDMIU) == 128
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.getsockopt(object(), nfc.llcp.SO_RCVMIU)
            assert excinfo.value.errno == errno.ENOTSOCK

        def test_bind_by_none(self, llc, raw, ldl, dlc):
            llc.bind(dlc)
            assert llc.getsockname(dlc) == 32
            for sap in range(33, 64):
                sock = llc.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
                llc.bind(sock)
                assert llc.getsockname(sock) == sap
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(ldl)
            assert excinfo.value.errno == errno.EAGAIN

        def test_bind_by_addr(self, llc, raw, ldl, dlc):
            llc.bind(raw, 16)
            assert llc.getsockname(raw) == 16
            for i, sock in enumerate([ldl, dlc]):
                with pytest.raises(nfc.llcp.Error) as excinfo:
                    llc.bind(sock, 16)
                assert excinfo.value.errno == errno.EACCES
            llc.bind(ldl, 63)
            assert llc.getsockname(ldl) == 63
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(dlc, 63)
            assert excinfo.value.errno == errno.EADDRINUSE
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(dlc, 64)
            assert excinfo.value.errno == errno.EFAULT
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(dlc, -1)
            assert excinfo.value.errno == errno.EFAULT
            llc.bind(dlc, 62)
            assert llc.getsockname(dlc) == 62

        def test_bind_by_name(self, llc, raw, ldl, dlc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(dlc, 'urn:nfc:snep')
            assert excinfo.value.errno == errno.EFAULT
            llc.bind(dlc, 'urn:nfc:sn:snep')
            assert llc.getsockname(dlc) == 4
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(ldl, 'urn:nfc:sn:snep')
            assert excinfo.value.errno == errno.EADDRINUSE
            llc.bind(ldl, 'urn:nfc:xsn:nfcpy.org:service')
            assert llc.getsockname(ldl) == 16
            for sap in range(17, 32):
                sock = llc.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
                llc.bind(sock, 'urn:nfc:sn:use_sap-{}'.format(sap))
                assert llc.getsockname(sock) == sap
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(raw, 'urn:nfc:sn:sap-32')
            assert excinfo.value.errno == errno.EADDRNOTAVAIL

        def test_bind_notsock(self, llc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(object())
            assert excinfo.value.errno == errno.ENOTSOCK

        def test_bind_isbound(self, llc, raw):
            llc.bind(raw)
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(raw)
            assert excinfo.value.errno == errno.EINVAL

        def test_bind_notype(self, llc, raw):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.bind(raw, float(0))
            assert excinfo.value.errno == errno.EFAULT

        @pytest.mark.parametrize("peer_miu, send_miu", [
            (128, 128), (248, 248), (249, 248),
        ])
        def test_connect(self, llc, ldl, dlc, peer_miu, send_miu):
            def collect_and_dispatch(llc):
                llc.collect()
                llc.dispatch(nfc.llcp.pdu.ConnectionComplete(32, 16, peer_miu))
            threading.Timer(0.01, collect_and_dispatch, (llc,)).start()
            llc.bind(dlc, 32)
            llc.connect(dlc, 16)
            assert llc.getsockopt(dlc, nfc.llcp.SO_SNDMIU) == send_miu
            llc.connect(ldl, 17)
            assert llc.getsockname(ldl) == 33
            assert llc.getpeername(ldl) == 17
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.connect(object(), 18)
            assert excinfo.value.errno == errno.ENOTSOCK

        @pytest.mark.parametrize("bind", [True, False])
        def test_listen(self, llc, ldl, dlc, bind):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.listen(object(), 0)
            assert excinfo.value.errno == errno.ENOTSOCK
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.listen(ldl, 0)
            assert excinfo.value.errno == errno.EOPNOTSUPP
            with pytest.raises(TypeError) as excinfo:
                llc.listen(dlc, 0.1)
            assert str(excinfo.value) == "backlog must be int type"
            with pytest.raises(ValueError) as excinfo:
                llc.listen(dlc, -1)
            assert str(excinfo.value) == "backlog can not be negative"
            if bind:
                llc.bind(dlc)
            llc.listen(dlc, 0)
            assert dlc.state.LISTEN is True

        @pytest.mark.parametrize("peer_miu, send_miu", [
            (128, 128), (248, 248), (249, 248),
        ])
        def test_accept_connect(self, llc, ldl, dlc, peer_miu, send_miu):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.accept(object())
            assert excinfo.value.errno == errno.ENOTSOCK
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.accept(ldl)
            assert excinfo.value.errno == errno.EOPNOTSUPP
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.accept(dlc)
            assert excinfo.value.errno == errno.EINVAL
            connect_pdu = nfc.llcp.pdu.Connect(4, 32, peer_miu)
            threading.Timer(0.01, llc.dispatch, (connect_pdu,)).start()
            llc.bind(dlc, b'urn:nfc:sn:snep')
            llc.listen(dlc, 0)
            sock = llc.accept(dlc)
            assert isinstance(sock, nfc.llcp.tco.DataLinkConnection)
            assert llc.getsockopt(sock, nfc.llcp.SO_SNDMIU) == send_miu
            assert llc.getpeername(sock) == 32
            assert llc.getsockname(sock) == 4

        def test_accept_send_cc(self, llc, dlc):
            llc.bind(dlc, b'urn:nfc:sn:snep')
            llc.listen(dlc, 0)
            threading.Timer(0, llc.accept, (dlc,)).start()
            time.sleep(0.01)
            llc.dispatch(nfc.llcp.pdu.Connect(4, 32))
            pdu = llc.collect(0.01)
            assert isinstance(pdu, nfc.llcp.pdu.ConnectionComplete)
            assert pdu.dsap == 32 and pdu.ssap == 4

        def test_send_with_unconnected_ldl_socket(self, llc, ldl):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.send(ldl, b'123', nfc.llcp.MSG_DONTWAIT)
            assert excinfo.value.errno == errno.EDESTADDRREQ

        def test_send_with_connected_ldl_socket(self, llc, ldl):
            llc.connect(ldl, 16)
            assert llc.send(ldl, b'123', nfc.llcp.MSG_DONTWAIT) is True
            pdu = llc.collect()
            assert isinstance(pdu, nfc.llcp.pdu.UnnumberedInformation)
            assert pdu.dsap == 16 and pdu.ssap == 32 and pdu.data == b'123'

        def test_send_with_unconnected_dlc_socket(self, llc, dlc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.send(dlc, b'123', nfc.llcp.MSG_DONTWAIT)
            assert excinfo.value.errno == errno.ENOTCONN

        def test_send_with_connected_dlc_socket(self, llc, dlc):
            pdu = nfc.llcp.pdu.ConnectionComplete(32, 17)
            threading.Timer(0.01, llc.collect).start()
            threading.Timer(0.02, llc.dispatch, (pdu,)).start()
            llc.connect(dlc, 17)
            llc.send(dlc, b'123', nfc.llcp.MSG_DONTWAIT)
            pdu = llc.collect()
            assert isinstance(pdu, nfc.llcp.pdu.Information)
            assert pdu.dsap == 17 and pdu.ssap == 32 and pdu.data == b'123'

        def test_sendto_with_invalid_socket_type(self, llc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.sendto(object(), b'123', 16, nfc.llcp.MSG_DONTWAIT)
            assert excinfo.value.errno == errno.ENOTSOCK

        def test_sendto_with_invalid_message_type(self, llc, ldl):
            with pytest.raises(TypeError) as excinfo:
                llc.sendto(ldl, u'123', 16, nfc.llcp.MSG_DONTWAIT)
            assert str(excinfo.value) == \
                "the message argument must be a byte string"

        def test_sendto_with_unbound_socket(self, llc, ldl):
            assert llc.sendto(ldl, b'123', 16, nfc.llcp.MSG_DONTWAIT) is True
            pdu = llc.collect()
            assert isinstance(pdu, nfc.llcp.pdu.UnnumberedInformation)
            assert pdu.dsap == 16 and pdu.ssap == 32 and pdu.data == b'123'

        def test_sendto_with_prebound_socket(self, llc, ldl):
            llc.bind(ldl, 32)
            assert llc.sendto(ldl, b'123', 16, nfc.llcp.MSG_DONTWAIT) is True
            pdu = llc.collect()
            assert isinstance(pdu, nfc.llcp.pdu.UnnumberedInformation)
            assert pdu.dsap == 16 and pdu.ssap == 32 and pdu.data == b'123'

        def test_sendto_on_raw_socket_data_must_be_pdu(self, llc, raw):
            with pytest.raises(TypeError) as excinfo:
                llc.sendto(raw, b'123', 16, nfc.llcp.MSG_DONTWAIT)
            assert str(excinfo.value) == \
                "on a raw access point message must be a pdu"

        def test_sendto_on_raw_unbound_socket(self, llc, raw):
            pdu = nfc.llcp.pdu.UnnumberedInformation(16, 32, b'123')
            llc.sendto(raw, pdu, 16, nfc.llcp.MSG_DONTWAIT)
            pdu = llc.collect()
            assert isinstance(pdu, nfc.llcp.pdu.UnnumberedInformation)
            assert pdu.dsap == 16 and pdu.ssap == 32 and pdu.data == b'123'

        def test_sendto_on_raw_prebound_socket(self, llc, raw):
            llc.bind(raw, 33)
            pdu = nfc.llcp.pdu.UnnumberedInformation(16, 33, b'123')
            llc.sendto(raw, pdu, 16, nfc.llcp.MSG_DONTWAIT)
            pdu = llc.collect()
            assert isinstance(pdu, nfc.llcp.pdu.UnnumberedInformation)
            assert pdu.dsap == 16 and pdu.ssap == 33 and pdu.data == b'123'

        def test_sendto_with_invalid_tco_object(self, llc):
            sock = nfc.llcp.tco.TransmissionControlObject(0, 0)
            llc.sendto(sock, b'', 1, 0)

        def test_recv(self, llc, dlc):
            llc.setsockopt(dlc, nfc.llcp.SO_RCVBUF, 2)
            pdu = nfc.llcp.pdu.ConnectionComplete(32, 17)
            threading.Timer(0.01, llc.collect).start()
            threading.Timer(0.02, llc.dispatch, (pdu,)).start()
            llc.connect(dlc, 17)
            pdu = nfc.llcp.pdu.Information(32, 17, 0, 0, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            assert llc.recv(dlc) == b'123'
            assert llc.collect() == nfc.llcp.pdu.ReceiveReady(17, 32, 1)

        def test_recvfrom_with_invalid_socket_type(self, llc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.recvfrom(object())
            assert excinfo.value.errno == errno.ENOTSOCK

        def test_recvfrom_with_unbound_socket(self, llc, ldl):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.recvfrom(ldl)
            assert excinfo.value.errno == errno.EBADF

        def test_recvfrom_with_raw_socket(self, llc, raw):
            pdu = nfc.llcp.pdu.UnnumberedInformation(32, 17, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            llc.bind(raw, 32)
            assert llc.recvfrom(raw) == (pdu, None)

        def test_recvfrom_with_ldl_socket(self, llc, ldl):
            pdu = nfc.llcp.pdu.UnnumberedInformation(32, 17, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            llc.bind(ldl, 32)
            assert llc.recvfrom(ldl) == (b'123', 17)

        def test_recvfrom_with_dlc_socket(self, llc, dlc):
            pdu = nfc.llcp.pdu.ConnectionComplete(32, 17)
            threading.Timer(0.01, llc.collect).start()
            threading.Timer(0.02, llc.dispatch, (pdu,)).start()
            llc.connect(dlc, 17)
            pdu = nfc.llcp.pdu.Information(32, 17, 0, 0, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            assert llc.recvfrom(dlc) == (b'123', 17)

        def test_recvfrom_with_invalid_tco_object(self, llc):
            sock = nfc.llcp.tco.TransmissionControlObject(0, 0)
            sock.addr = 1
            llc.recvfrom(sock)

        def test_poll(self, llc, ldl):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.poll(object(), 'recv')
            assert excinfo.value.errno == errno.ENOTSOCK
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.poll(ldl, 'recv')
            assert excinfo.value.errno == errno.EBADF
            llc.bind(ldl)
            pdu = nfc.llcp.pdu.UnnumberedInformation(32, 17, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            assert llc.poll(ldl, 'recv') is True

        def test_close(self, llc, ldl, dlc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.close(object())
            assert excinfo.value.errno == errno.ENOTSOCK
            llc.bind(ldl)
            llc.close(ldl)
            assert ldl.state.SHUTDOWN is True
            llc.close(dlc)
            assert dlc.state.SHUTDOWN is True

        def test_getsockname_with_invalid_socket_type(self, llc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.getsockname(object())
            assert excinfo.value.errno == errno.ENOTSOCK

        def test_getpeername_with_invalid_socket_type(self, llc):
            with pytest.raises(nfc.llcp.Error) as excinfo:
                llc.getpeername(object())
            assert excinfo.value.errno == errno.ENOTSOCK

        def test_collect_raw_socket_large_pdu(self, llc, raw):
            assert llc.cfg['send-miu'] == 248
            pdu = nfc.llcp.pdu.UnnumberedInformation(16, 32, 248 * b'1')
            llc.sendto(raw, pdu, 16, nfc.llcp.MSG_DONTWAIT)
            assert llc.collect() == pdu

        def test_collect_with_aggregation(self, llc, ldl):
            assert llc.cfg['send-miu'] == 248
            llc.sendto(ldl, 100 * b'1', 16, nfc.llcp.MSG_DONTWAIT)
            llc.sendto(ldl, 100 * b'2', 16, nfc.llcp.MSG_DONTWAIT)
            assert llc.collect() == nfc.llcp.pdu.AggregatedFrame(0, 0, [
                nfc.llcp.pdu.UnnumberedInformation(16, 32, 100 * b'1'),
                nfc.llcp.pdu.UnnumberedInformation(16, 32, 100 * b'2'),
            ])
            llc.sendto(ldl, 120 * b'3', 16, nfc.llcp.MSG_DONTWAIT)
            llc.sendto(ldl, 119 * b'4', 16, nfc.llcp.MSG_DONTWAIT)
            assert llc.collect() == nfc.llcp.pdu.AggregatedFrame(0, 0, [
                nfc.llcp.pdu.UnnumberedInformation(16, 32, 120 * b'3'),
                nfc.llcp.pdu.UnnumberedInformation(16, 32, 119 * b'4'),
            ])
            llc.sendto(ldl, 120 * b'5', 16, nfc.llcp.MSG_DONTWAIT)
            llc.sendto(ldl, 120 * b'6', 16, nfc.llcp.MSG_DONTWAIT)
            assert llc.collect() == \
                nfc.llcp.pdu.UnnumberedInformation(16, 32, 120 * b'5')
            assert llc.collect() == \
                nfc.llcp.pdu.UnnumberedInformation(16, 32, 120 * b'6')

        def test_collect_voluntary_ack_before_aggregation(self, llc):
            dlc = [None, None, None]
            for i in range(len(dlc)):
                dlc[i] = llc.socket(nfc.llcp.DATA_LINK_CONNECTION)
                llc.setsockopt(dlc[i], nfc.llcp.SO_RCVBUF, 2)
                pdu = nfc.llcp.pdu.ConnectionComplete(32+i, 16+i)
                threading.Timer(0.01, llc.collect).start()
                threading.Timer(0.02, llc.dispatch, (pdu,)).start()
                llc.connect(dlc[i], 16+i)

            pdu = nfc.llcp.pdu.Information(32, 16, 0, 0, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            assert llc.recv(dlc[0]) == b'123'
            assert llc.collect() == nfc.llcp.pdu.ReceiveReady(16, 32, 1)

        def test_collect_voluntary_ack_within_aggregation(self, llc):
            dlc = [None, None, None, None]
            for i in range(len(dlc)):
                dlc[i] = llc.socket(nfc.llcp.DATA_LINK_CONNECTION)
                llc.setsockopt(dlc[i], nfc.llcp.SO_RCVBUF, 2)
                pdu = nfc.llcp.pdu.ConnectionComplete(32+i, 16+i, 248)
                threading.Timer(0.01, llc.collect).start()
                threading.Timer(0.02, llc.dispatch, (pdu,)).start()
                llc.connect(dlc[i], 16+i)

            llc.send(dlc[0], 230 * b'1', nfc.llcp.MSG_DONTWAIT)
            pdu = nfc.llcp.pdu.Information(33, 17, 0, 0, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            assert llc.recv(dlc[1]) == b'123'
            pdu = nfc.llcp.pdu.Information(34, 18, 0, 0, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            assert llc.recv(dlc[2]) == b'123'
            pdu = nfc.llcp.pdu.Information(35, 19, 0, 0, b'123')
            threading.Timer(0.01, llc.dispatch, (pdu,)).start()
            assert llc.recv(dlc[3]) == b'123'
            assert llc.collect() == nfc.llcp.pdu.AggregatedFrame(0, 0, [
                nfc.llcp.pdu.Information(16, 32, 0, 0, 230 * b'1'),
                nfc.llcp.pdu.ReceiveReady(17, 33, 1),
                nfc.llcp.pdu.ReceiveReady(18, 34, 1)
            ])
            assert llc.collect() == nfc.llcp.pdu.ReceiveReady(19, 35, 1)

        def test_dispatch_aggregated_frame(self, llc):
            aggregate = 3 * [nfc.llcp.pdu.Symmetry()]
            llc.dispatch(nfc.llcp.pdu.AggregatedFrame(0, 0, aggregate))
            llc.dispatch(nfc.llcp.pdu.AggregatedFrame(1, 0, aggregate))

        def test_dispatch_connect_by_name(self, llc, dlc):
            llc.dispatch(nfc.llcp.pdu.Connect(1, 32, sn=b'urn:nfc:sn:service'))
            assert llc.collect() == nfc.llcp.pdu.DisconnectedMode(32, 1, 2)
            llc.bind(dlc, b'urn:nfc:sn:service')
            llc.listen(dlc, 1)
            llc.dispatch(nfc.llcp.pdu.Connect(1, 32, sn=b'urn:nfc:sn:service'))
            llc.accept(dlc)
            assert llc.collect() == nfc.llcp.pdu.ConnectionComplete(32, 16)

        def test_dispatch_to_inactive_sap(self, llc):
            llc.dispatch(nfc.llcp.pdu.UnnumberedInformation(63, 63))

    # -------------------------------------------------------------------------
    # class TestAsInitiator - Initiator specific fixtures and tests
    # -------------------------------------------------------------------------
    class TestAsInitiator(BaseTestAs):
        @pytest.fixture
        def target(self):
            atr_res = 'D50100010203040506070809000000083246666D01011302020078'
            return nfc.clf.RemoteTarget("106A", atr_res=HEX(atr_res))

        @pytest.fixture
        def sec_target(self):
            atr_res = 'D50100010203040506070809000000083246666D010113070107'
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

        def test_collect_with_aggregation_sec(self, sec_llc, cipher, ldl):
            ecpk = HEX('0A40') + cipher.public_key_x + cipher.public_key_y
            rand = HEX('0B08') + cipher.random_nonce
            sec_llc.mac.exchange.side_effect = [
                HEX('0280') + ecpk + rand, HEX('0000'), None
            ]
            sec_llc.run_as_initiator()
            assert sec_llc.sec is not None
            sec_llc.sendto(ldl, 10 * b'1', 16, nfc.llcp.MSG_DONTWAIT)
            sec_llc.sendto(ldl, 10 * b'2', 16, nfc.llcp.MSG_DONTWAIT)
            agf = sec_llc.collect()
            assert isinstance(agf, nfc.llcp.pdu.AggregatedFrame)
            assert agf.count == 2
            for pdu in agf:
                assert isinstance(pdu, nfc.llcp.pdu.UnnumberedInformation)

        def test_dispatch_encrypted_ui_pdu(self, sec_llc, cipher, ldl):
            ecpk = HEX('0A40') + cipher.public_key_x + cipher.public_key_y
            rand = HEX('0B08') + cipher.random_nonce
            sec_llc.mac.exchange.side_effect = [
                HEX('0280') + ecpk + rand, HEX('0000'), None
            ]
            sec_llc.run_as_initiator()
            assert sec_llc.sec is not None

            pubkey = sec_llc.sec.public_key_x + sec_llc.sec.public_key_y
            random = sec_llc.sec.random_nonce
            cipher.calculate_session_key(pubkey, rn_i=random)

            pdu = nfc.llcp.pdu.UnnumberedInformation(16, 32, b'123')
            a = pdu.encode_header()
            c = cipher.encrypt(a, pdu.data)
            pdu = type(pdu)(*type(pdu).decode_header(a), data=c)
            sec_llc.bind(ldl, b'urn:nfc:sn:service')
            sec_llc.dispatch(pdu)

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

        def test_run_send_pdu_and_symm(self, llc, ldl):
            llc.mac.exchange.side_effect = 10 * [HEX('0000')] + [None]
            llc.sendto(ldl, b'123', 16, nfc.llcp.MSG_DONTWAIT)
            llc.run_as_initiator()
            assert llc.mac.exchange.mock_calls == [
                mock.call(HEX('40e0313233'), 0.11)
            ] + 10 * [
                mock.call(HEX('0000'), 0.11)
            ]
            assert str(llc.pcnt) == "sent/rcvd 11/10 SYMM 10/10 UI 1/0"

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

    # -------------------------------------------------------------------------
    # class TestAsTarget - Target specific fixtures and tests
    # -------------------------------------------------------------------------
    class TestAsTarget(BaseTestAs):
        @pytest.fixture
        def target(self):
            atr_req = 'D400 000102030405060708090000003246666D01011302020078'
            return nfc.clf.RemoteTarget("106A", atr_req=HEX(atr_req),
                                        dep_req=HEX('D406 000000'))

        @pytest.fixture
        def sec_target(self):
            atr_req = 'D400 000102030405060708090000003246666D010113070107'
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

        def test_run_send_pdu_and_symm(self, llc, ldl):
            llc.mac.exchange.side_effect = 10 * [HEX('0000')] + [None]
            llc.sendto(ldl, b'123', 16, nfc.llcp.MSG_DONTWAIT)
            llc.run_as_target()
            print(llc.mac.exchange.mock_calls)
            assert llc.mac.exchange.mock_calls == [
                mock.call(None, 0.11),
                mock.call(HEX('40e0313233'), 0.11),
            ] + 9 * [
                mock.call(HEX('0000'), 0.11)
            ]
            assert str(llc.pcnt) == "sent/rcvd 10/10 SYMM 9/10 UI 1/0"

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


# =============================================================================
# Service Access Point
# =============================================================================
class TestServiceAccessPoint:
    @pytest.fixture
    def llc(self,):
        return nfc.llcp.llc.LogicalLinkController()

    @pytest.fixture
    def sap(self, llc):
        sap = nfc.llcp.llc.ServiceAccessPoint(16, llc)
        assert str(sap) == "SAP 16"
        return sap

    def test_mode(self, sap):
        assert sap.mode == 0
        sap.sock_list.appendleft(nfc.llcp.tco.RawAccessPoint(128))
        assert sap.mode == nfc.llcp.llc.RAW_ACCESS_POINT
        sap.sock_list.appendleft(nfc.llcp.tco.LogicalDataLink(128))
        assert sap.mode == nfc.llcp.LOGICAL_DATA_LINK
        sap.sock_list.appendleft(nfc.llcp.tco.DataLinkConnection(128, 1))
        assert sap.mode == nfc.llcp.DATA_LINK_CONNECTION
        sap.sock_list.appendleft(object())
        assert sap.mode is None

    def test_insert_socket(self, sap):
        assert sap.insert_socket(nfc.llcp.tco.LogicalDataLink(128))
        assert not sap.insert_socket(nfc.llcp.tco.DataLinkConnection(128, 1))
        assert sap.insert_socket(nfc.llcp.tco.LogicalDataLink(128))

    def test_remove_socket(self, sap):
        sock_1 = nfc.llcp.tco.LogicalDataLink(128)
        sock_2 = nfc.llcp.tco.LogicalDataLink(128)
        assert sap.insert_socket(sock_1)
        assert sap.insert_socket(sock_2)
        assert len(sap.sock_list) == 2
        sap.remove_socket(sock_1)
        assert len(sap.sock_list) == 1
        sap.remove_socket(sock_1)
        assert len(sap.sock_list) == 1
        sap.remove_socket(sock_2)
        assert len(sap.sock_list) == 0
        assert sap.llc.sap[sap.addr] is None

    def test_enqueue_connect_but_no_socket(self, sap):
        sap.enqueue(nfc.llcp.pdu.Connect(16, 32))
        assert sap.dequeue(128, 0) == nfc.llcp.pdu.DisconnectedMode(32, 16, 2)

    def test_enqueue_connect_but_not_listening(self, sap):
        sap.insert_socket(nfc.llcp.tco.LogicalDataLink(128))
        sap.enqueue(nfc.llcp.pdu.Connect(16, 32))
        assert sap.dequeue(128, 0) == nfc.llcp.pdu.DisconnectedMode(32, 16, 2)

    def test_enqueue_ldl_pdu_but_no_socket(self, sap):
        sap.enqueue(nfc.llcp.pdu.UnnumberedInformation(16, 32))
        assert sap.dequeue(128, 0) is None

    def test_enqueue_ldl_pdu_but_wrong_peer(self, sap):
        sap.insert_socket(nfc.llcp.tco.LogicalDataLink(128))
        sap.sock_list[0].peer = 63
        sap.enqueue(nfc.llcp.pdu.UnnumberedInformation(16, 32))
        assert sap.dequeue(128, 0) is None

    def test_enqueue_dlc_pdu_but_no_socket(self, sap):
        sap.enqueue(nfc.llcp.pdu.Information(16, 32, 0, 0))
        assert sap.dequeue(128, 0) == nfc.llcp.pdu.DisconnectedMode(32, 16, 1)

    def test_enqueue_dlc_pdu_but_wrong_peer(self, sap):
        sap.insert_socket(nfc.llcp.tco.DataLinkConnection(128, 1))
        sap.sock_list[0].peer = 63
        sap.enqueue(nfc.llcp.pdu.Information(16, 32, 0, 0))
        assert sap.dequeue(128, 0) == nfc.llcp.pdu.DisconnectedMode(32, 16, 1)


# =============================================================================
# Service Discovery
# =============================================================================
class TestServiceDiscovery:
    @pytest.fixture
    def llc(self,):
        return nfc.llcp.llc.LogicalLinkController()

    @pytest.fixture
    def sdp(self, llc):
        return nfc.llcp.llc.ServiceDiscovery(llc)

    def test_format_str(self, sdp):
        assert str(sdp) == "SAP  1"

    def test_resolve_after_shutdown(self, sdp):
        sdp.shutdown()
        assert sdp.resolve(b'urn:nfc:sn:sdp') is None

    def test_enqueue_not_snl_pdu(self, sdp):
        sdp.enqueue(nfc.llcp.pdu.Symmetry())
        assert sdp.dequeue(128, 0) is None
        assert len(sdp.snl) == 0

    def test_enqueue_tid_was_not_requested(self, sdp):
        sdp.enqueue(nfc.llcp.pdu.ServiceNameLookup(1, 1, sdres=[(101, 16)]))
        assert sdp.dequeue(128, 0) is None
        assert len(sdp.snl) == 0

    def test_enqueue_csn_flag_in_sdres(self, sdp):
        sdp.sent[101] = 'urn:nfc:sn:service'
        sdp.enqueue(nfc.llcp.pdu.ServiceNameLookup(1, 1, sdres=[(101, 0x40)]))
        assert sdp.resolve('urn:nfc:sn:service') == 1

    def test_enqueue_resolve_name(self, sdp):
        sdreq = [(101, 'urn:nfc:sn:service')]
        sdp.enqueue(nfc.llcp.pdu.ServiceNameLookup(1, 1, sdreq=sdreq))
        assert sdp.dequeue(128, 0) == \
            nfc.llcp.pdu.ServiceNameLookup(1, 1, sdres=[(101, 0)])

    def test_dequeue_miu_is_exhausted(self, sdp):
        sdp.sdreq.append((2, 'urn:nfc:sn:svc'))
        recv_sdreq = [(101, 'urn:nfc:sn:service')]
        sdp.enqueue(nfc.llcp.pdu.ServiceNameLookup(1, 1, sdreq=recv_sdreq))
        assert sdp.dequeue(0, 0) == nfc.llcp.pdu.ServiceNameLookup(1, 1)
        assert sdp.dequeue(8, 0) == \
            nfc.llcp.pdu.ServiceNameLookup(1, 1, sdres=[(101, 0)])
        assert sdp.dequeue(128, 0) == \
            nfc.llcp.pdu.ServiceNameLookup(1, 1, sdreq=[(2, 'urn:nfc:sn:svc')])
