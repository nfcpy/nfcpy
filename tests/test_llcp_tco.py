# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import errno
import pytest
import threading
import nfc.llcp.tco


def HEX(s):
    return bytearray.fromhex(s)


# =============================================================================
# Transmission Control Object
# =============================================================================
class TestTransmissionControlObject:
    @pytest.fixture
    def tco(self):
        tco = nfc.llcp.tco.TransmissionControlObject(10, 10)
        yield tco
        tco.close()
        assert tco.state.SHUTDOWN is True

    def test_init(self):
        tco = nfc.llcp.tco.TransmissionControlObject(10, 20)
        assert tco.send_miu == 10
        assert tco.recv_miu == 20
        assert tco.send_buf == 1
        assert tco.recv_buf == 1
        assert tco.addr is None
        assert tco.peer is None
        assert len(tco.send_queue) == 0
        assert len(tco.recv_queue) == 0
        assert str(tco.state) == "SHUTDOWN"
        assert tco.mode.BLOCK is False
        assert tco.mode.RECV_BUSY is False
        assert tco.mode.SEND_BUSY is False
        assert tco.mode.RECV_BUSY_SENT is False
        assert len(str(tco.mode)) == 81
        assert tco.is_bound is False

    def test_sockopt(self, tco):
        assert tco.getsockopt(nfc.llcp.SO_SNDMIU) == tco.send_miu
        assert tco.getsockopt(nfc.llcp.SO_RCVMIU) == tco.recv_miu
        with pytest.raises(NotImplementedError) as excinfo:
            tco.setsockopt(nfc.llcp.SO_SNDBUF, 0)
        assert str(excinfo.value) == "SO_SNDBUF can not be set"
        assert tco.getsockopt(nfc.llcp.SO_SNDBUF) == 1
        tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        assert tco.getsockopt(nfc.llcp.SO_RCVBUF) == 2
        assert tco.getsockopt(-1) is None
        with pytest.raises(ValueError) as excinfo:
            tco.setsockopt(-1, 0)
        assert str(excinfo.value) == "invalid option value"

    def test_bind(self, tco):
        assert tco.bind(1) == 1 and tco.is_bound is True
        assert tco.bind(1) == 1 and tco.is_bound is True
        assert tco.bind(2) == 2 and tco.is_bound is True
        assert tco.bind(None) is None and tco.is_bound is False

    @pytest.mark.parametrize("pdu", [
        nfc.llcp.pdu.UnnumberedInformation(1, 1, HEX('1122')),
        nfc.llcp.pdu.FrameReject(1, 1),
    ])
    def test_send(self, tco, pdu):
        assert tco.send(pdu, flags=nfc.llcp.MSG_DONTWAIT) is None
        assert tco.dequeue(1, 0, False) is None
        assert tco.dequeue(10, 4, False) == pdu
        assert tco.dequeue(10, 4) is None
        threading.Timer(0.01, tco.dequeue, (10, 4)).start()
        tco.send(pdu, 0)

    @pytest.mark.parametrize("pdu", [
        nfc.llcp.pdu.UnnumberedInformation(1, 1, HEX('1122')),
        nfc.llcp.pdu.FrameReject(1, 1),
    ])
    def test_recv(self, tco, pdu):
        assert tco.enqueue(pdu) is True
        assert tco.enqueue(pdu) is False
        tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        assert tco.enqueue(pdu) is True
        assert tco.enqueue(pdu) is False
        assert tco.recv() == pdu
        assert tco.recv() == pdu
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        tco.recv()

    def test_poll(self, tco):
        pdu = nfc.llcp.pdu.UnnumberedInformation(1, 1, HEX('1122'))
        assert tco.poll("", 1.0) is None
        assert tco.poll("recv", 0.001) is None
        assert tco.enqueue(pdu) is True
        assert tco.poll("recv", 0.001) == pdu
        assert tco.poll("send", 1.0) is True
        assert tco.send(pdu, flags=nfc.llcp.MSG_DONTWAIT) is None
        assert tco.poll("send", 0.001) is False
        assert tco.dequeue(10, 4, False) == pdu
        assert tco.poll("send", 1.0) is True


# =============================================================================
# Raw Access Point
# =============================================================================
class TestRawAccessPoint:
    @pytest.fixture
    def tco(self):
        tco = nfc.llcp.tco.RawAccessPoint(128)
        assert tco.state.ESTABLISHED is True
        yield tco
        tco.close()
        assert tco.state.SHUTDOWN is True

    def test_init(self):
        tco = nfc.llcp.tco.RawAccessPoint(100)
        assert tco.send_miu == 128
        assert tco.recv_miu == 100

    def test_str(self, tco):
        assert str(tco) == "RAW None ->  ?"
        tco.bind(1)
        assert str(tco) == "RAW  1 ->  ?"

    def test_sockopt(self, tco):
        assert tco.getsockopt(nfc.llcp.SO_RCVBUF) == 1
        tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        assert tco.getsockopt(nfc.llcp.SO_RCVBUF) == 2
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        assert excinfo.value.errno == errno.ESHUTDOWN
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.getsockopt(nfc.llcp.SO_RCVBUF)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_poll(self, tco):
        assert tco.poll("recv", 0.001) is False
        assert tco.poll("send", 0.001) is True
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.poll("invalid", 1)
        assert excinfo.value.errno == errno.EINVAL
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.poll("recv", 1)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_send(self, tco):
        pdu = nfc.llcp.pdu.UnnumberedInformation(1, 1, HEX('1122'))
        assert tco.send(pdu, flags=nfc.llcp.MSG_DONTWAIT) is True
        assert tco.dequeue(10, 4) == pdu
        threading.Timer(0.01, tco.dequeue, (10, 4)).start()
        assert tco.send(pdu, 0) is True
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.send(pdu, 0)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_recv(self, tco):
        pdu = nfc.llcp.pdu.UnnumberedInformation(1, 1, HEX('1122'))
        assert tco.enqueue(pdu) is True
        assert tco.recv() == pdu
        threading.Timer(0.01, tco.close).start()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.recv()
        assert excinfo.value.errno == errno.EPIPE
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.recv()
        assert excinfo.value.errno == errno.ESHUTDOWN


# =============================================================================
# Logical Data Link
# =============================================================================
class TestLogicalDataLink:
    @pytest.fixture
    def tco(self):
        tco = nfc.llcp.tco.LogicalDataLink(128)
        assert tco.state.ESTABLISHED is True
        assert tco.bind(1) == 1
        yield tco
        tco.close()
        assert tco.state.SHUTDOWN is True

    def test_init(self):
        tco = nfc.llcp.tco.LogicalDataLink(100)
        assert tco.send_miu == 128
        assert tco.recv_miu == 100

    def test_str(self):
        tco = nfc.llcp.tco.LogicalDataLink(128)
        assert str(tco) == "LDL None -> None"
        tco.bind(1)
        assert str(tco) == "LDL  1 -> None"
        tco.connect(1)
        assert str(tco) == "LDL  1 ->  1"

    def test_sockopt(self, tco):
        assert tco.getsockopt(nfc.llcp.SO_RCVBUF) == 1
        tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        assert tco.getsockopt(nfc.llcp.SO_RCVBUF) == 2
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        assert excinfo.value.errno == errno.ESHUTDOWN
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.getsockopt(nfc.llcp.SO_RCVBUF)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_connect(self, tco):
        assert tco.connect(1) == 1
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.connect(2)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_poll(self, tco):
        assert tco.poll("recv", 0.001) is False
        assert tco.poll("send", 0.001) is True
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.poll("invalid", 1)
        assert excinfo.value.errno == errno.EINVAL
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.poll("recv", 1)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_sendto(self, tco):
        pdu = nfc.llcp.pdu.UnnumberedInformation(1, 1, HEX('1122'))
        assert tco.sendto(pdu.data, 1, flags=nfc.llcp.MSG_DONTWAIT) is True
        assert tco.dequeue(10, 4) == pdu
        assert tco.connect(2) is True
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.sendto(pdu.data, 1, flags=nfc.llcp.MSG_DONTWAIT)
        assert excinfo.value.errno == errno.EDESTADDRREQ
        with pytest.raises(nfc.llcp.Error) as excinfo:
            data = (tco.send_miu + 1) * HEX('11')
            tco.sendto(data, 2, flags=nfc.llcp.MSG_DONTWAIT)
        assert excinfo.value.errno == errno.EMSGSIZE
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.sendto(pdu.data, 1, 0)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_recvfrom(self, tco):
        pdu = nfc.llcp.pdu.Symmetry()
        assert tco.enqueue(pdu) is False
        pdu = nfc.llcp.pdu.UnnumberedInformation(1, 1, (tco.recv_miu+1) * b'1')
        assert tco.enqueue(pdu) is False
        pdu = nfc.llcp.pdu.UnnumberedInformation(1, 1, HEX('1122'))
        assert tco.enqueue(pdu) is True
        assert tco.recvfrom() == (pdu.data, pdu.ssap)
        threading.Timer(0.01, tco.close).start()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.recvfrom()
        assert excinfo.value.errno == errno.EPIPE
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.recvfrom()
        assert excinfo.value.errno == errno.ESHUTDOWN
