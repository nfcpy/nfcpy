# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import time
import errno
import pytest
import threading
import nfc.llcp.tco

import logging
logging.basicConfig(level=logging.DEBUG-1)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.llcp").setLevel(logging_level)


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


# =============================================================================
# Data Link Connection
# =============================================================================
class TestDataLinkConnection:
    @pytest.fixture
    def tco(self):
        tco = nfc.llcp.tco.DataLinkConnection(128, 1)
        assert tco.state.CLOSED is True
        assert tco.bind(16) == 16
        return tco

    def test_init(self):
        tco = nfc.llcp.tco.DataLinkConnection(100, 1)
        assert tco.state.CLOSED is True
        assert tco.send_miu == 128
        assert tco.recv_miu == 100

    def test_str(self):
        tco = nfc.llcp.tco.DataLinkConnection(128, 1)
        assert str(tco) == \
            "DLC None <-> None CLOSED RW(R)=None " \
            "V(S)=0 V(SA)=0 RW(L)=1 V(R)=0 V(RA)=0"
        tco.bind(1)
        assert str(tco) == \
            "DLC  1 <-> None CLOSED RW(R)=None " \
            "V(S)=0 V(SA)=0 RW(L)=1 V(R)=0 V(RA)=0"

    def test_sockopt(self, tco):
        assert tco.getsockopt(nfc.llcp.SO_SNDBUF) == 1
        assert tco.getsockopt(nfc.llcp.SO_RCVBUF) == 1
        assert tco.getsockopt(nfc.llcp.SO_SNDMIU) == 128
        assert tco.getsockopt(nfc.llcp.SO_RCVMIU) == 128
        assert tco.getsockopt(nfc.llcp.SO_SNDBSY) is False
        assert tco.getsockopt(nfc.llcp.SO_RCVBSY) is False
        tco.setsockopt(nfc.llcp.SO_RCVMIU, 200)
        tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        tco.setsockopt(nfc.llcp.SO_RCVBSY, True)
        assert tco.getsockopt(nfc.llcp.SO_RCVBUF) == 2
        assert tco.getsockopt(nfc.llcp.SO_RCVMIU) == 200
        assert tco.getsockopt(nfc.llcp.SO_RCVBSY) is True
        with pytest.raises(NotImplementedError) as excinfo:
            tco.setsockopt(nfc.llcp.SO_SNDBUF, 2)
        assert str(excinfo.value) == "SO_SNDBUF can not be set"

    def test_listen(self, tco):
        tco.listen(backlog=1)
        assert tco.state.LISTEN is True
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.listen(1)
        assert excinfo.value.errno == errno.ENOTSUP
        tco.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.listen(1)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_accept(self, tco):
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.accept()
        assert excinfo.value.errno == errno.EINVAL
        tco.setsockopt(nfc.llcp.SO_RCVMIU, 1000)
        tco.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        tco.listen(backlog=1)
        assert tco.state.LISTEN is True
        tco.enqueue(nfc.llcp.pdu.Connect(tco.addr, 17, 500, 15))
        dlc = tco.accept()
        assert isinstance(dlc, nfc.llcp.tco.DataLinkConnection)
        assert dlc.state.ESTABLISHED is True
        assert dlc.getsockopt(nfc.llcp.SO_RCVMIU) == 1000
        assert dlc.getsockopt(nfc.llcp.SO_SNDMIU) == 500
        assert dlc.getsockopt(nfc.llcp.SO_RCVBUF) == 2
        assert tco.dequeue(128, 4) == \
            nfc.llcp.pdu.ConnectionComplete(17, tco.addr, 1000, 2)
        threading.Timer(0.01, tco.close).start()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.accept()
        assert excinfo.value.errno == errno.EPIPE
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.accept()
        assert excinfo.value.errno == errno.ESHUTDOWN

    @pytest.mark.parametrize("dest, dsap", [(17, 17), (b'name', 1)])
    def test_connect_by_addr_or_name(self, tco, dest, dsap):
        pdu = nfc.llcp.pdu.ConnectionComplete(tco.addr, dsap, 1000, 2)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        tco.connect(dest)
        assert tco.state.ESTABLISHED is True
        pdu = nfc.llcp.pdu.DisconnectedMode(tco.addr, dsap)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        tco.close()
        assert tco.state.SHUTDOWN is True

    def test_connect_with_invalid_dest_type(self, tco):
        with pytest.raises(TypeError) as excinfo:
            tco.connect(1.0)
        assert str(excinfo.value) == "connect destination must be int or bytes"

    def test_connect_with_connect_rejected(self, tco):
        pdu = nfc.llcp.pdu.DisconnectedMode(tco.addr, 17)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        with pytest.raises(nfc.llcp.ConnectRefused) as excinfo:
            tco.connect(17)
        assert excinfo.value.errno == errno.ECONNREFUSED
        assert tco.state.CLOSED is True

    def test_connect_with_error_broken_pipe(self, tco):
        threading.Timer(0.01, tco.close).start()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.connect(17)
        assert excinfo.value.errno == errno.EPIPE
        assert tco.state.SHUTDOWN is True
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.connect(17)
        assert excinfo.value.errno == errno.EPIPE

    def test_connect_with_error_is_connected(self, tco):
        pdu = nfc.llcp.pdu.ConnectionComplete(tco.addr, 17, 1000, 2)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        tco.connect(17)
        assert tco.state.ESTABLISHED is True
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.connect(18)
        assert excinfo.value.errno == errno.EISCONN

    def test_connect_with_error_is_connecting(self, tco):
        pdu = nfc.llcp.pdu.ConnectionComplete(tco.addr, 17, 1000, 2)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        threading.Timer(0, tco.connect, (17,)).start()
        time.sleep(0.001)
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.connect(18)
        assert excinfo.value.errno == errno.EALREADY

    @pytest.fixture
    def dlc(self, tco):
        pdu = nfc.llcp.pdu.ConnectionComplete(tco.addr, 17, 128, 1)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        tco.connect(17)
        assert tco.state.ESTABLISHED is True
        assert tco.dequeue(128, 4) == nfc.llcp.pdu.Connect(17, 16, 128, 1)
        return tco

    def test_send_with_flags_dont_wait(self, dlc):
        assert dlc.send(b'', nfc.llcp.MSG_DONTWAIT) is True
        assert dlc.dequeue(128, 4) == \
            nfc.llcp.pdu.Information(17, 16, 0, 0, b'')

    def test_send_with_error_would_block(self, dlc):
        assert dlc.send(b'', nfc.llcp.MSG_DONTWAIT) is True
        with pytest.raises(nfc.llcp.Error) as excinfo:
            dlc.send(b'', nfc.llcp.MSG_DONTWAIT)
        assert excinfo.value.errno == errno.EWOULDBLOCK

    def test_send_with_wait_send_busy(self, dlc):
        threading.Timer(0.01, dlc.dequeue, (128, 0)).start()
        assert dlc.send(b'123', 0) is True
        pdu = nfc.llcp.pdu.ReceiveReady(dlc.addr, dlc.peer, nr=1)
        threading.Timer(0.01, dlc.enqueue, (pdu,)).start()
        threading.Timer(0.02, dlc.dequeue, (128, 0)).start()
        assert dlc.send(b'456', 0) is True

    def test_send_with_busy_then_closed(self, dlc):
        threading.Timer(0.01, dlc.dequeue, (128, 0)).start()
        assert dlc.send(b'123', 0) is True
        pdu = nfc.llcp.pdu.DisconnectedMode(dlc.addr, dlc.peer)
        threading.Timer(0.01, dlc.close).start()
        threading.Timer(0.02, dlc.enqueue, (pdu,)).start()
        assert dlc.send(b'456', 0) is False

    def test_send_with_error_message_size(self, dlc):
        with pytest.raises(nfc.llcp.Error) as excinfo:
            dlc.send(129 * b'.', nfc.llcp.MSG_DONTWAIT)
        assert excinfo.value.errno == errno.EMSGSIZE

    def test_send_while_state_close_wait(self, dlc):
        pdu = nfc.llcp.pdu.Disconnect(dlc.addr, dlc.peer)
        dlc.enqueue(pdu)
        with pytest.raises(nfc.llcp.Error) as excinfo:
            dlc.send(b'123', 0)
        assert excinfo.value.errno == errno.EPIPE

    def test_send_with_error_not_connected(self, tco):
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.send(b'', nfc.llcp.MSG_DONTWAIT)
        assert excinfo.value.errno == errno.ENOTCONN

    def test_recv_two_messages(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.recv() == b'123'
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.ReceiveReady(dlc.peer, dlc.addr, nr=1)
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 1, 0, b'456'))
        assert dlc.recv() == b'456'
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.ReceiveReady(dlc.peer, dlc.addr, nr=2)

    def test_recv_peer_disconnect(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.recv() == b'123'
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.ReceiveReady(dlc.peer, dlc.addr, nr=1)
        dlc.enqueue(nfc.llcp.pdu.Disconnect(dlc.addr, dlc.peer))
        threading.Timer(0.01, dlc.dequeue, (128, 0)).start()
        assert dlc.recv() is None
        assert dlc.state.SHUTDOWN is True

    def test_recv_confs_runtime_error(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.recv() == b'123'
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.ReceiveReady(dlc.peer, dlc.addr, nr=1)
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 1, 0, b'456'))
        dlc.recv_confs += 1
        with pytest.raises(RuntimeError) as excinfo:
            dlc.recv()
        assert str(excinfo.value) == "recv_confs > recv_win"

    def test_recv_with_forced_close(self, dlc):
        threading.Timer(0.01, dlc.close).start()
        threading.Timer(0.02, dlc.close).start()
        assert dlc.recv() is None

    def test_recv_unexpected_pdu(self, dlc):
        pdu = nfc.llcp.pdu.DisconnectedMode(dlc.addr, dlc.peer)
        threading.Timer(0.01, dlc.close).start()
        threading.Timer(0.02, dlc.enqueue, (pdu,)).start()
        threading.Timer(0.03, dlc.close).start()
        with pytest.raises(RuntimeError) as excinfo:
            dlc.recv()
        assert str(excinfo.value) == "only I or DISC expected, not DM"

    def test_recv_while_not_established(self, tco):
        with pytest.raises(nfc.llcp.Error) as excinfo:
            tco.recv()
        assert excinfo.value.errno == errno.ENOTCONN

    def test_poll_recv(self, dlc):
        assert dlc.poll('recv', timeout=0.01) is False
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.poll('recv', timeout=None) is True
        assert dlc.recv() == b'123'
        threading.Timer(0.01, dlc.close).start()
        threading.Timer(0.02, dlc.close).start()
        assert dlc.poll('recv', timeout=None) is None
        dlc = nfc.llcp.tco.DataLinkConnection(128, 1)
        assert dlc.poll('recv', timeout=None) is None

    def test_poll_send(self, dlc, tco):
        assert dlc.poll('send', timeout=None) is True
        dlc.send(b'123', nfc.llcp.MSG_DONTWAIT)
        assert dlc.poll('send', timeout=0.01) is False
        dlc = nfc.llcp.tco.DataLinkConnection(128, 1)
        assert dlc.poll('send', timeout=None) is None

    def test_poll_acks(self, dlc):
        assert dlc.poll('acks', timeout=0.01) is False
        dlc.send(b'123', nfc.llcp.MSG_DONTWAIT)
        dlc.dequeue(128, 0)
        dlc.enqueue(nfc.llcp.pdu.ReceiveReady(dlc.addr, dlc.peer, nr=1))
        assert dlc.poll('acks', timeout=None) is True

    def test_poll_some(self, dlc):
        with pytest.raises(nfc.llcp.Error) as excinfo:
            dlc.poll('some', timeout=None)
        assert excinfo.value.errno == errno.EINVAL

    def test_poll_shutdown(self, dlc):
        threading.Timer(0.01, dlc.close).start()
        dlc.close()
        with pytest.raises(nfc.llcp.Error) as excinfo:
            dlc.poll('recv', timeout=None)
        assert excinfo.value.errno == errno.ESHUTDOWN

    def test_enqueue_invalid_pdu_for_dlc(self, dlc):
        pdu = nfc.llcp.pdu.UnnumberedInformation(dlc.addr, dlc.peer, b'123')
        threading.Timer(0.01, dlc.close).start()
        assert dlc.enqueue(pdu) is None
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.FrameReject.from_pdu(pdu, "W", dlc)

    def test_enqueue_state_closed_recv_any(self, tco):
        pdu = nfc.llcp.pdu.DisconnectedMode(tco.addr, 17)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        with pytest.raises(nfc.llcp.ConnectRefused):
            tco.connect(17)
        assert tco.state.CLOSED is True
        assert tco.dequeue(128, 0) == nfc.llcp.pdu.Connect(17, tco.addr)
        pdu = nfc.llcp.pdu.Information(tco.addr, 17, 0, 0, b'123')
        assert tco.enqueue(pdu) is None
        assert tco.dequeue(128, 0) == \
            nfc.llcp.pdu.DisconnectedMode(17, tco.addr, reason=1)

    def test_enqueue_state_listen_recv_connect(self, tco):
        tco.listen(backlog=1)
        tco.enqueue(nfc.llcp.pdu.Connect(tco.addr, 17))
        tco.enqueue(nfc.llcp.pdu.Connect(tco.addr, 18))
        tco.accept()
        assert tco.dequeue(128, 0) == \
            nfc.llcp.pdu.DisconnectedMode(18, tco.addr, reason=0x20)
        assert tco.dequeue(128, 1) == \
            nfc.llcp.pdu.ConnectionComplete(17, tco.addr)

    def test_enqueue_state_connect_recv_cc(self, tco):
        pdu = nfc.llcp.pdu.ConnectionComplete(17, tco.addr)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        tco.connect(17)
        assert tco.state.ESTABLISHED is True

    def test_enqueue_state_connect_recv_dm(self, tco):
        pdu = nfc.llcp.pdu.DisconnectedMode(17, tco.addr)
        threading.Timer(0.01, tco.enqueue, (pdu,)).start()
        with pytest.raises(nfc.llcp.ConnectRefused):
            tco.connect(17)
        assert tco.state.CLOSED is True

    def test_enqueue_state_disconnect_recv_dm(self, dlc):
        threading.Timer(0, dlc.close).start()
        time.sleep(0.01)
        assert dlc.state.DISCONNECT is True
        dlc.enqueue(nfc.llcp.pdu.DisconnectedMode(dlc.addr, dlc.peer))
        time.sleep(0.01)
        assert dlc.state.SHUTDOWN is True

    def test_enqueue_state_established_recv_data(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.recv() == b'123'

    def test_enqueue_state_established_recv_wrong_miu(self, dlc):
        data = (dlc.recv_miu + 1) * b'0'
        ipdu = nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, data)
        frmr = nfc.llcp.pdu.FrameReject.from_pdu(ipdu, flags="I", dlc=dlc)
        dlc.enqueue(ipdu)
        assert dlc.dequeue(128, 0) == frmr

    def test_enqueue_state_established_recv_wrong_ns(self, dlc):
        ipdu = nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 1, 0, b'123')
        frmr = nfc.llcp.pdu.FrameReject.from_pdu(ipdu, flags="S", dlc=dlc)
        dlc.enqueue(ipdu)
        assert dlc.dequeue(128, 0) == frmr

    def test_enqueue_state_established_recv_frmr(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.FrameReject(dlc.addr, dlc.peer))
        assert dlc.state.SHUTDOWN is True

    def test_enqueue_state_established_recv_disc(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Disconnect(dlc.addr, dlc.peer))
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.DisconnectedMode(dlc.peer, dlc.addr, reason=0)
        assert dlc.state.CLOSE_WAIT is True
        assert dlc.recv() is None
        assert dlc.state.SHUTDOWN is True

    def test_enqueue_state_established_recv_acks(self, dlc):
        dlc.send(b'123', flags=nfc.llcp.MSG_DONTWAIT)
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.Information(dlc.peer, dlc.addr, 0, 0, b'123')
        assert dlc.poll('acks', timeout=0.01) is False
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 1, b'456'))
        assert dlc.poll('acks', timeout=None) is True
        assert dlc.poll('acks', timeout=0.01) is False

    def test_enqueue_state_established_recv_busy(self, dlc):
        dlc.send(b'123', flags=nfc.llcp.MSG_DONTWAIT)
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.Information(dlc.peer, dlc.addr, 0, 0, b'123')
        assert dlc.mode.SEND_BUSY is False
        dlc.enqueue(nfc.llcp.pdu.ReceiveNotReady(dlc.addr, dlc.peer, 2))
        assert dlc.mode.SEND_BUSY is True
        dlc.enqueue(nfc.llcp.pdu.ReceiveReady(dlc.addr, dlc.peer, 2))
        assert dlc.mode.SEND_BUSY is False

    def test_enqueue_state_established_recv_dm(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.DisconnectedMode(dlc.addr, dlc.peer))

    def test_enqueue_state_shutdown_recv_data(self, dlc):
        threading.Timer(0.01, dlc.close).start()
        dlc.close()
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer))

    def test_dequeue_flip_busy(self, dlc):
        assert dlc.getsockopt(nfc.llcp.SO_RCVBSY) is False
        dlc.setsockopt(nfc.llcp.SO_RCVBSY, True)
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.ReceiveNotReady(dlc.peer, dlc.addr, 0)
        assert dlc.getsockopt(nfc.llcp.SO_RCVBSY) is True
        dlc.setsockopt(nfc.llcp.SO_RCVBSY, False)
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.ReceiveReady(dlc.peer, dlc.addr, 0)

    def test_dequeue_frmr_pdu(self, dlc):
        pdu = nfc.llcp.pdu.FrameReject(dlc.peer, dlc.addr)
        super(type(dlc), dlc).send(pdu, nfc.llcp.MSG_DONTWAIT)
        assert dlc.dequeue(128, 0) == pdu

    def test_dequeue_inf_pdu(self, dlc):
        dlc.send(b'123', nfc.llcp.MSG_DONTWAIT)
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.Information(dlc.peer, dlc.addr, 0, 0, b'123')

    def test_dequeue_inf_with_acks(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.recv() == b'123'
        dlc.send(b'456', nfc.llcp.MSG_DONTWAIT)
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.Information(dlc.peer, dlc.addr, 0, 1, b'456')

    def test_dequeue_dm_in_close_wait(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Disconnect(dlc.addr, dlc.peer))
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.DisconnectedMode(dlc.peer, dlc.addr, reason=0)

    def test_dequeue_must_send_ack(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.recv() == b'123'
        assert dlc.dequeue(128, 0) == \
            nfc.llcp.pdu.ReceiveReady(dlc.peer, dlc.addr, nr=1)

    def test_dequeue_none_to_send(self, dlc):
        assert dlc.dequeue(128, 0) is None

    def test_sendack_acks_to_send(self, dlc):
        dlc.enqueue(nfc.llcp.pdu.Information(dlc.addr, dlc.peer, 0, 0, b'123'))
        assert dlc.recv() == b'123'
        assert dlc.sendack() == \
            nfc.llcp.pdu.ReceiveReady(dlc.peer, dlc.addr, nr=1)

    def test_sendack_none_to_send(self, dlc):
        assert dlc.sendack() is None

    def test_sendack_not_established(self, tco):
        assert tco.sendack() is None
