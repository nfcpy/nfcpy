# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
from . import pdu
from . import err
import nfc.llcp

import errno
import threading
import collections

import logging
log = logging.getLogger(__name__)


class TransmissionControlObject(object):
    class State(object):
        def __init__(self):
            self.names = ("SHUTDOWN", "CLOSED", "LISTEN", "CONNECT",
                          "ESTABLISHED", "DISCONNECT", "CLOSE_WAIT")
            self.value = self.names.index("SHUTDOWN")

        def __str__(self):
            return self.names[self.value]

        def __getattr__(self, name):
            return self.value == self.names.index(name)

        def __setattr__(self, name, value):
            if name not in ("names", "value"):
                value, name = self.names.index(name), "value"
            object.__setattr__(self, name, value)

    class Mode(object):
        def __init__(self):
            self.names = ("BLOCK", "SEND_BUSY", "RECV_BUSY", "RECV_BUSY_SENT")
            self.value = dict([(name, False) for name in self.names])

        def __str__(self):
            return str(self.value)

        def __getattr__(self, name):
            return self.value[name]

    def __init__(self, send_miu, recv_miu):
        self.lock = threading.RLock()
        self.mode = TransmissionControlObject.Mode()
        self.state = TransmissionControlObject.State()
        self.send_queue = collections.deque()
        self.recv_queue = collections.deque()
        self.send_ready = threading.Condition(self.lock)
        self.recv_ready = threading.Condition(self.lock)
        self.recv_miu = recv_miu
        self.send_miu = send_miu
        self.recv_buf = 1
        self.send_buf = 1
        self.addr = None
        self.peer = None

    @property
    def is_bound(self):
        return self.addr is not None

    def setsockopt(self, option, value):
        if option == nfc.llcp.SO_SNDBUF:
            # with self.lock: self.send_buf = int(value)
            # adjustable send buffer only with non-blocking socket mode
            raise NotImplementedError("SO_SNDBUF can not be set")
        elif option == nfc.llcp.SO_RCVBUF:
            with self.lock:
                self.recv_buf = int(value)
        else:
            raise ValueError("invalid option value")

    def getsockopt(self, option):
        if option == nfc.llcp.SO_SNDMIU:
            return self.send_miu
        if option == nfc.llcp.SO_RCVMIU:
            return self.recv_miu
        if option == nfc.llcp.SO_SNDBUF:
            return self.send_buf
        if option == nfc.llcp.SO_RCVBUF:
            return self.recv_buf

    def bind(self, addr):
        if self.addr and addr and self.addr != addr:
            log.warning("socket rebound from {} to {}".format(self.addr, addr))
        self.addr = addr
        return self.addr

    def poll(self, event, timeout):
        if event == "recv":
            with self.recv_ready:
                if len(self.recv_queue) == 0:
                    self.recv_ready.wait(timeout)
                if len(self.recv_queue) > 0:
                    return self.recv_queue[0]
                return None
        if event == "send":
            with self.send_ready:
                if len(self.send_queue) >= self.send_buf:
                    self.send_ready.wait(timeout)
                return len(self.send_queue) < self.send_buf

    def send(self, send_pdu, flags):
        with self.send_ready:
            self.send_queue.append(send_pdu)
            if not (flags & nfc.llcp.MSG_DONTWAIT):
                self.send_ready.wait()

    def recv(self):
        with self.recv_ready:
            try:
                return self.recv_queue.popleft()
            except IndexError:
                self.recv_ready.wait()
            return self.recv_queue.popleft()

    def close(self):
        with self.lock:
            self.send_queue.clear()
            self.recv_queue.clear()
            self.send_ready.notify_all()
            self.recv_ready.notify_all()
            self.state.SHUTDOWN = True

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, rcvd_pdu):
        with self.lock:
            if len(self.recv_queue) < self.recv_buf:
                log.debug("enqueue {0}".format(rcvd_pdu))
                self.recv_queue.append(rcvd_pdu)
                self.recv_ready.notify()
                return True
            else:
                log.warning("discard {0}".format(rcvd_pdu))
                return False

    def dequeue(self, miu_size, icv_size, notify=True):
        # Return the first pending outbound PDU if it's information
        # field size (total size - header size) does not exceed the
        # given miu_size value. For UI and I PDUs do also consider the
        # icv_size value (this is set to non-zero by the packet
        # collector when aggregating). Re-insert the PDU at the
        # beginning of the send queue if it exceeds the miu_size.
        # Skip the length check if miu_size is None.
        with self.lock:
            try:
                send_pdu = self.send_queue.popleft()
                log.debug("dequeue {0}".format(send_pdu))
            except IndexError:
                return None

            if send_pdu.name in ("UI", "I"):
                pdu_size = len(send_pdu) + icv_size
            else:
                pdu_size = len(send_pdu)

            if ((miu_size is not None and
                 pdu_size - send_pdu.header_size > miu_size)):
                log.debug("requeue {0}".format(send_pdu))
                self.send_queue.appendleft(send_pdu)
                return None

            if notify is True:
                self.send_ready.notify()

            return send_pdu


class RawAccessPoint(TransmissionControlObject):
    """
    ============= =========== ============
        State        Event     Transition
    ============= =========== ============
    SHUTDOWN      init()      ESTABLISHED
    ESTABLISHED   close()     SHUTDOWN
    ============= =========== ============
    """
    def __init__(self, recv_miu):
        super(RawAccessPoint, self).__init__(128, recv_miu)
        self.state.ESTABLISHED = True

    def __str__(self):
        return "RAW {:2} ->  ?".format(self.addr
                                       if self.addr is not None
                                       else "None")

    def setsockopt(self, option, value):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        super(RawAccessPoint, self).setsockopt(option, value)

    def getsockopt(self, option):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        return super(RawAccessPoint, self).getsockopt(option)

    def poll(self, event, timeout):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        if event not in ("recv", "send"):
            raise err.Error(errno.EINVAL)
        return super(RawAccessPoint, self).poll(event, timeout) is not None

    def send(self, send_pdu, flags):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        log.debug("{0} send {1}".format(str(self), send_pdu))
        super(RawAccessPoint, self).send(send_pdu, flags)
        return self.state.ESTABLISHED is True

    def recv(self):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        try:
            return super(RawAccessPoint, self).recv()
        except IndexError:
            raise err.Error(errno.EPIPE)

    def close(self):
        super(RawAccessPoint, self).close()

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, rcvd_pdu):
        return super(RawAccessPoint, self).enqueue(rcvd_pdu)

    def dequeue(self, miu_size, icv_size):
        return super(RawAccessPoint, self).dequeue(miu_size=None, icv_size=0)


class LogicalDataLink(TransmissionControlObject):
    """
    ============= =========== ============
        State        Event     Transition
    ============= =========== ============
    SHUTDOWN      init()      ESTABLISHED
    ESTABLISHED   close()     SHUTDOWN
    ============= =========== ============
    """
    def __init__(self, recv_miu):
        super(LogicalDataLink, self).__init__(128, recv_miu)
        self.state.ESTABLISHED = True

    def __str__(self):
        return "LDL {addr:2} -> {peer:2}".format(
                addr=self.addr if self.addr is not None else "None",
                peer=self.peer if self.peer is not None else "None"
        )

    def setsockopt(self, option, value):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        super(LogicalDataLink, self).setsockopt(option, value)

    def getsockopt(self, option):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        return super(LogicalDataLink, self).getsockopt(option)

    def connect(self, dest):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        with self.lock:
            self.peer = dest
            return self.peer > 0

    def poll(self, event, timeout):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        if event not in ("recv", "send"):
            raise err.Error(errno.EINVAL)
        return super(LogicalDataLink, self).poll(event, timeout) is not None

    def sendto(self, message, dest, flags):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        if self.peer and dest != self.peer:
            raise err.Error(errno.EDESTADDRREQ)
        if len(message) > self.send_miu:
            raise err.Error(errno.EMSGSIZE)
        send_pdu = pdu.UnnumberedInformation(dest, self.addr, data=message)
        super(LogicalDataLink, self).send(send_pdu, flags)
        return self.state.ESTABLISHED is True

    def recvfrom(self):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)
        try:
            rcvd_pdu = super(LogicalDataLink, self).recv()
        except IndexError:
            raise err.Error(errno.EPIPE)
        return (rcvd_pdu.data, rcvd_pdu.ssap) if rcvd_pdu else (None, None)

    def close(self):
        super(LogicalDataLink, self).close()

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, rcvd_pdu):
        if not rcvd_pdu.name == "UI":
            log.warning("ignore %s PDU on logical data link", rcvd_pdu.name)
            return False
        if len(rcvd_pdu.data) > self.recv_miu:
            log.warning("received UI PDU exceeds local link MIU")
            return False
        return super(LogicalDataLink, self).enqueue(rcvd_pdu)

    def dequeue(self, miu_size, icv_size):
        return super(LogicalDataLink, self).dequeue(miu_size, icv_size)


class DataLinkConnection(TransmissionControlObject):
    """
    ============= =========== ============
        State        Event     Transition
    ============= =========== ============
    SHUTDOWN      init()      ESTABLISHED
    CLOSED        listen()    LISTEN
    CLOSED        connect()   CONNECT
    CONNECT       CC-PDU      ESTABLISHED
    CONNECT       DM-PDU      CLOSED
    ESTABLISHED   I-PDU       ESTABLISHED
    ESTABLISHED   RR-PDU      ESTABLISHED
    ESTABLISHED   RNR-PDU     ESTABLISHED
    ESTABLISHED   FRMR-PDU    SHUTDOWN
    ESTABLISHED   DISC-PDU    CLOSE_WAIT
    ESTABLISHED   close()     SHUTDOWN
    CLOSE_WAIT    close()     SHUTDOWN
    ============= =========== ============
    """

    DLC_PDU_NAMES = ("CONNECT", "DISC", "CC", "DM", "FRMR", "I", "RR", "RNR")

    def __init__(self, recv_miu, recv_win):
        super(DataLinkConnection, self).__init__(128, recv_miu)
        self.state.CLOSED = True
        self.acks_ready = threading.Condition(self.lock)
        self.acks_recvd = 0  # received acknowledgements
        self.recv_confs = 0  # outstanding receive confirmations
        self.send_token = threading.Condition(self.lock)
        self.recv_buf = recv_win
        self.recv_win = recv_win  # RW(Local)
        self.recv_cnt = 0         # V(R)
        self.recv_ack = 0         # V(RA)
        self.send_win = None      # RW(Remote)
        self.send_cnt = 0         # V(S)
        self.send_ack = 0         # V(SA)

    def __str__(self):
        s = "DLC {addr:2} <-> {peer:2} {dlc.state} "
        s += "RW(R)={dlc.send_win} V(S)={dlc.send_cnt} V(SA)={dlc.send_ack} "
        s += "RW(L)={dlc.recv_win} V(R)={dlc.recv_cnt} V(RA)={dlc.recv_ack}"
        return s.format(
                dlc=self,
                addr=self.addr if self.addr is not None else "None",
                peer=self.peer if self.peer is not None else "None"
        )

    def log(self, string):
        log.debug("DLC ({dlc.addr},{dlc.peer}) {dlc.state} {s}"
                  .format(dlc=self, s=string))

    def err(self, string):
        log.error("DLC ({dlc.addr},{dlc.peer}) {s}".format(dlc=self, s=string))

    def setsockopt(self, option, value):
        with self.lock:
            if option == nfc.llcp.SO_RCVMIU and self.state.CLOSED:
                self.recv_miu = min(value, 2175)
                return
            if option == nfc.llcp.SO_RCVBUF and self.state.CLOSED:
                self.recv_win = min(value, 15)
                self.recv_buf = self.recv_win
                return
            if option == nfc.llcp.SO_RCVBSY:
                self.mode.RECV_BUSY = bool(value)
                return
            super(DataLinkConnection, self).setsockopt(option, value)

    def getsockopt(self, option):
        if option == nfc.llcp.SO_RCVBUF:
            return self.recv_win
        if option == nfc.llcp.SO_SNDBSY:
            return self.mode.SEND_BUSY
        if option == nfc.llcp.SO_RCVBSY:
            return self.mode.RECV_BUSY
        return super(DataLinkConnection, self).getsockopt(option)

    def listen(self, backlog):
        with self.lock:
            if self.state.SHUTDOWN:
                raise err.Error(errno.ESHUTDOWN)
            if not self.state.CLOSED:
                self.err("listen() but socket state is {0}".format(self.state))
                raise err.Error(errno.ENOTSUP)
            self.state.LISTEN = True
            self.recv_buf = backlog

    def accept(self):
        with self.lock:
            if self.state.SHUTDOWN:
                raise err.Error(errno.ESHUTDOWN)
            if not self.state.LISTEN:
                self.err("accept() but socket state is {0}".format(self.state))
                raise err.Error(errno.EINVAL)
            self.recv_buf += 1
            try:
                rcvd_pdu = super(DataLinkConnection, self).recv()
            except IndexError:
                raise err.Error(errno.EPIPE)
            self.recv_buf -= 1
            if rcvd_pdu.name == "CONNECT":
                dlc = DataLinkConnection(self.recv_miu, self.recv_win)
                dlc.addr = self.addr
                dlc.peer = rcvd_pdu.ssap
                dlc.send_miu = rcvd_pdu.miu
                dlc.send_win = rcvd_pdu.rw
                send_pdu = pdu.ConnectionComplete(dlc.peer, dlc.addr)
                send_pdu.miu, send_pdu.rw = dlc.recv_miu, dlc.recv_win
                log.debug("accepting CONNECT from SAP %d" % dlc.peer)
                dlc.state.ESTABLISHED = True
                self.send_queue.append(send_pdu)
                return dlc
            else:  # pragma: no cover
                raise RuntimeError("CONNECT expected, not " + rcvd_pdu.name)

    def connect(self, dest):
        with self.lock:
            if not self.state.CLOSED:
                self.err("connect() in socket state {0}".format(self.state))
                if self.state.ESTABLISHED:
                    raise err.Error(errno.EISCONN)
                if self.state.CONNECT:
                    raise err.Error(errno.EALREADY)
                raise err.Error(errno.EPIPE)
            if isinstance(dest, (bytes, bytearray)):
                send_pdu = pdu.Connect(1, self.addr, self.recv_miu,
                                       self.recv_win, bytes(dest))
            elif isinstance(dest, str):
                send_pdu = pdu.Connect(1, self.addr, self.recv_miu,
                                       self.recv_win, dest.encode('latin'))
            elif isinstance(dest, int):
                send_pdu = pdu.Connect(dest, self.addr, self.recv_miu,
                                       self.recv_win)
            else:
                raise TypeError("connect destination must be int or bytes")

            self.state.CONNECT = True
            self.send_queue.append(send_pdu)

            try:
                rcvd_pdu = super(DataLinkConnection, self).recv()
            except IndexError:
                raise err.Error(errno.EPIPE)

            if rcvd_pdu.name == "DM":
                logstr = "connect rejected with reason {}"
                self.log(logstr.format(rcvd_pdu.reason))
                self.state.CLOSED = True
                raise err.ConnectRefused(rcvd_pdu.reason)
            elif rcvd_pdu.name == "CC":
                self.peer = rcvd_pdu.ssap
                self.recv_buf = self.recv_win
                self.send_miu = rcvd_pdu.miu
                self.send_win = rcvd_pdu.rw
                self.state.ESTABLISHED = True
                return
            else:  # pragma: no cover
                raise RuntimeError("CC or DM expected, not " + rcvd_pdu.name)

    @property
    def send_window_slots(self):
        # RW(R) - V(S) + V(SA) mod 16
        return (self.send_win - self.send_cnt + self.send_ack) % 16

    @property
    def recv_window_slots(self):
        # RW(L) - V(R) + V(RA) mod 16
        return (self.recv_win - self.recv_cnt + self.recv_ack) % 16

    def send(self, message, flags):
        with self.send_token:
            if not self.state.ESTABLISHED:
                self.err("send() in socket state {0}".format(self.state))
                if self.state.CLOSE_WAIT:
                    raise err.Error(errno.EPIPE)
                raise err.Error(errno.ENOTCONN)
            if len(message) > self.send_miu:
                raise err.Error(errno.EMSGSIZE)
            while self.send_window_slots == 0 and self.state.ESTABLISHED:
                if flags & nfc.llcp.MSG_DONTWAIT:
                    raise err.Error(errno.EWOULDBLOCK)
                self.log("waiting on busy send window")
                self.send_token.wait()
            self.log("send {0} byte on {1}".format(len(message), str(self)))
            if self.state.ESTABLISHED:
                send_pdu = pdu.Information(self.peer, self.addr, data=message)
                send_pdu.ns = self.send_cnt
                self.send_cnt = (self.send_cnt + 1) % 16
                super(DataLinkConnection, self).send(send_pdu, flags)
            return self.state.ESTABLISHED is True

    def recv(self):
        with self.lock:
            if not (self.state.ESTABLISHED or self.state.CLOSE_WAIT):
                self.err("recv() in socket state {0}".format(self.state))
                raise err.Error(errno.ENOTCONN)

            try:
                rcvd_pdu = super(DataLinkConnection, self).recv()
            except IndexError:
                return None

            if rcvd_pdu.name == "I":
                self.recv_confs += 1
                if self.recv_confs > self.recv_win:
                    self.err("recv_confs({0}) > recv_win({1})"
                             .format(self.recv_confs, self.recv_win))
                    raise RuntimeError("recv_confs > recv_win")
                return rcvd_pdu.data

            if rcvd_pdu.name == "DISC":
                self.close()
                return None

            raise RuntimeError("only I or DISC expected, not " + rcvd_pdu.name)

    def poll(self, event, timeout):
        if self.state.SHUTDOWN:
            raise err.Error(errno.ESHUTDOWN)

        if event == "recv":
            if self.state.ESTABLISHED or self.state.CLOSE_WAIT:
                rcvd_pdu = super(DataLinkConnection, self).poll(event, timeout)
                if self.state.ESTABLISHED or self.state.CLOSE_WAIT:
                    return isinstance(rcvd_pdu, pdu.Information)
        elif event == "send":
            if self.state.ESTABLISHED:
                if super(DataLinkConnection, self).poll(event, timeout):
                    return self.state.ESTABLISHED
                return False
        elif event == "acks":
            with self.acks_ready:
                if not self.acks_recvd > 0:
                    self.acks_ready.wait(timeout)
                if self.acks_recvd > 0:
                    self.acks_recvd = self.acks_recvd - 1
                    return True
                return False
        else:
            raise err.Error(errno.EINVAL)

    def close(self):
        with self.lock:
            self.log("close()")
            if self.state.ESTABLISHED and self.is_bound:
                self.state.DISCONNECT = True
                self.send_token.notify_all()
                self.acks_ready.notify_all()
                send_pdu = pdu.Disconnect(self.peer, self.addr)
                self.send_queue.append(send_pdu)
                try:
                    super(DataLinkConnection, self).recv()
                except IndexError:
                    pass
            super(DataLinkConnection, self).close()
            self.acks_ready.notify_all()
            self.send_token.notify_all()

    #
    # enqueue() and dequeue() are called from llc thread context
    #
    def enqueue(self, rcvd_pdu):
        self.log("enqueue {pdu.name} PDU".format(pdu=rcvd_pdu))

        if rcvd_pdu.name not in self.DLC_PDU_NAMES:
            self.err("non connection mode pdu on data link connection")
            send_pdu = pdu.FrameReject.from_pdu(rcvd_pdu, flags="W", dlc=self)
            self.close()
            self.send_queue.append(send_pdu)
            return

        if self.state.CLOSED:
            self.send_queue.append(pdu.DisconnectedMode(
                rcvd_pdu.ssap, rcvd_pdu.dsap, reason=1))

        elif self.state.LISTEN and rcvd_pdu.name == "CONNECT":
            if super(DataLinkConnection, self).enqueue(rcvd_pdu) is False:
                log.warning("full backlog on listening socket")
                self.send_queue.append(pdu.DisconnectedMode(
                    rcvd_pdu.ssap, rcvd_pdu.dsap, reason=0x20))

        elif self.state.CONNECT and rcvd_pdu.name in ("CC", "DM"):
            with self.lock:
                self.recv_queue.append(rcvd_pdu)
                self.recv_ready.notify()

        elif self.state.DISCONNECT and rcvd_pdu.name == "DM":
            with self.lock:
                self.recv_queue.append(rcvd_pdu)
                self.recv_ready.notify()

        elif self.state.ESTABLISHED:
            return self._enqueue_state_established(rcvd_pdu)

    def _enqueue_state_established(self, rcvd_pdu):
        if rcvd_pdu.name == "I":
            frmr = None
            if len(rcvd_pdu.data) > self.recv_miu:
                frmr = pdu.FrameReject.from_pdu(rcvd_pdu, flags="I", dlc=self)
            elif rcvd_pdu.ns != self.recv_cnt:
                frmr = pdu.FrameReject.from_pdu(rcvd_pdu, flags="S", dlc=self)
            if frmr:
                self.log("reject " + str(self))
                self.send_queue.clear()
                self.send_queue.append(frmr)
                log.debug("enqueued frame reject pdu")
                return

        if rcvd_pdu.name == "FRMR":
            with self.lock:
                self.state.SHUTDOWN = True
                self.close()
            return

        if rcvd_pdu.name == "DISC":
            with self.lock:
                self.state.CLOSE_WAIT = True
                self.send_queue.clear()
                self.send_queue.append(pdu.DisconnectedMode(
                    self.peer, self.addr, reason=0))
            return

        if rcvd_pdu.name in ("I", "RR", "RNR"):
            with self.lock:
                # acks = N(R) - V(SA) mod 16
                acks = (rcvd_pdu.nr - self.send_ack) % 16
                if acks:
                    self.acks_recvd += acks
                    self.acks_ready.notify_all()
                    self.send_token.notify()
                    self.send_ack = rcvd_pdu.nr  # V(SA) := N(R)
                if rcvd_pdu.name == "RNR":
                    self.mode.SEND_BUSY = True
                if rcvd_pdu.name == "RR":
                    self.mode.SEND_BUSY = False

        if rcvd_pdu.name == "I":
            with self.lock:
                # V(R) := V(R) + 1 mod 16
                self.recv_cnt = (self.recv_cnt + 1) % 16
            super(DataLinkConnection, self).enqueue(rcvd_pdu)

    def dequeue(self, miu_size, icv_size):
        with self.lock:
            if self.state.ESTABLISHED:
                if self.mode.RECV_BUSY_SENT != self.mode.RECV_BUSY:
                    self.mode.RECV_BUSY_SENT = self.mode.RECV_BUSY
                    ACK = RNR_PDU if self.mode.RECV_BUSY else RR_PDU
                    return ACK(self.peer, self.addr, self.recv_ack)

            send_pdu = super(DataLinkConnection, self).dequeue(
                miu_size, icv_size, notify=False)

            if send_pdu:
                self.log("dequeue {0} PDU".format(send_pdu.name))

                if send_pdu.name == "FRMR":
                    self.state.SHUTDOWN = True
                    self.close()

                if send_pdu.name == "I" and self.state.ESTABLISHED:
                    if self.recv_confs and self.recv_cnt != self.recv_ack:
                        self.log("piggyback ack " + str(self))
                        self.recv_ack = (self.recv_ack + self.recv_confs) % 16
                        self.recv_confs = 0
                    send_pdu.nr = self.recv_ack
                    self.send_ready.notify()

                if send_pdu.name == "DM" and self.state.CLOSE_WAIT:
                    self.recv_queue.append(pdu.Disconnect(
                        dsap=self.peer, ssap=self.addr))
                    self.recv_ready.notify()
                    self.send_token.notify_all()

            else:
                if ((self.state.ESTABLISHED and self.recv_confs
                     and self.recv_window_slots == 0)):
                    # must send acknowledgement to keep going
                    self.log("necessary ack " + str(self))
                    self.recv_ack = (self.recv_ack + self.recv_confs) % 16
                    self.recv_confs = 0
                    ACK = RNR_PDU if self.mode.RECV_BUSY else RR_PDU
                    return ACK(self.peer, self.addr, self.recv_ack)

            return send_pdu

    def sendack(self):
        if self.state.ESTABLISHED:
            with self.lock:
                if self.recv_confs and self.recv_cnt != self.recv_ack:
                    self.log("voluntary ack " + str(self))
                    self.recv_ack = (self.recv_ack + self.recv_confs) % 16
                    self.recv_confs = 0
                    ACK = RNR_PDU if self.mode.RECV_BUSY else RR_PDU
                    return ACK(self.peer, self.addr, self.recv_ack)


RR_PDU, RNR_PDU = pdu.ReceiveReady, pdu.ReceiveNotReady
