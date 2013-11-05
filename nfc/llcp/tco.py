# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://www.osor.eu/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------

__all__ = ["TransmissionControlObject", "RawAccessPoint", 
           "LogicalDataLink", "DataLinkConnection"]

import logging
log = logging.getLogger(__name__)

import collections
import threading
import time
import errno
from types import *

# local imports
from pdu import *
from err import *
from opt import *

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
            if not name in ("names", "value"):
                value, name = self.names.index(name), "value"
            object.__setattr__(self, name, value)
        
    class Mode(object):
        def __init__(self):
            self.names = ("BLOCK", "SEND_BUSY", "RECV_BUSY", "RECV_BUSY_SENT")
            self.value = dict([(name,False) for name in self.names])
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
        return self.addr != None

    def setsockopt(self, option, value):
        if option == SO_SNDBUF:
            # with self.lock: self.send_buf = int(value)
            # adjustable send buffer only with non-blocking socket mode
            raise NotImplemented
        if option == SO_RCVBUF:
            with self.lock: self.recv_buf = int(value)

    def getsockopt(self, option):
        if option == SO_SNDMIU:
            return self.send_miu
        if option == SO_RCVMIU:
            return self.recv_miu
        if option == SO_SNDBUF:
            return self.send_buf
        if option == SO_RCVBUF:
            return self.recv_buf

    def bind(self, addr):
        if self.addr and addr and self.addr != addr:
            log.warn("socket rebound from {0} to {1}".format(self.addr, addr))
        self.addr = addr

    def poll(self, event, timeout):
        if event == "recv":
            with self.recv_ready:
                if len(self.recv_queue) == 0:
                    self.recv_ready.wait(timeout)
                if len(self.recv_queue) > 0:
                    return self.recv_queue[0].type
                return None
        if event == "send":
            with self.send_ready:
                if len(self.send_queue) >= self.send_buf:
                    self.send_ready.wait(timeout)
                return len(self.send_queue) < self.send_buf

    def send(self, pdu):
        with self.send_ready:
            self.send_queue.append(pdu)
            self.send_ready.wait()

    def recv(self):
        with self.recv_ready:
            try: return self.recv_queue.popleft()
            except IndexError: self.recv_ready.wait()
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
    def enqueue(self, pdu):
        with self.lock:
            if len(self.recv_queue) < self.recv_buf:
                self.recv_queue.append(pdu)
                self.recv_ready.notify()
                return True
            else: log.warn("lost data on busy recv queue")
            return False

    def dequeue(self, maxlen, notify=True):
        with self.lock:
            pdu = self.send_queue.popleft()
            if len(pdu) <= maxlen:
                if notify == True:
                    self.send_ready.notify()
                return pdu
            else: self.send_queue.appendleft(pdu)

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
        return "RAW {0:2} ->  ?".format(self.addr)

    def setsockopt(self, option, value):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        super(RawAccessPoint, self).setsockopt(option, value)

    def getsockopt(self, option):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        return super(RawAccessPoint, self).getsockopt(option)

    def poll(self, event, timeout):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        if not event in ("recv", "send"):
            raise Error(errno.EINVAL)
        return super(RawAccessPoint, self).poll(event, timeout) is not None
        
    def send(self, pdu):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        log.debug("{0} send {1}".format(str(self), pdu))
        super(RawAccessPoint, self).send(pdu)
        return self.state.ESTABLISHED == True

    def recv(self):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        try: return super(RawAccessPoint, self).recv()
        except IndexError: raise Error(errno.EPIPE)

    def close(self):
        super(RawAccessPoint, self).close()

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, pdu):
        return super(RawAccessPoint, self).enqueue(pdu)

    def dequeue(self, maxlen):
        try: return super(RawAccessPoint, self).dequeue(3 + 2048 + 128)
        except IndexError: return None


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
        return "LDL {0:2} -> {1:2}".format(self.addr, self.peer)

    def setsockopt(self, option, value):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        super(LogicalDataLink, self).setsockopt(option, value)

    def getsockopt(self, option):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        return super(LogicalDataLink, self).getsockopt(option)

    def connect(self, dest):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        with self.lock:
            self.peer = dest
            return self.peer > 0

    def poll(self, event, timeout):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        if not event in ("recv", "send"):
            raise Error(errno.EINVAL)
        return super(LogicalDataLink, self).poll(event, timeout) is not None
        
    def sendto(self, message, dest):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        if self.peer and dest != self.peer:
            raise Error(errno.EDESTADDRREQ)
        if len(message) > self.send_miu:
            raise Error(errno.EMSGSIZE)
        pdu = UnnumberedInformation(dest, self.addr, sdu=message)
        super(LogicalDataLink, self).send(pdu)
        return self.state.ESTABLISHED == True

    def recvfrom(self):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        try: pdu = super(LogicalDataLink, self).recv()
        except IndexError: raise Error(errno.EPIPE)
        return (pdu.sdu, pdu.ssap) if pdu else (None, None)

    def close(self):
        super(LogicalDataLink, self).close()

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, pdu):
        if not isinstance(pdu, UnnumberedInformation):
            log.warn("ignore {0} PDU on logical data link".format(pdu.name))
            return False
        if len(pdu.sdu) > self.recv_miu:
            log.warn("received UI PDU exceeds local link MIU")
            return False
        return super(LogicalDataLink, self).enqueue(pdu)

    def dequeue(self, maxlen):
        try: return super(LogicalDataLink, self).dequeue(maxlen)
        except IndexError: return None


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
    def __init__(self, recv_miu, recv_win):
        super(DataLinkConnection, self).__init__(128, recv_miu)
        self.state.CLOSED = True
        self.acks_ready = threading.Condition(self.lock)
        self.acks_recvd = 0 # received acknowledgements
        self.recv_confs = 0 # outstanding receive confirmations
        self.send_token = threading.Condition(self.lock)
        self.recv_buf = recv_win
        self.recv_win = recv_win # RW(Local)
        self.recv_cnt = 0        # V(R)
        self.recv_ack = 0        # V(RA)
        self.send_win = None     # RW(Remote)
        self.send_cnt = 0        # V(S)
        self.send_ack = 0        # V(SA)

    def __str__(self):
        s  = "DLC {dlc.addr:2} <-> {dlc.peer:2} {dlc.state} "
        s += "RW(R)={dlc.send_win} V(S)={dlc.send_cnt} V(SA)={dlc.send_ack} "
        s += "RW(L)={dlc.recv_win} V(R)={dlc.recv_cnt} V(RA)={dlc.recv_ack}"
        return s.format(dlc=self)

    def log(self, string):
        log.debug("DLC ({dlc.addr},{dlc.peer}) {dlc.state} {s}"
                  .format(dlc=self, s=string))

    def err(self, string):
        log.error("DLC ({dlc.addr},{dlc.peer}) {s}".format(dlc=self, s=string))

    def setsockopt(self, option, value):
        with self.lock:
            if option == SO_RCVMIU and self.state.CLOSED:
                self.recv_miu = min(value, 2175)
                return
            if option == SO_RCVBUF and self.state.CLOSED:
                self.recv_win = min(value, 15)
                self.recv_buf = self.recv_win
                return
            if option == SO_RCVBSY:
                self.mode.RECV_BUSY = bool(value)
                return
            super(DataLinkConnection, self).setsockopt(option, value)

    def getsockopt(self, option):
        if option == SO_RCVBUF:
            return self.recv_win
        if option == SO_SNDBSY:
            return self.mode.SEND_BUSY
        if option == SO_RCVBSY:
            return self.mode.RECV_BUSY
        return super(DataLinkConnection, self).getsockopt(option)

    def listen(self, backlog):
        with self.lock:
            if self.state.SHUTDOWN:
                raise Error(errno.EBADF)
            if not self.state.CLOSED:
                self.err("listen() but socket state is {0}".format(self.state))
                raise RuntimeError # should raise Error(errno.E???)
            self.state.LISTEN = True
            self.recv_buf = backlog

    def accept(self):
        with self.lock:
            if self.state.SHUTDOWN:
                raise Error(errno.EBADF)
            if not self.state.LISTEN:
                self.err("accept() but socket state is {0}".format(self.state))
                raise Error(errno.EINVAL)
            self.recv_buf += 1
            try: pdu = super(DataLinkConnection, self).recv()
            except IndexError: raise Error(errno.EPIPE)
            self.recv_buf -= 1
            if isinstance(pdu, Connect):
                dlc = DataLinkConnection(self.recv_miu, self.recv_win)
                dlc.addr = self.addr
                dlc.peer = pdu.ssap
                dlc.send_miu = pdu.miu
                dlc.send_win = pdu.rw
                pdu = ConnectionComplete(dlc.peer, dlc.addr)
                pdu.miu, pdu.rw = dlc.recv_miu, dlc.recv_win
                log.info("accepting CONNECT from SAP %d" % dlc.peer)
                dlc.state.ESTABLISHED = True
                self.send_queue.append(pdu)
                return dlc
            raise RuntimeError("only CONNECT expected, not "+ pdu.name)

    def connect(self, dest):
        with self.lock:
            if not self.state.CLOSED:
                self.err("connect() in socket state {0}".format(self.state))
                if self.state.ESTABLISHED:
                    raise Error(errno.EISCONN)
                if self.state.CONNECT:
                    raise Error(errno.EALREADY)
                raise Error(errno.EPIPE)
            if type(dest) is StringType:
                pdu = Connect(1, self.addr, self.recv_miu, self.recv_win, dest)
            elif type(dest) is IntType:
                pdu = Connect(dest, self.addr, self.recv_miu, self.recv_win)
            else: raise TypeError("connect() arg *dest* must be int or string")
            self.state.CONNECT = True
            self.send_queue.append(pdu)
            try: pdu = super(DataLinkConnection, self).recv()
            except IndexError: raise Error(errno.EPIPE)
            if isinstance(pdu, DisconnectedMode):
                self.log("connect rejected with reason {0}".format(pdu.reason))
                self.state.CLOSED = True
                raise ConnectRefused(pdu.reason)
            if isinstance(pdu, ConnectionComplete):
                self.peer = pdu.ssap
                self.recv_buf = self.recv_win
                self.send_miu = pdu.miu
                self.send_win = pdu.rw
                self.state.ESTABLISHED = True
                return
            raise RuntimeError("only CC or DM expected, not " + pdu.name)

    @property
    def send_window_slots(self):
        # RW(R) - V(S) + V(SA) mod 16
        return (self.send_win - self.send_cnt + self.send_ack) % 16

    @property
    def recv_window_slots(self):
        # RW(L) - V(R) + V(RA) mod 16
        return (self.recv_win - self.recv_cnt + self.recv_ack) % 16

    def send(self, message):
        with self.send_token:
            if not self.state.ESTABLISHED:
                self.err("send() in socket state {0}".format(self.state))
                if self.state.CLOSE_WAIT:
                    raise Error(errno.EPIPE)
                raise Error(errno.ENOTCONN)
            if len(message) > self.send_miu:
                raise Error(errno.EMSGSIZE)
            while self.send_window_slots == 0 and self.state.ESTABLISHED:
                self.log("waiting on busy send window")
                self.send_token.wait()
            self.log("send() {0}".format(str(self)))
            if self.state.ESTABLISHED:
                pdu = Information(self.peer, self.addr, sdu=message)
                pdu.ns = self.send_cnt
                self.send_cnt = (self.send_cnt + 1) % 16
                super(DataLinkConnection, self).send(pdu)
            return self.state.ESTABLISHED == True

    def recv(self):
        with self.lock:
            if not (self.state.ESTABLISHED or self.state.CLOSE_WAIT):
                self.err("recv() in socket state {0}".format(self.state))
                raise Error(errno.ENOTCONN)
            try: pdu = super(DataLinkConnection, self).recv()
            except IndexError: return None
            if isinstance(pdu, Information):
                self.recv_confs += 1
                if self.recv_confs > self.recv_win:
                    self.err("recv_confs({0}) > recv_win({1})"
                             .format(self.recv_confs, self.recv_win))
                    raise RuntimeError("recv_confs > recv_win")
                return pdu.sdu
            if isinstance(pdu, Disconnect):
                self.close()
                return None
            raise RuntimeError("only I or DISC expected, not "+ pdu.name)

    def poll(self, event, timeout):
        if self.state.SHUTDOWN:
            raise Error(errno.EBADF)
        if not event in ("recv", "send", "acks"):
            raise Error(errno.EINVAL)
        if event == "recv":
            if self.state.ESTABLISHED or self.state.CLOSE_WAIT:
                ptype = super(DataLinkConnection, self).poll(event, timeout)
                if self.state.ESTABLISHED or self.state.CLOSE_WAIT:
                    return ptype == ProtocolDataUnit.Information
                else: return False
        if event == "send":
            if self.state.ESTABLISHED:
                if super(DataLinkConnection, self).poll(event, timeout):
                    return self.state.ESTABLISHED
        if event == "acks":
            with self.acks_ready:
                while not self.acks_recvd > 0:
                    self.acks_ready.wait(timeout)
                if self.acks_recvd > 0:
                    self.acks_recvd = self.acks_recvd - 1
                    return True
        return False

    def close(self):
        with self.lock:
            self.log("close()")
            if self.state.ESTABLISHED and self.is_bound:
                self.state.DISCONNECT = True
                self.send_token.notify_all()
                self.acks_ready.notify_all()
                pdu = Disconnect(self.peer, self.addr)
                self.send_queue.append(pdu)
                try: super(DataLinkConnection, self).recv()
                except IndexError: pass
            super(DataLinkConnection, self).close()
            self.acks_ready.notify_all()
            self.send_token.notify_all()

    #
    # enqueue() and dequeue() are called from llc thread context
    #
    def enqueue(self, pdu):
        self.log("enqueue {pdu.name} PDU".format(pdu=pdu))
        if not pdu.type in connection_mode_pdu_types:
            self.err("non connection mode pdu on data link connection")
            pdu = FrameReject.from_pdu(pdu, flags="W", dlc=self)
            self.close(); self.send_queue.append(pdu)
            return

        if self.state.CLOSED:
            pdu = DisconnectedMode(pdu.ssap, pdu.dsap, reason=1)
            self.send_queue.append(pdu)

        if self.state.LISTEN:
            if isinstance(pdu, Connect):
                if super(DataLinkConnection, self).enqueue(pdu) == False:
                    log.warn("full backlog on listening socket")
                    pdu = DisconnectedMode(pdu.ssap, pdu.dsap, reason=0x20)
                    self.send_queue.append(pdu)
                    return False
                return True

        if self.state.CONNECT:
            if (isinstance(pdu, ConnectionComplete) or
                isinstance(pdu, DisconnectedMode)):
                with self.lock:
                    self.recv_queue.append(pdu)
                    self.recv_ready.notify()

        if self.state.DISCONNECT:
            if isinstance(pdu, DisconnectedMode):
                with self.lock:
                    self.recv_queue.append(pdu)
                    self.recv_ready.notify()

        if self.state.ESTABLISHED:
            return self._enqueue_state_established(pdu)

    def _enqueue_state_established(self, pdu):
        if isinstance(pdu, Information):
            if len(pdu.sdu) > self.recv_miu:
                self.log("reject " + str(self))
                pdu = FrameReject.from_pdu(pdu, flags="I", dlc=self)
            elif pdu.ns != self.recv_cnt:
                self.log("reject " + str(self))
                pdu = FrameReject.from_pdu(pdu, flags="S", dlc=self)
            if isinstance(pdu, FrameReject):
                self.send_queue.clear()
                self.send_queue.append(pdu)
                log.debug("enqueued frame reject")
                return

        if isinstance(pdu, FrameReject):
            with self.lock:
                self.state.SHUTDOWN = True
                self.close()
            return

        if isinstance(pdu, Disconnect):
            with self.lock:
                self.state.CLOSE_WAIT = True
                pdu = DisconnectedMode(self.peer, self.addr, reason=0)
                self.send_queue.clear()
                self.send_queue.append(pdu)
            return

        if (isinstance(pdu, Information) or
            isinstance(pdu, ReceiveReady) or
            isinstance(pdu, ReceiveNotReady)):
            with self.lock:
                # acks = N(R) - V(SA) mod 16
                acks = (pdu.nr - self.send_ack) % 16
                if acks:
                    self.acks_recvd += acks
                    self.acks_ready.notify_all()
                    self.send_token.notify()
                    self.send_ack = pdu.nr # V(SA) := N(R)
                if isinstance(pdu, ReceiveNotReady):
                    self.mode.SEND_BUSY = True
                if isinstance(pdu, ReceiveReady):
                    self.mode.SEND_BUSY = False

        if isinstance(pdu, Information):
            with self.lock:
                # V(R) := V(R) + 1 mod 16
                self.recv_cnt = (self.recv_cnt + 1) % 16
            super(DataLinkConnection, self).enqueue(pdu)

    def dequeue(self, maxlen):
        self.super = super(DataLinkConnection, self)
        with self.lock:
            if self.state.ESTABLISHED:
                if self.mode.RECV_BUSY_SENT != self.mode.RECV_BUSY:
                    self.mode.RECV_BUSY_SENT = self.mode.RECV_BUSY
                    Ack = (ReceiveReady, ReceiveNotReady)[self.mode.RECV_BUSY]
                    return Ack(self.peer, self.addr, self.recv_ack)

            try: pdu = self.super.dequeue(maxlen, notify=False)
            except IndexError: pdu = None # no pdu available
            if pdu: self.log("dequeue {0} PDU".format(pdu.name))

            if isinstance(pdu, FrameReject):
                self.state.SHUTDOWN = True
                self.close()
            elif isinstance(pdu, Information) and self.state.ESTABLISHED:
                if (self.recv_confs and self.recv_cnt != self.recv_ack):
                    self.log("piggyback ack " + str(self))
                    self.recv_ack = (self.recv_ack + self.recv_confs) % 16
                    self.recv_confs = 0
                pdu.nr = self.recv_ack
                self.send_ready.notify()
            elif isinstance(pdu, DisconnectedMode) and self.state.CLOSE_WAIT:
                dm = Disconnect(dsap=self.peer, ssap=self.addr)
                self.recv_queue.append(dm)
                self.recv_ready.notify()
                self.send_token.notify_all()
            elif pdu is None and self.state.ESTABLISHED:
                if (self.recv_confs and maxlen >= 3 and
                    self.recv_window_slots == 0):
                    self.log("necessary ack " + str(self))
                    self.recv_ack = (self.recv_ack + self.recv_confs) % 16
                    self.recv_confs = 0
                    Ack = (ReceiveReady, ReceiveNotReady)[self.mode.RECV_BUSY]
                    pdu = Ack(self.peer, self.addr, self.recv_ack)
            return pdu

    def sendack(self, maxlen):
        if self.state.ESTABLISHED:
            with self.lock:
                if (self.recv_confs and maxlen >= 3 and
                    self.recv_cnt != self.recv_ack):
                    self.log("voluntary ack " + str(self))
                    self.recv_ack = (self.recv_ack + self.recv_confs) % 16
                    self.recv_confs = 0
                    Ack = (ReceiveReady, ReceiveNotReady)[self.mode.RECV_BUSY]
                    pdu = Ack(self.peer, self.addr, self.recv_ack)
                    return pdu

