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

import logging
log = logging.getLogger(__name__)

import time
from types import *
import threading
import collections
import random

import nfc.clf
import nfc.dep

# local imports
from tco import *
from pdu import *
from err import *
from opt import *

RAW_ACCESS_POINT, LOGICAL_DATA_LINK, DATA_LINK_CONNECTION = range(3)

wks_map = {
    "urn:nfc:sn:sdp" : 1,
    "urn:nfc:sn:ip"  : 2,
    "urn:nfc:sn:obex": 3,
    "urn:nfc:sn:snep": 4}

class ServiceAccessPoint(object):
    def __init__(self, addr, llc):
        self.llc = llc
        self.addr = addr
        self.sock_list = collections.deque()
        self.send_list = collections.deque()

    def __str__(self):
        return "SAP {0:>2}".format(self.addr)

    @property
    def mode(self):
        with self.llc.lock:
            try:
                if isinstance(self.sock_list[0], RawAccessPoint):
                    return RAW_ACCESS_POINT
                if isinstance(self.sock_list[0], LogicalDataLink):
                    return LOGICAL_DATA_LINK
                if isinstance(self.sock_list[0], DataLinkConnection):
                    return DATA_LINK_CONNECTION
            except IndexError: return 0

    def insert_socket(self, socket):
        with self.llc.lock:
            try: insertable = type(socket) == type(self.sock_list[0])
            except IndexError: insertable = True
            if insertable:
                socket.bind(self.addr)
                self.sock_list.appendleft(socket)
            else: log.error("can't insert socket of different type")
            return insertable

    def remove_socket(self, socket):
        assert socket.addr == self.addr
        socket.close()
        with self.llc.lock:
            try: self.sock_list.remove(socket)
            except ValueError: pass
            if len(self.sock_list) == 0:
                # completely remove this sap
                self.llc.sap[self.addr] = None

    def send(self, pdu):
        self.send_list.append(pdu)

    def shutdown(self):
        while True:
            try: socket = self.sock_list.pop()
            except IndexError: return
            log.debug("shutdown socket %s" % str(socket))
            socket.bind(None); socket.close()

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, pdu):
        with self.llc.lock:
            if isinstance(pdu, Connect):
                for socket in self.sock_list:
                    if socket.state.LISTEN:
                        socket.enqueue(pdu)
                        return
            else:
                for socket in self.sock_list:
                    if pdu.ssap == socket.peer or socket.peer is None:
                        socket.enqueue(pdu)
                        return
                    
            if pdu.type in connection_mode_pdu_types:
                self.send(DisconnectedMode(pdu.ssap, pdu.dsap, reason=1))

    def dequeue(self, max_size):
        with self.llc.lock:
            for socket in self.sock_list:
                #print "dequeue from", socket
                pdu = socket.dequeue(max_size)
                if pdu: return pdu
            else:
                try: return self.send_list.popleft()
                except IndexError: pass

    def sendack(self, max_size):
        with self.llc.lock:
            for socket in self.sock_list:
                pdu = socket.sendack(max_size)
                if pdu: return pdu

class ServiceDiscovery(object):
    def __init__(self, llc):
        self.llc = llc
        self.snl = dict()
        self.tids = range(256)
        self.resp = threading.Condition(self.llc.lock)
        self.sent = dict()
        self.sdreq = collections.deque()
        self.sdres = collections.deque()
        self.dmpdu = collections.deque()

    def __str__(self):
        return "SAP  1"

    @property
    def mode(self):
        return LOGICAL_DATA_LINK

    def resolve(self, name):
        with self.resp:
            if self.snl is None: return None
            log.debug("resolve service name '{0}'".format(name))
            try: return self.snl[name]
            except KeyError: pass
            tid = random.choice(self.tids)
            self.tids.remove(tid)
            self.sdreq.append((tid, name))
            while not self.snl is None and not name in self.snl:
                self.resp.wait()
            return None if self.snl is None else self.snl[name]

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, pdu):
        with self.llc.lock:
            if isinstance(pdu, ServiceNameLookup) and not self.snl is None:
                for tid, sap in pdu.sdres:
                    try: name = self.sent[tid]
                    except KeyError: pass
                    else:
                        log.debug("resolved '{0}' to remote addr {1}"
                                  .format(name, sap))
                        self.snl[name] = sap
                        self.tids.append(tid)
                        self.resp.notify_all()
                for tid, name in pdu.sdreq:
                    try: sap = self.llc.snl[name]
                    except KeyError: sap = 0
                    self.sdres.append((tid, sap))

    def dequeue(self, max_size):
        if max_size < 2:
            return None
        with self.llc.lock:
            if len(self.sdres) > 0 or len(self.sdreq) > 0:
                pdu = ServiceNameLookup(dsap=1, ssap=1)
                max_size -= len(pdu)
                while max_size > 0:
                    try: pdu.sdres.append(self.sdres.popleft())
                    except IndexError: break
                for i in range(len(self.sdreq)):
                    tid, name = self.sdreq[0]
                    if 1 + len(name) > max_size:
                        self.sdreq.rotate(-1)
                    else:
                        pdu.sdreq.append(self.sdreq.popleft())
                        self.sent[tid] = name
                return pdu
            if len(self.dmpdu) > 0 and max_size >= 2:
                return self.dmpdu.popleft()

    def shutdown(self):
        with self.llc.lock:
            self.snl = None
            self.resp.notify_all()

class LogicalLinkController(object):
    def __init__(self, recv_miu=248, send_lto=500, send_agf=True,
                 symm_log=True):
        self.lock = threading.RLock()
        self.cfg = dict()
        self.cfg['recv-miu'] = recv_miu
        self.cfg['send-lto'] = send_lto
        self.cfg['send-agf'] = send_agf
        self.cfg['symm-log'] = symm_log
        self.snl = dict({"urn:nfc:sn:sdp" : 1})
        self.sap = 64 * [None]
        self.sap[0] = ServiceAccessPoint(0, self)
        self.sap[1] = ServiceDiscovery(self)

    def __str__(self):
        local = "Local(MIU={miu}, LTO={lto}ms)".format(
            miu=self.cfg.get('recv-miu'), lto=self.cfg.get('send-lto'))
        remote = "Remote(MIU={miu}, LTO={lto}ms)".format(
            miu=self.cfg.get('send-miu'), lto=self.cfg.get('recv-lto'))
        return "LLC: {local} {remote}".format(local=local, remote=remote)

    def activate(self, mac):
        assert type(mac) in (nfc.dep.Initiator, nfc.dep.Target)
        self.mac = None
        
        miu = self.cfg['recv-miu']
        lto = self.cfg['send-lto']
        wks = 1+sum(sorted([1<<sap for sap in self.snl.values() if sap < 15]))
        pax = ParameterExchange(version=(1,1), miu=miu, lto=lto, wks=wks)
        
        if type(mac) == nfc.dep.Initiator:
            gb = mac.activate(gbi='Ffm'+pax.to_string()[2:])
            self.run = self.run_as_initiator
            role = "Initiator"
        if type(mac) == nfc.dep.Target:
            gb = mac.activate(gbt='Ffm'+pax.to_string()[2:], wt=9)
            self.run = self.run_as_target
            role = "Target"

        if gb is not None and gb.startswith('Ffm') and len(gb) >= 6:
            info = ["LLCP Link established as NFC-DEP {0}".format(role)]

            info.append("Local LLCP Settings")
            info.append("  LLCP Version: {0[0]}.{0[1]}".format(pax.version))
            info.append("  Link Timeout: {0} ms".format(pax.lto))
            info.append("  Max Inf Unit: {0} octet".format(pax.miu))
            info.append("  Service List: {0:016b}".format(pax.wks))

            pax = ProtocolDataUnit.from_string("\x00\x40" + str(gb[3:]))
            info.append("Remote LLCP Settings")
            info.append("  LLCP Version: {0[0]}.{0[1]}".format(pax.version))
            info.append("  Link Timeout: {0} ms".format(pax.lto))
            info.append("  Max Inf Unit: {0} octet".format(pax.miu))
            info.append("  Service List: {0:016b}".format(pax.wks))
            log.info('\n'.join(info))

            self.cfg['rcvd-ver'] = pax.version
            self.cfg['send-miu'] = pax.miu
            self.cfg['recv-lto'] = pax.lto
            self.cfg['send-wks'] = pax.wks
            self.cfg['send-lsc'] = pax.lsc
            log.debug("llc cfg {0}".format(self.cfg))
            
            if type(mac) == nfc.dep.Initiator and mac.rwt is not None:
                max_rwt = 4096/13.56E6 * 2**10
                if mac.rwt > max_rwt:
                    log.warning("NFC-DEP RWT {0:.3f} exceeds max {1:.3f} sec"
                                .format(mac.rwt, max_rwt))

            self.mac = mac

        return bool(self.mac)

    def terminate(self, reason):
        log.debug("llcp link termination caused by {0}".format(reason))
        if reason == "local choice":
            self.exchange(Disconnect(0, 0), timeout=0.1)
            self.mac.deactivate()
        elif reason == "remote choice":
            self.mac.deactivate()
        # shutdown local services
        for i in range(63, -1, -1):
            if not self.sap[i] is None:
                log.debug("closing service access point %d" % i)
                self.sap[i].shutdown()
                self.sap[i] = None
        
    def exchange(self, pdu, timeout):
        if not isinstance(pdu, Symmetry) or self.cfg.get('symm-log') is True:
            log.debug("SEND {0}".format(pdu))

        data = pdu.to_string() if pdu else None
        try:
            data = self.mac.exchange(data, timeout)
            if data is None: return None
        except nfc.clf.DigitalProtocolError as error:
            log.debug("{0!r}".format(error))
            return None

        pdu = ProtocolDataUnit.from_string(data)
        if not isinstance(pdu, Symmetry) or self.cfg.get('symm-log') is True:
            log.debug("RECV {0}".format(pdu))
        return pdu

    def run_as_initiator(self, terminate=lambda: False):
        recv_timeout = 1E-3 * (self.cfg['recv-lto'] + 10)
        symm = 0

        try:
            pdu = self.collect(delay=0.01)
            while not terminate():
                if pdu is None: pdu = Symmetry()
                pdu = self.exchange(pdu, recv_timeout)
                if pdu is None:
                    return self.terminate(reason="link disruption")
                if pdu == Disconnect(0, 0):
                    return self.terminate(reason="remote choice")
                symm = symm + 1 if type(pdu) == Symmetry else 0
                self.dispatch(pdu)
                pdu = self.collect(delay=0.001)
                if pdu is None and symm >= 10:
                    pdu = self.collect(delay=0.05)
            else:
                self.terminate(reason="local choice")
        except KeyboardInterrupt:
            print # move to new line
            self.terminate(reason="local choice")
            raise KeyboardInterrupt
        except IOError:
            self.terminate(reason="input/output error")
            raise SystemExit
        finally:
            log.debug("llc run loop terminated on initiator")

    def run_as_target(self, terminate=lambda: False):
        recv_timeout = 1E-3 * (self.cfg['recv-lto'] + 10)
        symm = 0
        
        try:
            pdu = None
            while not terminate():
                pdu = self.exchange(pdu, recv_timeout)
                if pdu is None:
                    return self.terminate(reason="link disruption")
                if pdu == Disconnect(0, 0):
                    return self.terminate(reason="remote choice")
                symm = symm + 1 if type(pdu) == Symmetry else 0
                self.dispatch(pdu)
                pdu = self.collect(delay=0.001)
                if pdu is None and symm >= 10:
                    pdu = self.collect(delay=0.05)
                if pdu is None: pdu = Symmetry()
            else:
                self.terminate(reason="local choice")
        except KeyboardInterrupt:
            print # move to new line
            self.terminate(reason="local choice")
            raise KeyboardInterrupt
        except IOError:
            self.terminate(reason="input/output error")
            raise SystemExit
        finally:
            log.debug("llc run loop terminated on target")

    def collect(self, delay=None):
        if delay: time.sleep(delay)
        pdu_list = list()
        max_data = None
        with self.lock:
            active_sap_list = [sap for sap in self.sap if sap is not None]
            for sap in active_sap_list:
                #log.debug("query sap {0}, max_data={1}"
                #          .format(sap, max_data))
                pdu = sap.dequeue(max_data if max_data else 2179)
                if pdu is not None:
                    if self.cfg['send-agf'] == False:
                        return pdu
                    pdu_list.append(pdu)
                    if max_data is None:
                        max_data = self.cfg["send-miu"] + 2
                    max_data -= len(pdu)
                    if max_data < bool(len(pdu_list)==1) * 2 + 2 + 2:
                        break
            else: max_data = self.cfg["send-miu"] + 2

            for sap in active_sap_list:
                if sap.mode == DATA_LINK_CONNECTION:
                    pdu = sap.sendack(max_data)
                    if not pdu is None:
                        if self.cfg['send-agf'] == False:
                            return pdu
                        pdu_list.append(pdu)
                        max_data -= len(pdu)
                        if max_data < bool(len(pdu_list)==1) * 2 + 2 + 3:
                            break

        if len(pdu_list) > 1:
            return AggregatedFrame(aggregate=pdu_list)
        if len(pdu_list) == 1:
            return pdu_list[0]
        return None

    def dispatch(self, pdu):
        if isinstance(pdu, Symmetry):
            return

        if isinstance(pdu, AggregatedFrame):
            if pdu.dsap == 0 and pdu.ssap == 0:
                [log.debug("     " + str(p)) for p in pdu]
                [self.dispatch(p) for p in pdu]
            return

        if isinstance(pdu, Connect) and pdu.dsap == 1:
            # connect-by-name
            addr = self.snl.get(pdu.sn)
            if not addr or self.sap[addr] is None:
                log.debug("no service named '{0}'".format(pdu.sn))
                pdu = DisconnectedMode(pdu.ssap, 1, reason=2)
                self.sap[1].dmpdu.append(pdu)
                return
            pdu = Connect(dsap=addr, ssap=pdu.ssap, rw=pdu.rw, miu=pdu.miu)

        with self.lock:
            sap = self.sap[pdu.dsap]
            if sap:
                sap.enqueue(pdu)
                return

        log.debug("discard PDU {0}".format(str(pdu)))
        return

    def resolve(self, name):
        return self.sap[1].resolve(name)

    def socket(self, socket_type):
        if socket_type == RAW_ACCESS_POINT:
            return RawAccessPoint(recv_miu=self.cfg["recv-miu"])
        if socket_type == LOGICAL_DATA_LINK:
            return LogicalDataLink(recv_miu=self.cfg["recv-miu"])
        if socket_type == DATA_LINK_CONNECTION:
            return DataLinkConnection(recv_miu=128, recv_win=1)

    def setsockopt(self, socket, option, value):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if option == SO_RCVMIU:
            value = min(value, self.cfg['recv-miu'])
        socket.setsockopt(option, value)
        return socket.getsockopt(option)

    def getsockopt(self, socket, option):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if isinstance(socket, LogicalDataLink):
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
        if isinstance(socket, RawAccessPoint):
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
        return socket.getsockopt(option)

    def bind(self, socket, addr_or_name=None):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if not socket.addr is None:
            raise Error(errno.EINVAL)
        if addr_or_name is None:
            self._bind_by_none(socket)
        elif type(addr_or_name) is IntType:
            self._bind_by_addr(socket, addr_or_name)
        elif type(addr_or_name) is StringType:
            self._bind_by_name(socket, addr_or_name)
        else: raise Error(errno.EFAULT)

    def _bind_by_none(self, socket):
        with self.lock:
            try: addr = 32 + self.sap[32:64].index(None)
            except ValueError: raise Error(errno.EAGAIN)
            else:
                socket.bind(addr)
                self.sap[addr] = ServiceAccessPoint(addr, self)
                self.sap[addr].insert_socket(socket)

    def _bind_by_addr(self, socket, addr):
        with self.lock:
            if addr in range(32, 64):
                if self.sap[addr] is None:
                    socket.bind(addr)
                    self.sap[addr] = ServiceAccessPoint(addr, self)
                    self.sap[addr].insert_socket(socket)
                else: raise Error(errno.EADDRINUSE)
            else: raise Error(errno.EACCES)

    def _bind_by_name(self, socket, name):
        if not (name.startswith("urn:nfc:sn") or
                name.startswith("urn:nfc:xsn") or
                name == "com.android.npp"): # invalid name but legacy
            raise Error(errno.EFAULT)
        with self.lock:
            if self.snl.get(name) != None:
                raise Error(errno.EADDRINUSE)
            addr = wks_map.get(name)
            if addr is None:
                try: addr = 16 + self.sap[16:32].index(None)
                except ValueError: raise Error(errno.EADDRNOTAVAIL)
            socket.bind(addr)
            self.sap[addr] = ServiceAccessPoint(addr, self)
            self.sap[addr].insert_socket(socket)
            self.snl[name] = addr

    def connect(self, socket, dest):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if not socket.is_bound:
            self.bind(socket)
        socket.connect(dest)
        log.debug("connected ({0} ===> {1})".format(socket.addr, socket.peer))

    def listen(self, socket, backlog):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if not isinstance(socket, DataLinkConnection):
            raise Error(errno.EOPNOTSUPP)
        if not type(backlog) == IntType:
            raise TypeError("backlog must be integer")
        if backlog < 0:
            raise ValueError("backlog mmust not be negative")
        backlog = min(backlog, 16)
        if not socket.is_bound:
            self.bind(socket)
        socket.listen(backlog)

    def accept(self, socket):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if not isinstance(socket, DataLinkConnection):
            raise Error(errno.EOPNOTSUPP)
        while True:
            client = socket.accept()
            if not client.is_bound:
                self.bind(client)
            if self.sap[client.addr].insert_socket(client):
                log.debug("new data link connection ({0} <=== {1})"
                          .format(client.addr, client.peer))
                return client
            else:
                pdu = DisconnectedMode(client.peer, socket.addr, reason=0x20)
                super(DataLinkConnection, socket).send(pdu)

    def send(self, socket, message):
        return self.sendto(socket, message, socket.peer)

    def sendto(self, socket, message, dest):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if isinstance(socket, RawAccessPoint):
            if not isinstance(message, ProtocolDataUnit):
                raise TypeError("message must be a pdu on raw access point")
            if not socket.is_bound:
                self.bind(socket)
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
            return socket.send(message)
        if not type(message) == StringType:
            raise TypeError("sendto() argument *message* must be a string")
        if isinstance(socket, LogicalDataLink):
            if dest is None:
                raise Error(errno.EDESTADDRREQ)
            if not socket.is_bound:
                self.bind(socket)
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
            return socket.sendto(message, dest)
        if isinstance(socket, DataLinkConnection):
            return socket.send(message)

    def recv(self, socket):
        message, sender = self.recvfrom(socket)
        return message

    def recvfrom(self, socket):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if not (socket.addr and self.sap[socket.addr]):
            raise Error(errno.EBADF)
        if isinstance(socket, RawAccessPoint):
            return (socket.recv(), None)
        if isinstance(socket, LogicalDataLink):
            return socket.recvfrom()
        if isinstance(socket, DataLinkConnection):
            return (socket.recv(), socket.peer)

    def poll(self, socket, event, timeout=None):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if not (socket.addr and self.sap[socket.addr]):
            raise Error(errno.EBADF)
        return socket.poll(event, timeout)

    def close(self, socket):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        if socket.is_bound:
            self.sap[socket.addr].remove_socket(socket)
        else: socket.close()

    def getsockname(self, socket):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        return socket.addr

    def getpeername(self, socket):
        if not isinstance(socket, TransmissionControlObject):
            raise Error(errno.ENOTSOCK)
        return socket.peer
