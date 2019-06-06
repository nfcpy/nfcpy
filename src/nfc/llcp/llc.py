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
from . import tco
from . import pdu
from . import err
from . import sec
import nfc.llcp
import nfc.clf
import nfc.dep

import re
import time
import errno
import random
import threading
import collections

import logging
log = logging.getLogger(__name__)

RAW_ACCESS_POINT, LOGICAL_DATA_LINK, DATA_LINK_CONNECTION = range(3)

wks_map = {
    b"urn:nfc:sn:sdp": 1,
    b"urn:nfc:sn:snep": 4,
}

service_name_format = \
    re.compile(b"^urn:nfc:[x]?sn:[a-zA-Z][a-zA-Z0-9-_:\\.]*$")


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
                if isinstance(self.sock_list[0], tco.RawAccessPoint):
                    return RAW_ACCESS_POINT
                if isinstance(self.sock_list[0], tco.LogicalDataLink):
                    return LOGICAL_DATA_LINK
                if isinstance(self.sock_list[0], tco.DataLinkConnection):
                    return DATA_LINK_CONNECTION
            except IndexError:
                return 0

    def insert_socket(self, socket):
        with self.llc.lock:
            try:
                insertable = isinstance(socket, type(self.sock_list[0]))
            except IndexError:
                insertable = True
            if insertable:
                socket.bind(self.addr)
                self.sock_list.appendleft(socket)
            else:
                log.error("can't insert socket of different type")
            return insertable

    def remove_socket(self, socket):
        assert socket.addr == self.addr
        socket.close()
        with self.llc.lock:
            try:
                self.sock_list.remove(socket)
            except ValueError:
                pass
            if len(self.sock_list) == 0:
                # completely remove this sap
                self.llc.sap[self.addr] = None

    def send(self, send_pdu):
        self.send_list.append(send_pdu)

    def shutdown(self):
        while True:
            try:
                socket = self.sock_list.pop()
            except IndexError:
                return
            log.debug("shutdown socket %s" % str(socket))
            socket.bind(None)
            socket.close()

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, rcvd_pdu):
        with self.llc.lock:
            if isinstance(rcvd_pdu, pdu.Connect):
                for socket in self.sock_list:
                    if socket.state.LISTEN:
                        socket.enqueue(rcvd_pdu)
                        break
                else:
                    args = (rcvd_pdu.ssap, rcvd_pdu.dsap, 0x02)
                    self.send(pdu.DisconnectedMode(*args))
            else:
                for socket in self.sock_list:
                    if rcvd_pdu.ssap == socket.peer or socket.peer is None:
                        socket.enqueue(rcvd_pdu)
                        break
                else:
                    if rcvd_pdu.name in tco.DataLinkConnection.DLC_PDU_NAMES:
                        args = (rcvd_pdu.ssap, rcvd_pdu.dsap, 0x01)
                        self.send(pdu.DisconnectedMode(*args))
                    else:
                        log.debug("%s discard PDU %s", self, rcvd_pdu)

    def dequeue(self, miu_size, icv_size):
        with self.llc.lock:
            for socket in self.sock_list:
                send_pdu = socket.dequeue(miu_size, icv_size)
                if send_pdu:
                    return send_pdu
            else:
                try:
                    return self.send_list.popleft()
                except IndexError:
                    pass

    def sendack(self):
        with self.llc.lock:
            for socket in self.sock_list:
                send_pdu = socket.sendack()
                if send_pdu:
                    return send_pdu


class ServiceDiscovery(object):
    def __init__(self, llc):
        self.llc = llc
        self.snl = dict()
        self.tids = list(range(256))
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
            if self.snl is None:
                return None
            log.debug("resolve service name %r", name)
            try:
                return self.snl[name]
            except KeyError:
                pass
            tid = random.choice(self.tids)
            self.tids.remove(tid)
            self.sdreq.append((tid, name))
            while self.snl is not None and name not in self.snl:
                self.resp.wait()
            return None if self.snl is None else self.snl[name]

    #
    # enqueue() and dequeue() are called from llc run thread
    #
    def enqueue(self, rcvd_pdu):
        with self.llc.lock:
            if ((isinstance(rcvd_pdu, pdu.ServiceNameLookup)
                 and self.snl is not None)):

                for tid, sap in rcvd_pdu.sdres:
                    try:
                        name = self.sent[tid]
                    except KeyError:
                        continue
                    log.debug("resolved %r to remote addr %d", name, sap)
                    csn, sap = sap >> 6 & 1, sap & 63
                    if csn:
                        sap = 1
                    self.snl[name] = sap
                    self.tids.append(tid)
                    self.resp.notify_all()

                for tid, name in rcvd_pdu.sdreq:
                    try:
                        sap = self.llc.snl[name]
                    except KeyError:
                        sap = 0
                    self.sdres.append((tid, sap))

    def dequeue(self, miu_size, icv_size):
        with self.llc.lock:
            if len(self.sdres) > 0 or len(self.sdreq) > 0:
                send_pdu = pdu.ServiceNameLookup(dsap=1, ssap=1)
                # add service discovery responses
                while miu_size > 0:
                    try:
                        send_pdu.sdres.append(self.sdres.popleft())
                        miu_size -= 4
                    except IndexError:
                        break
                # add service discovery requests
                for i in range(len(self.sdreq)):
                    tid, name = self.sdreq[0]
                    if 3 + len(name) > miu_size:
                        self.sdreq.rotate(-1)
                    else:
                        send_pdu.sdreq.append(self.sdreq.popleft())
                        self.sent[tid] = name
                        miu_size -= 3 + len(name)
                return send_pdu
            if len(self.dmpdu) > 0 and miu_size > 0:
                return self.dmpdu.popleft()

    def shutdown(self):
        with self.llc.lock:
            self.snl = None
            self.resp.notify_all()


class LogicalLinkController(object):
    class LinkState(object):
        def __init__(self):
            self.names = ("SHUTDOWN", "LISTEN", "CONNECT", "CONNECTED",
                          "ESTABLISHED", "DISCONNECT", "CLOSED")
            self.value = self.names.index("SHUTDOWN")

        def __str__(self):
            return self.names[self.value]

        def __getattr__(self, name):
            return self.value == self.names.index(name)

        def __setattr__(self, name, value):
            if name not in ("names", "value"):
                value, name = self.names.index(name), "value"
            parent = super(LogicalLinkController.LinkState, self)
            parent.__setattr__(name, value)

    class Counter(object):
        def __init__(self):
            self.sent = collections.defaultdict(int)
            self.rcvd = collections.defaultdict(int)

        @property
        def sent_count(self):
            return sum(self.sent.values())

        @property
        def rcvd_count(self):
            return sum(self.rcvd.values())

        def __str__(self):
            s = "sent/rcvd {0}/{1}".format(self.sent_count, self.rcvd_count)
            for name in sorted(set(list(self.sent.keys())
                                   + list(self.rcvd.keys()))):
                s += " {name} {sent}/{rcvd}".format(
                    name=name, sent=self.sent[name], rcvd=self.rcvd[name])
            return s

    def __init__(self, **options):
        self.pcnt = LogicalLinkController.Counter()
        self.link = LogicalLinkController.LinkState()
        self.lock = threading.RLock()
        self.cfg = dict()
        self.cfg['recv-miu'] = options.get('miu', 248)
        self.cfg['send-lto'] = options.get('lto', 500)
        self.cfg['send-lsc'] = options.get('lsc', 3)
        self.cfg['send-agf'] = options.get('agf', True)
        self.cfg['llcp-sec'] = options.get('sec', True)
        if not sec.OpenSSL:
            self.cfg['llcp-sec'] = False
        log.debug("llc cfg {0}".format(self.cfg))
        self.sec = None
        self.snl = dict({b"urn:nfc:sn:sdp": 1})
        self.sap = 64 * [None]
        self.sap[0] = ServiceAccessPoint(0, self)
        self.sap[1] = ServiceDiscovery(self)

    def __str__(self):
        local = "Local(MIU={miu}, LTO={lto}ms)".format(
            miu=self.cfg.get('recv-miu'), lto=self.cfg.get('send-lto'))
        remote = "Remote(MIU={miu}, LTO={lto}ms)".format(
            miu=self.cfg.get('send-miu'), lto=self.cfg.get('recv-lto'))
        return "LLC: {local} {remote}".format(local=local, remote=remote)

    @property
    def secure_data_transfer(self):
        return self.cfg.get('llcp-dpc', 0) == 1

    def activate(self, mac, **options):
        assert isinstance(mac, (nfc.dep.Initiator, nfc.dep.Target))
        self.mac = None

        wks = 1 + sum([1 << sap for sap in self.snl.values() if sap < 15])

        send_pax = pdu.ParameterExchange()
        send_pax.version = (1, 3)
        send_pax.wks = wks
        if self.cfg['recv-miu'] != 128:
            send_pax.miu = self.cfg['recv-miu']
        if self.cfg['send-lto'] != 100:
            send_pax.lto = self.cfg['send-lto']
        if self.cfg['send-lsc'] != 0:
            send_pax.lsc = self.cfg['send-lsc']
        if self.cfg['llcp-sec']:
            send_pax.dpc = 1

        gb = b'Ffm' + pdu.encode(send_pax)[2:]
        if isinstance(mac, nfc.dep.Initiator):
            self.link.CONNECT = True
            gb = mac.activate(gbi=gb, **options)
            self.run = self.run_as_initiator
        else:
            self.link.LISTEN = True
            gb = mac.activate(gbt=gb, **options)
            self.run = self.run_as_target

        if gb and gb.startswith(b'Ffm') and len(gb) >= 6:
            if ((isinstance(mac, nfc.dep.Target)
                 and mac.rwt >= send_pax.lto * 1E-3)):
                msg = "local NFC-DEP RWT {0:.3f} contradicts LTO {1:.3f} sec"
                log.warning(msg.format(mac.rwt, send_pax.lto*1E3))

            rcvd_pax = pdu.decode(b"\x00\x40" + bytes(gb[3:]))

            log.debug("SENT {0}".format(send_pax))
            log.debug("RCVD {0}".format(rcvd_pax))

            self.cfg['rcvd-ver'] = rcvd_pax.version
            self.cfg['send-miu'] = rcvd_pax.miu
            self.cfg['recv-lto'] = rcvd_pax.lto
            self.cfg['send-wks'] = rcvd_pax.wks
            self.cfg['send-lsc'] = rcvd_pax.lsc
            self.cfg['llcp-dpc'] = rcvd_pax.dpc if self.cfg['llcp-sec'] else 0
            log.debug("llc cfg {0}".format(self.cfg))

            info = '\n'.join([
                "LLCP Link established as NFC-DEP {role}",
                "Local LLCP Settings",
                "  LLCP Version: {send_pax.version_text}",
                "  Link Timeout: {send_pax.lto} ms",
                "  Max Inf Unit: {send_pax.miu} octet",
                "  Link Service: {send_pax.lsc_text}",
                "  Data Protect: {send_pax.dpc_text}",
                "  Service List: {send_pax.wks:016b} ({send_pax.wks_text})",
                "Remote LLCP Settings",
                "  LLCP Version: {rcvd_pax.version[0]}.{rcvd_pax.version[1]}",
                "  Link Timeout: {rcvd_pax.lto} ms",
                "  Max Inf Unit: {rcvd_pax.miu} octet",
                "  Link Service: {rcvd_pax.lsc_text}",
                "  Data Protect: {rcvd_pax.dpc_text}",
                "  Service List: {rcvd_pax.wks:016b} ({rcvd_pax.wks_text})"
            ]).format(role=mac.role, send_pax=send_pax, rcvd_pax=rcvd_pax)
            log.info(info)

            if isinstance(mac, nfc.dep.Initiator) and mac.rwt is not None:
                max_rwt = 4096/13.56E6 * 2**10
                if mac.rwt > max_rwt:
                    msg = "remote NFC-DEP RWT {0:.3f} exceeds max {1:.3f} sec"
                    log.warning(msg.format(mac.rwt, max_rwt))

            self.mac = mac
            self.link.CONNECTED = True

        return bool(self.mac)

    def terminate(self, reason):
        log.debug("llcp link termination caused by {0}".format(reason))
        if type(self.mac) == nfc.dep.Initiator:
            if self.link.DISCONNECT is True:
                self.exchange(pdu.Disconnect(0, 0), timeout=0.5)
            self.mac.deactivate(release=False)  # use DESELECT
        if type(self.mac) == nfc.dep.Target:
            self.mac.deactivate(data=bytearray(b"\x01\x40"))
        # shutdown local services
        for i in range(63, -1, -1):
            if not self.sap[i] is None:
                log.debug("closing service access point %d" % i)
                self.sap[i].shutdown()
                self.sap[i] = None
        self.link.SHUTDOWN = True

    def exchange(self, send_pdu, timeout):
        # Send and receive one protocol data unit. The send_pdu is
        # None for the first call when running as target (because the
        # target first receives a pdu). All PDUs except SYMM are
        # logged with debug level, SYMM is logged with DEBUG-1 so that
        # it must be explicitely enabled. The return value is either a
        # PDU instance or None.
        try:
            if send_pdu:
                loglevel = logging.DEBUG - bool(send_pdu.name == "SYMM")
                log.log(loglevel, "SEND %s", send_pdu)
                send_data = pdu.encode(send_pdu)
                self.pcnt.sent[send_pdu.name] += 1
                rcvd_data = self.mac.exchange(send_data, timeout)
            else:
                rcvd_data = self.mac.exchange(None, timeout)
            if rcvd_data is not None:
                rcvd_pdu = pdu.decode(rcvd_data)
                self.pcnt.rcvd[rcvd_pdu.name] += 1
                loglevel = logging.DEBUG - bool(rcvd_pdu.name == "SYMM")
                log.log(loglevel, "RECV %s", rcvd_pdu)
                return rcvd_pdu
        except (nfc.clf.CommunicationError, pdu.Error) as error:
            log.warning("{0!r}".format(error))

    def run_as_initiator(self, terminate=lambda: False):
        recv_timeout = 1E-3 * (self.cfg['recv-lto'] + 10)
        msg = "starting initiator run loop with a receive timeout of %.3f sec"
        log.debug(msg, recv_timeout)

        symm = 0  # counts the number of consecutive SYMM PDUs
        try:
            if self.cfg['llcp-dpc'] == 1:
                cipher = sec.cipher_suite("ECDH_anon_WITH_AEAD_AES_128_CCM_4")
                pubkey = cipher.public_key_x + cipher.public_key_y
                random = cipher.random_nonce
                send_dps = pdu.DataProtectionSetup(0, 0, pubkey, random)
                rcvd_dps = self.exchange(send_dps, recv_timeout)
                if not isinstance(rcvd_dps, pdu.DataProtectionSetup):
                    log.error("expected a DPS PDU response")
                    return self.terminate(reason="key agreement error")
                if not (rcvd_dps.ecpk and len(rcvd_dps.ecpk) == 64):
                    log.error("absent or invalid ECPK parameter in DPS PDU")
                    return self.terminate(reason="key agreement error")
                if not (rcvd_dps.rn and len(rcvd_dps.rn) == 8):
                    log.error("absent or invalid RN parameter in DPS PDU")
                    return self.terminate(reason="key agreement error")
                cipher.calculate_session_key(rcvd_dps.ecpk, rn_t=rcvd_dps.rn)
                self.sec = cipher

            send_pdu = self.collect(delay=0.01)
            self.link.ESTABLISHED = True
            while not terminate():
                if send_pdu is None:
                    send_pdu = pdu.Symmetry()
                rcvd_pdu = self.exchange(send_pdu, recv_timeout)
                if rcvd_pdu is None:
                    return self.terminate(reason="link disruption")
                if rcvd_pdu == pdu.Disconnect(0, 0):
                    self.link.CLOSED = True
                    return self.terminate(reason="remote choice")
                symm += 1 if rcvd_pdu.name == "SYMM" else 0
                self.dispatch(rcvd_pdu)
                send_pdu = self.collect(delay=0.001)
                if send_pdu is None and symm >= 10:
                    send_pdu = self.collect(delay=0.05)
            else:
                self.link.DISCONNECT = True
                self.terminate(reason="local choice")
        except KeyboardInterrupt:
            print()  # move to new line
            self.link.DISCONNECT = True
            self.terminate(reason="local choice")
            raise KeyboardInterrupt
        except IOError:
            self.terminate(reason="input/output error")
            raise SystemExit
        except sec.KeyAgreementError:
            self.terminate(reason="key agreement error")
            raise SystemExit
        except sec.DecryptionError:
            self.terminate(reason="decryption error")
            raise SystemExit
        except sec.EncryptionError:
            self.terminate(reason="encryption error")
            raise SystemExit
        finally:
            log.debug("llc run loop terminated on initiator")

    def run_as_target(self, terminate=lambda: False):
        recv_timeout = 1E-3 * (self.cfg['recv-lto'] + 10)
        msg = "starting target run loop with a receive timeout of %.3f sec"
        log.debug(msg, recv_timeout)

        symm = 0  # counts the number of consecutive SYMM PDUs
        try:
            if self.cfg['llcp-dpc'] == 1:
                cipher = sec.cipher_suite("ECDH_anon_WITH_AEAD_AES_128_CCM_4")
                pubkey = cipher.public_key_x + cipher.public_key_y
                random = cipher.random_nonce
                send_dps = pdu.DataProtectionSetup(0, 0, pubkey, random)
                rcvd_dps = self.exchange(None, recv_timeout)
                if not isinstance(rcvd_dps, pdu.DataProtectionSetup):
                    log.error("expected a DPS PDU request")
                    return self.terminate(reason="key agreement error")
                if not (rcvd_dps.ecpk and len(rcvd_dps.ecpk) == 64):
                    log.error("absent or invalid ECPK parameter in DPS PDU")
                    return self.terminate(reason="key agreement error")
                if not (rcvd_dps.rn and len(rcvd_dps.rn) == 8):
                    log.error("absent or invalid RN parameter in DPS PDU")
                    return self.terminate(reason="key agreement error")
                rcvd_pdu = self.exchange(send_dps, recv_timeout)
                cipher.calculate_session_key(rcvd_dps.ecpk, rn_i=rcvd_dps.rn)
                self.sec = cipher
            else:
                rcvd_pdu = self.exchange(None, recv_timeout)

            self.link.ESTABLISHED = True
            while not terminate():
                if rcvd_pdu is None:
                    return self.terminate(reason="link disruption")
                if rcvd_pdu == pdu.Disconnect(0, 0):
                    self.link.CLOSED = True
                    return self.terminate(reason="remote choice")
                symm += 1 if isinstance(rcvd_pdu, pdu.Symmetry) else 0
                self.dispatch(rcvd_pdu)
                send_pdu = self.collect(delay=0.001)
                if send_pdu is None and symm >= 10:
                    send_pdu = self.collect(delay=0.05)
                if send_pdu is None:
                    send_pdu = pdu.Symmetry()
                rcvd_pdu = self.exchange(send_pdu, recv_timeout)
            else:
                self.link.DISCONNECT = True
                self.terminate(reason="local choice")
        except KeyboardInterrupt:
            print()  # move to new line
            self.link.DISCONNECT = True
            self.terminate(reason="local choice")
            raise KeyboardInterrupt
        except IOError:
            self.terminate(reason="input/output error")
            raise SystemExit
        except sec.KeyAgreementError:
            self.terminate(reason="key agreement error")
            raise SystemExit
        except sec.DecryptionError:
            self.terminate(reason="decryption error")
            raise SystemExit
        except sec.EncryptionError:
            self.terminate(reason="encryption error")
            raise SystemExit
        finally:
            log.debug("llc run loop terminated on target")

    def collect(self, delay=None):
        # Collect a single PDU or multiple PDUs if aggregation is enabled.
        if delay:
            time.sleep(delay)

        def encrypt(send_pdu):
            pdu_type = type(send_pdu)
            a = send_pdu.encode_header()
            c = self.sec.encrypt(a, send_pdu.data)
            return pdu_type(*pdu_type.decode_header(a), data=c)

        miu_size = self.cfg["send-miu"]
        icv_size = self.sec.icv_size if self.sec else 0
        send_pdu = None

        with self.lock:
            # Dequeue from the list of active SAP until a first PDU is
            # returned. The list is sorted to first iterate the raw
            # SAPs (raw SAPs do not respect the miu_size value and we
            # must avoid them to return PDUs in aggregation). The PDU
            # is returned straight if it fills or exceeds the Link
            # MIU. Otherwise the loop terminates at this point. The
            # sap.dequeue method is called with icv_size=0 because for
            # encrypted but not aggregated UI and I PDUs the receiver
            # must accept them with complete MIU plus ICV size.
            for sap in sorted(filter(None, self.sap), reverse=True,
                              key=lambda sap: sap.mode == RAW_ACCESS_POINT):
                send_pdu = sap.dequeue(miu_size, icv_size=0)
                if send_pdu:
                    if self.sec and send_pdu.name in ("UI", "I"):
                        send_pdu = encrypt(send_pdu)
                    if len(send_pdu) - send_pdu.header_size >= miu_size:
                        return send_pdu
                    break

            # Data Link Connection endpoints do not dequeue RR/RNR PDUs until
            # the receive window is exhausted. If there is not yet a PDU to
            # send, this loop allows voluntary acknowledgement.
            if send_pdu is None:
                for sap in filter(None, self.sap):
                    if sap.mode == DATA_LINK_CONNECTION:
                        send_pdu = sap.sendack()
                        if send_pdu:
                            break

            # Finish if either there is either no PDU to send or if PDU
            # aggregation is disabled.
            if send_pdu is None or self.cfg['send-agf'] is False:
                return send_pdu

            # We have one PDU to send and aggregation is enabled. We'll see if
            # there are more outbound PDUs and collect them into an AGF PDU.
            agf_pdu = pdu.AggregatedFrame(0, 0, [send_pdu])
            miu_size = self.cfg["send-miu"] - len(agf_pdu) - 3
            while True:
                # The first loop will dequeue PDUs until the reamining miu_size
                # is exhausted or all active SAP did not return a PDU.
                deq_none = True
                for sap in filter(None, self.sap):
                    send_pdu = sap.dequeue(miu_size, icv_size)
                    if send_pdu:
                        deq_none = False
                        if self.sec and send_pdu.name in ("UI", "I"):
                            send_pdu = encrypt(send_pdu)
                        agf_pdu.append(send_pdu)
                        miu_size = self.cfg["send-miu"] - len(agf_pdu) - 3
                        if miu_size < 0:
                            break
                if miu_size < 0 or deq_none:
                    break
            # If the miu_size is not yet exhausted we query all data link
            # connection endpoints once for voluntary acknowledgements.
            if miu_size >= 0:
                for sap in filter(None, self.sap):
                    if sap.mode == DATA_LINK_CONNECTION:
                        send_pdu = sap.sendack()
                        if send_pdu:
                            agf_pdu.append(send_pdu)
                            miu_size = self.cfg["send-miu"] - len(agf_pdu) - 3
                            if miu_size < 0:
                                break

            return agf_pdu if agf_pdu.count > 1 else agf_pdu.first

    def dispatch(self, rcvd_pdu):
        if rcvd_pdu is None or rcvd_pdu.name == "SYMM":
            return

        if rcvd_pdu.name == "AGF":
            if rcvd_pdu.dsap == 0 and rcvd_pdu.ssap == 0:
                for p in rcvd_pdu:
                    log.debug("     " + str(p))
                for p in rcvd_pdu:
                    self.dispatch(p)
            return

        if rcvd_pdu.name == "CONNECT" and rcvd_pdu.dsap == 1:
            # connect-by-name
            addr = self.snl.get(rcvd_pdu.sn)
            if not addr or self.sap[addr] is None:
                dm_reason = 0x10 if rcvd_pdu.sn is None else 0x02
                dm_pdu = pdu.DisconnectedMode(rcvd_pdu.ssap, 1, dm_reason)
                self.sap[1].dmpdu.append(dm_pdu)
                log.debug("could not find service %r", rcvd_pdu.sn)
                return
            # service found, rewrite CONNECT PDU to its DSAP
            rcvd_pdu = pdu.Connect(dsap=addr, ssap=rcvd_pdu.ssap,
                                   rw=rcvd_pdu.rw, miu=rcvd_pdu.miu)

        if self.sec and rcvd_pdu.name in ("UI", "I"):
            pdu_type = type(rcvd_pdu)
            a = rcvd_pdu.encode_header()
            p = self.sec.decrypt(a, rcvd_pdu.data)
            rcvd_pdu = pdu_type(*pdu_type.decode_header(a), data=p)

        with self.lock:
            sap = self.sap[rcvd_pdu.dsap]
            if sap:
                sap.enqueue(rcvd_pdu)
            else:
                log.debug("can't dispatch PDU %s", rcvd_pdu)

    def resolve(self, name):
        if isinstance(name, (bytes, bytearray)):
            return self.sap[1].resolve(bytes(name))
        return self.sap[1].resolve(name.encode('latin'))

    def socket(self, socket_type):
        if socket_type == RAW_ACCESS_POINT:
            return tco.RawAccessPoint(recv_miu=self.cfg["recv-miu"])
        if socket_type == LOGICAL_DATA_LINK:
            return tco.LogicalDataLink(recv_miu=self.cfg["recv-miu"])
        if socket_type == DATA_LINK_CONNECTION:
            return tco.DataLinkConnection(recv_miu=128, recv_win=1)

    def setsockopt(self, socket, option, value):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if option == nfc.llcp.SO_RCVMIU:
            value = min(value, self.cfg['recv-miu'])
        socket.setsockopt(option, value)
        return socket.getsockopt(option)

    def getsockopt(self, socket, option):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if isinstance(socket, tco.LogicalDataLink):
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
        if isinstance(socket, tco.RawAccessPoint):
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
        return socket.getsockopt(option)

    def bind(self, socket, addr_or_name=None):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if socket.addr is not None:
            raise err.Error(errno.EINVAL)
        if addr_or_name is None:
            self._bind_by_none(socket)
        elif isinstance(addr_or_name, int):
            self._bind_by_addr(socket, addr_or_name)
        elif isinstance(addr_or_name, (bytes, bytearray)):
            self._bind_by_name(socket, bytes(addr_or_name))
        elif isinstance(addr_or_name, str):
            self._bind_by_name(socket, addr_or_name.encode('latin'))
        else:
            raise err.Error(errno.EFAULT)

    def _bind_by_none(self, socket):
        with self.lock:
            try:
                addr = 32 + self.sap[32:64].index(None)
            except ValueError:
                raise err.Error(errno.EAGAIN)
            else:
                socket.bind(addr)
                self.sap[addr] = ServiceAccessPoint(addr, self)
                self.sap[addr].insert_socket(socket)

    def _bind_by_addr(self, socket, addr):
        if addr < 0 or addr > 63:
            raise err.Error(errno.EFAULT)
        with self.lock:
            if addr in range(32, 64) or isinstance(socket, tco.RawAccessPoint):
                if self.sap[addr] is None:
                    socket.bind(addr)
                    self.sap[addr] = ServiceAccessPoint(addr, self)
                    self.sap[addr].insert_socket(socket)
                else:
                    raise err.Error(errno.EADDRINUSE)
            else:
                raise err.Error(errno.EACCES)

    def _bind_by_name(self, socket, name):
        if not service_name_format.match(name):
            raise err.Error(errno.EFAULT)

        with self.lock:
            if self.snl.get(name) is not None:
                raise err.Error(errno.EADDRINUSE)
            addr = wks_map.get(name)
            if addr is None:
                try:
                    addr = 16 + self.sap[16:32].index(None)
                except ValueError:
                    raise err.Error(errno.EADDRNOTAVAIL)
            socket.bind(addr)
            self.sap[addr] = ServiceAccessPoint(addr, self)
            self.sap[addr].insert_socket(socket)
            self.snl[name] = addr

    def connect(self, socket, dest):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if not socket.is_bound:
            self.bind(socket)
        socket.connect(dest)
        log.debug("connected ({0} ===> {1})".format(socket.addr, socket.peer))
        if socket.send_miu > self.cfg['send-miu']:
            log.warning("reducing outbound miu to not exceed the link miu")
            socket.send_miu = self.cfg['send-miu']

    def listen(self, socket, backlog):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if not isinstance(socket, tco.DataLinkConnection):
            raise err.Error(errno.EOPNOTSUPP)
        if not isinstance(backlog, int):
            raise TypeError("backlog must be int type")
        if backlog < 0:
            raise ValueError("backlog can not be negative")
        backlog = min(backlog, 16)
        if not socket.is_bound:
            self.bind(socket)
        socket.listen(backlog)

    def accept(self, socket):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if not isinstance(socket, tco.DataLinkConnection):
            raise err.Error(errno.EOPNOTSUPP)
        while True:
            client = socket.accept()
            self.sap[client.addr].insert_socket(client)
            log.debug("new data link connection ({0} <=== {1})"
                      .format(client.addr, client.peer))
            if client.send_miu > self.cfg['send-miu']:
                log.warning("reducing outbound miu to comply with link miu")
                client.send_miu = self.cfg['send-miu']
            return client

    def send(self, socket, message, flags):
        return self.sendto(socket, message, socket.peer, flags)

    def sendto(self, socket, message, dest, flags):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if isinstance(socket, tco.RawAccessPoint):
            if not isinstance(message, pdu.ProtocolDataUnit):
                raise TypeError("on a raw access point message must be a pdu")
            if not socket.is_bound:
                self.bind(socket)
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
            return socket.send(message, flags)
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message data must be a bytes-like object")
        if isinstance(socket, tco.LogicalDataLink):
            if dest is None:
                raise err.Error(errno.EDESTADDRREQ)
            if not socket.is_bound:
                self.bind(socket)
            # FIXME: set socket send miu when activated
            socket.send_miu = self.cfg['send-miu']
            return socket.sendto(message, dest, flags)
        if isinstance(socket, tco.DataLinkConnection):
            return socket.send(message, flags)

    def recv(self, socket):
        message, sender = self.recvfrom(socket)
        return message

    def recvfrom(self, socket):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if not (socket.addr and self.sap[socket.addr]):
            raise err.Error(errno.EBADF)
        if isinstance(socket, tco.RawAccessPoint):
            return (socket.recv(), None)
        if isinstance(socket, tco.LogicalDataLink):
            return socket.recvfrom()
        if isinstance(socket, tco.DataLinkConnection):
            return (socket.recv(), socket.peer)

    def poll(self, socket, event, timeout=None):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if not (socket.addr and self.sap[socket.addr]):
            raise err.Error(errno.EBADF)
        return socket.poll(event, timeout)

    def close(self, socket):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        if socket.is_bound:
            self.sap[socket.addr].remove_socket(socket)
        else:
            socket.close()

    def getsockname(self, socket):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        return socket.addr

    def getpeername(self, socket):
        if not isinstance(socket, tco.TransmissionControlObject):
            raise err.Error(errno.ENOTSOCK)
        return socket.peer
