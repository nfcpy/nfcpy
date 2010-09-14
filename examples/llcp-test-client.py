#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
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
log = logging.getLogger()

import os
import sys
import time
from threading import Thread
from collections import namedtuple

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.llcp

default_miu = 128

class TestError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return str(self.value)

def info(message, prefix="   "):
    log.info(prefix + message)

def test_01():
    info("Test 1: link activation, symmetry and deactivation", prefix="")
    time.sleep(5)
    return

def test_02():
    TestData = namedtuple("TestData", "send recv")

    def send_and_receive(socket, send_count, packet_length):
        test_data = TestData(send=[], recv=[])
        cl_server = nfc.llcp.getpeername(socket)
        for i in range(1, send_count + 1):
            data, addr = packet_length * chr(i), cl_server
            nfc.llcp.sendto(socket, data, addr)
            info("sent message {0}".format(i))
            test_data.send.append((data, addr, time.time()))
            time.sleep(0.5)
        while nfc.llcp.poll(socket, "recv", timeout=5):
            data, addr = nfc.llcp.recvfrom(socket)
            test_data.recv.append((data, addr, time.time()))
        if len(test_data.recv) == 0:
            raise TestError("did not receive any data within 5 seconds")
        return test_data

    def run_step_1(socket):
        info("step 1: send one default size datagram", prefix="")
        test_data = send_and_receive(socket, 1, default_miu)
        if not len(test_data.recv) == len(test_data.send):
            raise TestError("received wrong number of datagrams")
        for i in range(len(test_data.recv)):
            send_data, send_addr, send_time = test_data.send[i]
            recv_data, recv_addr, recv_time = test_data.recv[i]
            if recv_addr != send_addr:
                raise TestError("received data from different port")
            if recv_data != send_data:
                raise TestError("received data does not match sent data")
            info("rcvd message {0} after {1} ms"
                     .format(i+1, int((recv_time - send_time) * 1000)))
        return True

    def run_step_2(socket):
        info("step 2: send two default size datagrams", prefix="")
        test_data = send_and_receive(socket, 2, default_miu)
        if not len(test_data.recv) == len(test_data.send):
            raise TestError("received wrong number of datagrams")
        for i in range(len(test_data.recv)):
            send_data, send_addr, send_time = test_data.send[i]
            recv_data, recv_addr, recv_time = test_data.recv[i]
            if recv_addr != send_addr:
                raise TestError("received data from different port")
            if recv_data != send_data:
                raise TestError("received data does not match sent data")
            info("rcvd message {0} after {1} ms"
                     .format(i+1, int((recv_time - send_time) * 1000)))
        return True

    def run_step_3(socket):
        info("step 3: send three default size datagrams", prefix="")
        test_data = send_and_receive(socket, 3, default_miu)
        if not len(test_data.recv) == len(test_data.send) - 1:
            raise TestError("received wrong number of datagrams")
        for i in range(len(test_data.recv)):
            send_data, send_addr, send_time = test_data.send[i]
            recv_data, recv_addr, recv_time = test_data.recv[i]
            if recv_addr != send_addr:
                raise TestError("received data from different port")
            if recv_data != send_data:
                raise TestError("received data does not match sent data")
            info("rcvd message {0} after {1} ms"
                     .format(i+1, int((recv_time - send_time) * 1000)))
        return True

    def run_step_4(socket):
        info("step 4: send one zero-length datagram", prefix="")
        test_data = send_and_receive(socket, 1, packet_length=0)
        if not len(test_data.recv) == len(test_data.send):
            raise TestError("received wrong number of datagrams")
        for i in range(len(test_data.recv)):
            send_data, send_addr, send_time = test_data.send[i]
            recv_data, recv_addr, recv_time = test_data.recv[i]
            if recv_addr != send_addr:
                raise TestError("received data from different port")
            if recv_data != send_data:
                raise TestError("received data does not match sent data")
            info("rcvd message {0} after {1} ms"
                     .format(i+1, int((recv_time - send_time) * 1000)))
        return True

    def run_step_5(socket):
        info("step 5: send one maximum length packet", prefix="")
        miu = nfc.llcp.getsockopt(socket, nfc.llcp.SO_SNDMIU)
        test_data = send_and_receive(socket, 1, packet_length=miu)
        if not len(test_data.recv) == len(test_data.send):
            raise TestError("received wrong number of datagrams")
        for i in range(len(test_data.recv)):
            send_data, send_addr, send_time = test_data.send[i]
            recv_data, recv_addr, recv_time = test_data.recv[i]
            if recv_addr != send_addr:
                raise TestError("received data from different port")
            if recv_data != send_data:
                raise TestError("received data does not match sent data")
            info("rcvd message {0} after {1} ms"
                     .format(i+1, int((recv_time - send_time) * 1000)))
        return True

    info("Test 2: connection-less information transfer", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.LOGICAL_DATA_LINK)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 10)
    if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 10:
        info("socket recv buffer set to 10")
    else: raise TestError("could not set the socket recv buffer")
    cl_echo_server = nfc.llcp.resolve("urn:nfc:sn:cl-echo")
    if not cl_echo_server:
        raise TestError("no connection-less echo server on peer device")
    info("connection-less echo server on sap {0}".format(cl_echo_server))
    nfc.llcp.connect(socket, cl_echo_server)
    try:
        if run_step_1(socket): info("PASS", prefix="")
        if run_step_2(socket): info("PASS", prefix="")
        if run_step_3(socket): info("PASS", prefix="")
        if run_step_4(socket): info("PASS", prefix="")
        if run_step_5(socket): info("PASS", prefix="")
    finally:
        nfc.llcp.close(socket)
            
def test_03():
    info("Test 3: connection-oriented information transfer", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 2:
        info("socket recv window set 2")
    else: raise TestError("could not set the socket recv window")
    cm_echo_server = nfc.llcp.resolve("urn:nfc:sn:cm-echo")
    if not cm_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(cm_echo_server))
    nfc.llcp.connect(socket, cm_echo_server)
    peer_sap = nfc.llcp.getpeername(socket)
    info("connected with sap {0}".format(peer_sap))
    nfc.llcp.send(socket, default_miu * "\xFF")
    t0 = time.time()
    info("sent one information pdu")
    if nfc.llcp.poll(socket, "acks", timeout = 5):
        elapsed = time.time() - t0
        info("got confirm after {0:.3f}".format(elapsed))
        if not elapsed < 1.9:
            raise TestError("no confirmation within 1.9 seconds")
        nfc.llcp.recv(socket)
        elapsed = time.time() - t0
        info("got message after {0:.3f}".format(time.time() - t0))
        if not elapsed > 2.0:
            raise TestError("echo'd data received too early")
    else: raise TestError("no data received within 5 seconds")
    nfc.llcp.close(socket)

def test_04():
    sent_data = []
    rcvd_data = []

    def receiver(socket, rcvd_data):
        while nfc.llcp.poll(socket, "recv", timeout=5):
            data = nfc.llcp.recv(socket)
            if data: rcvd_data.append((data, time.time()))

    info("Test 4: send and receive sequence number handling", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 2:
        info("receive window set to 2")
    else: raise TestError("failed to set receive window to 2")
    cm_echo_server = nfc.llcp.resolve("urn:nfc:sn:cm-echo")
    if not cm_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(cm_echo_server))
    recv_thread = Thread(target=receiver, args=[socket, rcvd_data])
    try:
        nfc.llcp.connect(socket, cm_echo_server)
        peer_sap = nfc.llcp.getpeername(socket)
        info("connected with sap {0}".format(peer_sap))
        recv_thread.start()
        count = 20
        info("now sending {0} messages".format(count))
        for i in range(count):
            data = default_miu * chr(i)
            if nfc.llcp.send(socket, data):
                info("sent message {0}".format(i+1))
                sent_data.append((data, time.time()))
        recv_thread.join()
        for i in range(count):
            r = "correct" if rcvd_data[i][0] == rcvd_data[i][0] else "wrong"
            t = rcvd_data[i][1] - sent_data[i][1]
            info("message {i:2} received after {t:.3f} sec was {r}"
                     .format(i=i, t=t, r=r))
    finally:
        try: recv_thread.join()
        except RuntimeError: pass # wasn't started
        nfc.llcp.close(socket)

def test_05():
    info("Test 5: handling of receiver busy condition", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 0)
    if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 0:
        info("receive window set to 0")
    else: raise TestError("failed to set receive window to 0")
    cm_echo_server = nfc.llcp.resolve("urn:nfc:sn:cm-echo")
    if not cm_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(cm_echo_server))
    try:
        nfc.llcp.connect(socket, cm_echo_server)
        peer_sap = nfc.llcp.getpeername(socket)
        info("connected with sap {0}".format(peer_sap))
        info("now sending 4 messages")
        for i in range(4):
            data = default_miu * chr(i)
            if nfc.llcp.send(socket, data):
                info("sent message {0}".format(i+1))
        for i in range(4):
            time.sleep(1.0)
            if nfc.llcp.getsockopt(socket, nfc.llcp.SO_SNDBSY):
                info("connection-mode echo server entered busy state")
                break
        else:
            raise TestError("did not recognize server busy state")
    finally:
        nfc.llcp.close(socket)

def test_06():
    info("Test 6: rejection of connect request", prefix="")
    socket1 = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    socket2 = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    cm_echo_server = nfc.llcp.resolve("urn:nfc:sn:cm-echo")
    if not cm_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(cm_echo_server))
    try:
        nfc.llcp.connect(socket1, cm_echo_server)
        peer_sap = nfc.llcp.getpeername(socket1)
        info("first connection established with sap {0}".format(peer_sap))
        try: nfc.llcp.connect(socket2, cm_echo_server)
        except nfc.llcp.ConnectRefused as e:
            info("second connection rejected with reason {0}".format(e.reason))
        else: raise TestError("second connection not rejected")
        finally: nfc.llcp.close(socket2)
    finally:
        nfc.llcp.close(socket1)

def test_07():
    info("Test 7: connect by service name", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    try:
        nfc.llcp.connect(socket, "urn:nfc:sn:cm-echo")
        info("connected to service 'urn:nfc:sn:cm-echo'")
        peer_sap = nfc.llcp.getpeername(socket)
        info("connection established with sap {0}".format(peer_sap))
        if nfc.llcp.send(socket, "here's stephen"):
            t0 = time.time()
            info("sent test message")
            if nfc.llcp.poll(socket, "recv", timeout=5):
                if nfc.llcp.recv(socket) == "here's stephen":
                    info("got echo after {0:.3f} sec".format(time.time()-t0))
    finally:
        nfc.llcp.close(socket)

def test_08():
    import nfc.llcp.pdu
    info("Test 8: aggregation and disaggregation", prefix="")
    try:
        socket = nfc.llcp.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
        nfc.llcp.bind(socket, None)
        nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 10)
        if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) != 10:
            raise TestError("could not set the socket recv buffer")
        info("socket recv buffer set to 10")
        cl_echo_server = nfc.llcp.resolve("urn:nfc:sn:cl-echo")
        if not cl_echo_server:
            raise TestError("no connection-less echo server on peer device")
        info("connection-less echo server on sap {0}".format(cl_echo_server))
        addr = nfc.llcp.getsockname(socket)
        UI = nfc.llcp.pdu.UnnumberedInformation
        pdu1 = UI(cl_echo_server, addr, 50*"\x01")
        pdu2 = UI(cl_echo_server, addr, 50*"\x02")
        pdu3 = UI(cl_echo_server, addr, 50*"\x03")

        info("step 1: send two datagrams with 50 byte payload")
        agf = nfc.llcp.pdu.AggregatedFrame(aggregate=[pdu1, pdu2])
        nfc.llcp.send(socket, agf)
        if not nfc.llcp.poll(socket, "recv", timeout=5):
            raise TestError("did not receive first message within 5 sec")
        if not nfc.llcp.recv(socket).sdu == 50*"\x01":
            raise TestError("first message came back wrong")
        info("received first message")
        if not nfc.llcp.poll(socket, "recv", timeout=5):
            raise TestError("did not receive second message within 5 sec")
        if not nfc.llcp.recv(socket).sdu == 50*"\x02":
            raise TestError("second message came back wrong")
        info("received second message")

        info("step2: send three datagrams with 50 byte payload")
        agf = nfc.llcp.pdu.AggregatedFrame(aggregate=[pdu1, pdu2, pdu3])
        nfc.llcp.send(socket, agf)
        if not nfc.llcp.poll(socket, "recv", timeout=5):
            raise TestError("did not receive first message within 5 sec")
        if not nfc.llcp.recv(socket).sdu == 50*"\x01":
            raise TestError("first message came back wrong")
        info("received first message")
        if not nfc.llcp.poll(socket, "recv", timeout=5):
            raise TestError("did not receive second message within 5 sec")
        if not nfc.llcp.recv(socket).sdu == 50*"\x02":
            raise TestError("second message came back wrong")
        info("received second message")
        if nfc.llcp.poll(socket, "recv", timeout=5):
            raise TestError("received third message")
        info("did not receive third message within 5 sec")
    finally:
        nfc.llcp.close(socket)

def test_09():
    info("Test 9: service name lookup", prefix="")
    sdp_addr = nfc.llcp.resolve("urn:nfc:sn:sdp")
    if not sdp_addr:
        raise TestError("no answer for 'urn:nfc:sn:sdp' lookup")
    info("resolved 'urn:nfc:sn:sdp' to sap {0}".format(sdp_addr))

def test_10():
    import nfc.llcp.pdu
    info("Test 10: exceed the maximum information unit size", prefix="")
    cm_echo_server = nfc.llcp.resolve("urn:nfc:sn:cm-echo")
    if not cm_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(cm_echo_server))
    dlc_socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    raw_socket = nfc.llcp.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
    try:
        nfc.llcp.connect(dlc_socket, cm_echo_server)
        addr = nfc.llcp.getsockname(dlc_socket)
        peer = nfc.llcp.getpeername(dlc_socket)
        info("connected with sap {0}".format(peer))
        send_miu = nfc.llcp.getsockopt(dlc_socket, nfc.llcp.SO_SNDMIU)
        info("the peers receive MIU is {0} octets".format(send_miu))
        sdu = (send_miu + 1) * '\x00'
        pdu = nfc.llcp.pdu.Information(dsap=peer, ssap=addr, sdu=sdu)
        pdu.ns, pdu.nr = 0, 0
        nfc.llcp.send(raw_socket, pdu)
        nfc.llcp.recv(dlc_socket)
    except nfc.llcp.Error as e:
        info(str(e))
    finally:
        nfc.llcp.close(dlc_socket)
        nfc.llcp.close(raw_socket)

def test_11():
    import nfc.llcp.pdu
    info("Test 11: generate invalid send sequence number", prefix="")
    cm_echo_server = nfc.llcp.resolve("urn:nfc:sn:cm-echo")
    if not cm_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(cm_echo_server))
    dlc_socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    raw_socket = nfc.llcp.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
    try:
        nfc.llcp.connect(dlc_socket, cm_echo_server)
        addr = nfc.llcp.getsockname(dlc_socket)
        peer = nfc.llcp.getpeername(dlc_socket)
        info("connected with sap {0}".format(peer))
        pdu = nfc.llcp.pdu.Information(dsap=peer, ssap=addr, sdu="wrong N(S)")
        pdu.ns, pdu.nr = 15, 0
        nfc.llcp.send(raw_socket, pdu)
        nfc.llcp.recv(dlc_socket)
    except nfc.llcp.Error as e:
        info(str(e))
    finally:
        nfc.llcp.close(dlc_socket)
        nfc.llcp.close(raw_socket)


def main(options):
    general_bytes = nfc.llcp.startup(lto=1000, miu=1024)
    clf = nfc.ContactlessFrontend()

    peer = None
    while True:
        listen_time = 250 + ord(os.urandom(1))
        peer = clf.listen(listen_time, general_bytes)
        if isinstance(peer, nfc.DEP):
            if peer.general_bytes.startswith("Ffm"):
                break
        peer = clf.poll(general_bytes)
        if isinstance(peer, nfc.DEP):
            if peer.general_bytes.startswith("Ffm"):
                break

    nfc.llcp.activate(peer)
    time.sleep(0.5)
    
    if not options.run_test:
        log.info("no test specified")

    test_suite = [test_01, test_02, test_03, test_04, test_05,
                  test_06, test_07, test_08, test_09, test_10,
                  test_11]
    try:
        for test in options.run_test:
            if test > 0 and test <= len(test_suite):
                try:
                    test_suite[test-1]()
                    log.info("PASS")
                except TestError as error:
                    log.error("FAIL: {0}".format(error))
            else: log.info("invalid test number '{0}'".format(test))
    except KeyboardInterrupt:
        log.info("aborted by user")
        for thread in threading.enumerate():
            log.info(thread.name)
    finally:
        nfc.llcp.shutdown()


if __name__ == '__main__':
    import sys
    from optparse import OptionParser, OptionGroup
    parser = OptionParser()
    parser.add_option("-t", action="append", dest="run_test", default=[],
                      help="run test number <INT>", metavar="INT")
    parser.add_option("-q", action="store_false", dest="verbose", default=True,
                      help="do only print errors to console")
    parser.add_option("-d", action="append", dest="debug", default=[],
                      metavar="MODULE", help="print debug messages for module")
    parser.add_option("-f", action="store", type="string", dest="logfile",
                      help="write log messages to LOGFILE")
    options, args = parser.parse_args()
    print options

    verbosity = logging.INFO if options.verbose else logging.ERROR
    logging.basicConfig(level=verbosity, format='%(message)s')

    if options.logfile:
        logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(options.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    if options.debug:
        logging.getLogger('').setLevel(logging.DEBUG)
        logging.getLogger('nfc').setLevel(logging.DEBUG)
        logging.getLogger('nfc.dev').setLevel(logging.INFO)
        if "llcp" in options.debug:
            logging.getLogger('nfc.llcp').setLevel(logging.DEBUG)
        else: log.warning("unrecognized debug target '{0}'".format(name))

    try: options.run_test = [int(t) for t in options.run_test]
    except ValueError: log.error("non-integer test number"); sys.exit(-1)

    main(options)
