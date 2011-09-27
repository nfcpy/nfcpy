#!/usr/bin/python
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
#
# Client side implementation of an LLCP validation suite to verify
# inter-operability of independent implementations. This suite was
# primarily developed for the purpose of validating the LLCP
# specification before final release by the NFC Forum.
#
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
    """Link activation, symmetry and deactivation

    Verify that the LLCP Link can be activated successfully, that the
    symmetry procedure is performed and the link can be intentionally
    deactivated.

    1. Start the MAC link activation procedure on two implementations
       and verify that the version number parameter is received and
       version number agreement is achieved.

    2. Verify for a duration of 5 seconds that SYMM PDUs are exchanged
       within the Link Timout values provided by the implementations.

    3. Perform intentional link deactivation by sending a DISC PDU to
       the remote Link Management component. Verify that SYMM PDUs
       are no longer exchanged.
    """
    info("Test 1: link activation, symmetry and deactivation", prefix="")
    time.sleep(5)
    return

def test_02():
    """Connection-less information transfer

    Verify that the source and destination access point address fields
    are correctly interpreted, the content of the information field is
    extracted as the service data unit and the service data unit can
    take any length between zero and the announced Link MIU. The LLCP
    Link must be activated prior to running this scenario and the Link
    MIU of the peer implementation must have been determined. In this
    scenario, sending of a service data unit (SDU) means that the SDU
    is carried within the information field of a UI PDU.

    1. Send a service data unit of 128 octets length to the
       connection-less mode echo service and verify that the same SDU
       is sent back after the echo delay time.

    2. Send within echo delay time with a time interval of at least
       0.5 second two consecutive service data units of 128 octets
       length to the connection-less mode echo service and verify that
       both SDUs are sent back correctly.

    3. Send within echo delay time with a time interval of at least
       0.5 second three consecutive service data units of 128 octets
       length to the connection-less mode echo service and verify that
       the first two SDUs are sent back correctly and the third SDU is
       discarded.

    4. Send a service data unit of zero octets length to the
       connection-less mode echo service and verify that the same zero
       length SDU is sent back after the echo delay time.

    5. Send a service data unit of maximum octets length to the
       connection-less mode echo service and verify that the same SDU
       is sent back after the echo delay time. Note that the maximum
       length here must be the smaller value of both implementations
       Link MIU.
    """
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
    cl_echo_server = options.cl_echo_sap
    if not cl_echo_server:
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
    """Connection-oriented information transfer

    Verify that a data link connection can be established, a service
    data unit is received and sent back correctly and the data link
    connection can be terminated. The LLCP Link must be activated
    prior to running this scenario and the connection-oriented mode
    echo service must be in the unconnected state.  In this scenario,
    sending of a service data unit (SDU) means that the SDU is carried
    within the information field of an I PDU.

    1. Send a CONNECT PDU to the connection-oriented mode echo service
       and verify that the connection request is acknowledged with a
       CC PDU. The CONNECT PDU shall encode the RW parameter with a
       value of 2. Verify that the CC PDU encodes the RW parameter
       with a value of 2 (as specified for the echo server).

    2. Send a single service data unit of 128 octets length over the
       data link connection and verify that the echo service sends an
       RR PDU before returning the same SDU after the echo delay time.

    3. Send a DISC PDU to terminate the data link connection and
       verify that the echo service responds with a correct DM PDU.
    """
    info("Test 3: connection-oriented information transfer", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 2:
        info("socket recv window set 2")
    else: raise TestError("could not set the socket recv window")
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    nfc.llcp.connect(socket, co_echo_server)
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
    """Send and receive sequence number handling

    Verify that a sequence of service data units that causes the send
    and receive sequence numbers to take all possible values is
    received and sent back correctly. The LLCP Link must be activated
    prior to running this scenario and the connection-oriented mode
    echo service must be in the unconnected state. In this scenario,
    sending of a service data unit (SDU) means that the SDU is carried
    within the information field of an I PDU.

    1. Send a CONNECT PDU to the connection-oriented mode echo service
       and verify that the connection request is acknowledged with a
       CC PDU. The CONNECT PDU shall encode the RW parameter with a
       value of 2. Verify that the CC PDU encodes the RW parameter
       with a value of 2 (as specified for the echo server).

    2. Send a sequence of at least 16 data units of each 128 octets
       length over the data link connection and verify that all SDUs
       are sent back correctly.

    3. Send a DISC PDU to terminate the data link connection and
       verify that the echo service responds with a correct DM PDU.
    """
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
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    recv_thread = Thread(target=receiver, args=[socket, rcvd_data])
    try:
        nfc.llcp.connect(socket, co_echo_server)
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
    """Handling of receiver busy condition

    Verify the handling of a busy condition. The LLCP Link must be
    activated prior to running this scenario and the
    connection-oriented mode echo service must be in the unconnected
    state.  In this scenario, sending of a service data unit (SDU)
    shall mean that the SDU is carried within the information field of
    an I PDU.

    1. Send a CONNECT PDU to the connection-oriented mode echo service
       and verify that the connect request is acknowledged with a CC
       PDU. The CONNECT PDU shall encode the RW parameter with a value
       of 0. Verify that the CC PDU encodes the RW parameter with a
       value of 2 (as specified for the echo server).

    2. Send four service data units of 128 octets length over the data
       link connection and verify that the echo service enters the
       busy state when acknowledging the last packet.

    3. Send a DISC PDU to terminate the data link connection and
       verify that the echo service responds with a correct DM PDU.
    """
    info("Test 5: handling of receiver busy condition", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 0)
    if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 0:
        info("receive window set to 0")
    else: raise TestError("failed to set receive window to 0")
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    try:
        nfc.llcp.connect(socket, co_echo_server)
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
    """Rejection of connect request

    Verify that an attempt to establish a second connection with the
    connection-oriented mode echo service is rejected. The LLCP Link
    must be activated prior to running this scenario.

    1. Send a first CONNECT PDU to the connection-oriented mode echo
       service and verify that the connect request is acknowledged
       with a CC PDU.

    2. Send a second CONNECT PDU to the connection-oriented mode echo
       service and verify that the connect request is rejected with a
       DM PDU and appropriate reason code.

    3. Send a service data unit of 128 octets length over the data
       link connection and verify that the echo service returns the
       same SDU after the echo delay time.

    4. Send a DISC PDU to terminate the data link connection and
       verify that the echo service responds with a correct DM PDU.

    """
    info("Test 6: rejection of connect request", prefix="")
    socket1 = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    socket2 = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    try:
        nfc.llcp.connect(socket1, co_echo_server)
        peer_sap = nfc.llcp.getpeername(socket1)
        info("first connection established with sap {0}".format(peer_sap))
        try: nfc.llcp.connect(socket2, co_echo_server)
        except nfc.llcp.ConnectRefused as e:
            info("second connection rejected with reason {0}".format(e.reason))
        else: raise TestError("second connection not rejected")
        finally: nfc.llcp.close(socket2)
    finally:
        nfc.llcp.close(socket1)

def test_07():
    """Connect by service name

    Verify that a data link connection can be established by
    specifying a service name. The LLCP Link must be activated prior
    to running this scenario and the connection-oriented mode echo
    service must be in the unconnected state.

    1. Send a CONNECT PDU with an SN parameter that encodes the value
       "urn:nfc:sn:co-echo" to the service discovery service access
       point address and verify that the connect request is
       acknowledged with a CC PDU.

    2. Send a service data unit over the data link connection and
       verify that it is sent back correctly.

    3. Send a DISC PDU to terminate the data link connection and
       verify that the echo service responds with a correct DM PDU.
    """
    info("Test 7: connect by service name", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    try:
        nfc.llcp.connect(socket, "urn:nfc:sn:co-echo")
        info("connected to service 'urn:nfc:sn:co-echo'")
        peer_sap = nfc.llcp.getpeername(socket)
        if peer_sap == 1:
            raise TestError("connection established with SDP port")
        info("connection established with sap {0}".format(peer_sap))
        if nfc.llcp.send(socket, "here's nfcpy"):
            t0 = time.time()
            info("sent test message")
            if nfc.llcp.poll(socket, "recv", timeout=5):
                if nfc.llcp.recv(socket) == "here's nfcpy":
                    info("got echo after {0:.3f} sec".format(time.time()-t0))
                else: raise TestError("received wrong data from echo server")
            else: raise TestError("no echo response within 5 seconds")
        else: raise TestError("failed to send data")
    finally:
        nfc.llcp.close(socket)
    try:
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        nfc.llcp.connect(socket, "urn:nfc:sn:co-echo-test")
        raise TestError("connect 'co-echo-test' rejected")
    except nfc.llcp.ConnectRefused as e:
        info("connect 'co-echo-test' rejected with reason {0}".format(e.reason))
    finally:
        nfc.llcp.close(socket)

def test_08():
    """Aggregation and disaggregation

    Verify that the aggregation procedure is performed correctly. The
    LLCP Link must be activated prior to running this scenario.  In
    this scenario, sending of a service data unit (SDU) shall mean
    that the SDU is carried within the information field of a UI PDU.

    1. Send two service data units of 50 octets length to the
       connection-less mode echo service such that the two resulting
       UI PDUs will be aggregated into a single AGF PDU by the LLC
       sublayer. Verify that both SDUs are sent back correctly and in
       the same order.

    2. Send three service data units of 50 octets length to the
       connection-less mode echo service such that the three resulting
       UI PDUs will be aggregated into a single AGF PDU by the LLC
       sublayer. Verify that the two first SDUs are sent back
       correctly and the third SDU is discarded.
    """
    import nfc.llcp.pdu
    info("Test 8: aggregation and disaggregation", prefix="")
    try:
        socket = nfc.llcp.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
        nfc.llcp.bind(socket, None)
        nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 10)
        if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) != 10:
            raise TestError("could not set the socket recv buffer")
        info("socket recv buffer set to 10")
        cl_echo_server = options.cl_echo_sap
        if not cl_echo_server:
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
    """Service name lookup

    Verify that a service name is correctly resolved into a service
    access point address by the remote LLC. The LLCP Link must be
    activated prior to running this scenario.  In this scenario,
    sending of a service data unit (SDU) shall mean that the SDU is
    carried within the information field of a UI PDU.

    1. Send an SNL PDU with an SDREQ parameter in the information
       field that encodes the value "urn:nfc:sn:sdp" to the service
       discovery service access point address and verify that the
       request is responded with an SNL PDU that contains an SDRES
       parameter with the SAP value '1' and a TID value that is the
       same as the value encoded in the antecedently transmitted SDREQ
       parameter.

    2. Send an SNL PDU with an SDREQ parameter in the information
       field that encodes the value "urn:nfc:sn:cl-echo" to the
       service discovery service access point address and verify that
       the request is responded with an SNL PDU that contains an SDRES
       parameter with a SAP value other than '0' and a TID value that
       is the same as the value encoded in the antecedently
       transmitted SDREQ parameter.

    3. Send a service data unit of 128 octets length to the service
       access point address received in step 2 and verify that the
       same SDU is sent back after the echo delay time.

    4. Send an SNL PDU with an SDREQ parameter in the information
       field that encodes the value "urn:nfc:sn:sdp-test" to the
       service discovery service access point address and verify that
       the request is responded with an SNL PDU that contains an SDRES
       parameter with the SAP value '0' and a TID value that is the
       same as the value encoded in the antecedently transmitted SDREQ
       parameter.
    """
    info("Test 9: service name lookup", prefix="")
    addr = nfc.llcp.resolve("urn:nfc:sn:sdp")
    if not addr:
        raise TestError("no answer for 'urn:nfc:sn:sdp' lookup")
    info("step 1: resolved 'urn:nfc:sn:sdp' to sap {0}".format(addr))
    addr = nfc.llcp.resolve("urn:nfc:sn:cl-echo")
    if not addr:
        raise TestError("no answer for 'urn:nfc:sn:cl-echo' lookup")
    info("step 2: resolved 'urn:nfc:sn:cl-echo' to sap {0}".format(addr))
    socket = nfc.llcp.socket(nfc.llcp.LOGICAL_DATA_LINK)
    t0 = time.time()
    if nfc.llcp.sendto(socket, 128 * "\xA9", addr):
        info("step 3: sent 128 byte message to sap {0}".format(addr))
        if not nfc.llcp.poll(socket, "recv", timeout=5):
            raise TestError("did not receive echo within 5 seconds")
        data, peer = nfc.llcp.recvfrom(socket)
        if not data == 128 * "\xA9":
            raise TestError("received wrong data in step 3")
        if not peer == addr:
            raise TestError("received from wrong sap in step 3")
        t1 = time.time()
        info("step 3: received echo after {0:.3} seconds".format(t1-t0))
    addr = nfc.llcp.resolve("urn:nfc:sn:sdp-test")
    if not addr == 0:
        raise TestError("'urn:nfc:sn:sdp-test' did not yield 0")
    info("step 4: resolved 'urn:nfc:sn:sdp-test' as {0}".format(addr))

def test_10():
    import nfc.llcp.pdu
    info("Test 10: exceed the maximum information unit size", prefix="")
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    dlc_socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    raw_socket = nfc.llcp.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
    try:
        nfc.llcp.connect(dlc_socket, co_echo_server)
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
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    dlc_socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    raw_socket = nfc.llcp.socket(nfc.llcp.llc.RAW_ACCESS_POINT)
    try:
        nfc.llcp.connect(dlc_socket, co_echo_server)
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

def test_12():
    info("Test 12: maximum data size on data link connection", prefix="")
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 2:
        info("socket recv window set 2")
    else: raise TestError("could not set the socket recv window")
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVMIU, 300)
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    nfc.llcp.connect(socket, co_echo_server)
    peer_sap = nfc.llcp.getpeername(socket)
    info("connected with sap {0}".format(peer_sap))
    miu = nfc.llcp.getsockopt(socket, nfc.llcp.SO_SNDMIU)
    nfc.llcp.send(socket, miu * "\xFF")
    t0 = time.time()
    info("sent one information pdu")
    if nfc.llcp.poll(socket, "acks", timeout = 5):
        elapsed = time.time() - t0
        info("got confirm after {0:.3f}".format(elapsed))
        if not elapsed < 1.9:
            raise TestError("no confirmation within 1.9 seconds")
        if not nfc.llcp.poll(socket, "recv", timeout=5):
            raise TestError("did not receive second message within 5 sec")
        data = nfc.llcp.recv(socket)
        info("got message after {0:.3f}".format(time.time() - t0))
    else: raise TestError("no data received within 5 seconds")
    nfc.llcp.close(socket)

def test_13():
    info("Test 13: DLC connect - release - connect", prefix="")
    socket1 = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    socket2 = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = nfc.llcp.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestError("no connection-mode echo server on peer device")
    info("connection-mode echo server on sap {0}".format(co_echo_server))
    try:
        nfc.llcp.connect(socket1, co_echo_server)
        peer_sap = nfc.llcp.getpeername(socket1)
        info("first connection established with sap {0}".format(peer_sap))
        nfc.llcp.send(socket1, "I'm the first connection")
        assert(nfc.llcp.recv(socket1) == "I'm the first connection")
        nfc.llcp.close(socket1)
        info("first connection terminated")
        nfc.llcp.connect(socket2, co_echo_server)
        peer_sap = nfc.llcp.getpeername(socket2)
        info("second connection established with sap {0}".format(peer_sap))
        nfc.llcp.send(socket2, "I'm the second connection")
        assert(nfc.llcp.recv(socket2) == "I'm the second connection")
        nfc.llcp.close(socket2)
    finally:
        pass


def main():
    llcp_config = {'recv-miu': options.link_miu, 'send-lto': 500}
    if options.quirks == "android":
        llcp_config['send-agf'] = False

    general_bytes = nfc.llcp.startup(llcp_config)
    for device in options.device:
        try: clf = nfc.ContactlessFrontend(device); break
        except LookupError: pass
    else: return

    peer = None
    try:
        while True:
            if options.mode == "target" or options.mode is None:
                listen_time = 250 + ord(os.urandom(1))
                peer = clf.listen(listen_time, general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        break
            if options.mode == "initiator" or options.mode is None:
                peer = clf.poll(general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        if options.quirks == "android":
                            # Google Nexus S does not receive the first
                            # packet if we send immediately.
                            time.sleep(0.1)
                        break
    except KeyboardInterrupt:
        log.info("aborted by user")
        clf.close()
        return

    nfc.llcp.activate(peer)
    time.sleep(0.5)
    
    if not options.run_test:
        log.info("no test specified")

    test_suite = [test_01, test_02, test_03, test_04, test_05,
                  test_06, test_07, test_08, test_09, test_10,
                  test_11, test_12, test_13]
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
        clf.close()
        log.info("I was the " + peer.role)


if __name__ == '__main__':
    from optparse import OptionParser, OptionGroup
    parser = OptionParser()
    parser.add_option("-t", "--test", type="int", default=[],
                      action="append", dest="run_test", metavar="N",
                      help="run test number <N>")
    parser.add_option("-q", default=True,
                      action="store_false", dest="verbose",
                      help="be quiet, only print errors")
    parser.add_option("-d", type="string", default=[],
                      action="append", dest="debug", metavar="MODULE",
                      help="print debug messages for MODULE")
    parser.add_option("-f", type="string",
                      action="store", dest="logfile",
                      help="write log messages to LOGFILE")
    parser.add_option("--device", type="string", default=[],
                      action="append", dest="device", metavar="SPEC",
                      help="use only device(s) according to SPEC: "\
                          "usb[:vendor[:product]] (vendor and product in hex) "\
                          "usb[:bus[:dev]] (bus and device number in decimal) "\
                          "tty[:(usb|com)[:port]] (usb virtual or com port)")
    parser.add_option("--mode", type="choice", default=None,
                      choices=["target", "initiator"],
                      action="store", dest="mode",
                      help="restrict mode to 'target' or 'initiator'")
    parser.add_option("--cl-echo", type="int", default=None,
                      action="store", dest="cl_echo_sap", metavar="SAP",
                      help="connection-less echo server address")
    parser.add_option("--co-echo", type="int", default=None,
                      action="store", dest="co_echo_sap", metavar="SAP",
                      help="connection-oriented echo server address")
    parser.add_option("--link-miu", type="int", default=1024,
                      action="store", dest="link_miu", metavar="MIU",
                      help="set maximum information unit size to MIU")
    parser.add_option("--quirks", type="string",
                      action="store", dest="quirks", metavar="choice",
                      help="quirks mode, choices are 'android'")

    global options
    options, args = parser.parse_args()

    verbosity = logging.INFO if options.verbose else logging.ERROR
    logging.basicConfig(level=verbosity, format='%(message)s')

    if options.logfile:
        logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(options.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    import inspect, os, os.path
    nfcpy_path = os.path.dirname(inspect.getfile(nfc))
    for name in os.listdir(nfcpy_path):
        if os.path.isdir(os.path.join(nfcpy_path, name)):
            logging.getLogger("nfc."+name).setLevel(verbosity)
        elif name.endswith(".py") and name != "__init__.py":
            logging.getLogger("nfc."+name[:-3]).setLevel(verbosity)
            
    if options.debug:
        logging.getLogger('').setLevel(logging.DEBUG)
        logging.getLogger('nfc').setLevel(logging.DEBUG)
        for module in options.debug:
            log.info("enable debug output for module '{0}'".format(module))
            logging.getLogger(module).setLevel(logging.DEBUG)

    try: options.run_test = [int(t) for t in options.run_test]
    except ValueError: log.error("non-integer test number"); sys.exit(-1)

    if len(options.device) == 0:
        # search and use first
        options.device = ["",]
        
    main()
