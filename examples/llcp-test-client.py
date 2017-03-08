#!/usr/bin/env python
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
#
# Client side implementation of an LLCP validation suite to verify
# inter-operability of independent implementations. This suite was
# primarily developed for the purpose of validating the LLCP
# specification before final release by the NFC Forum.
#
import logging
log = logging.getLogger('main')

import os
import time
import errno
import datetime
import argparse
import itertools
import collections
from threading import Thread

from cli import CommandLineInterface, TestFail, TestSkip

import nfc
import nfc.llcp
import nfc.llcp.pdu

default_miu = 128

def info(message, *args, **kwargs):
    log.info("  " + message, *args, **kwargs)

description = """
Execute some Logical Link Control Protocol (LLCP) tests. The peer
device must have the LLCP validation test servers running.
"""

def get_connection_less_echo_server_sap(llc, options):
    cl_echo_server = options.cl_echo_sap
    if not cl_echo_server:
        cl_echo_server = llc.resolve("urn:nfc:sn:cl-echo")
    if not cl_echo_server:
        raise TestFail("no connection-less echo server on peer device")
    info("connection-less echo server on sap {0}".format(cl_echo_server))
    return cl_echo_server

def get_connection_mode_echo_server_sap(llc, options):
    co_echo_server = options.co_echo_sap
    if not co_echo_server:
        co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
    if not co_echo_server:
        raise TestFail("no connection-mode echo server on peer device")
    info("connection-mode echo server addr is {0}".format(co_echo_server))
    return co_echo_server

def get_data_link_connection(socket, dsap, ssap, miu, rw, sn=None):
    try:
        socket.bind(ssap)
        pdu = nfc.llcp.pdu.Connect(dsap, ssap, miu, rw, sn)
        socket.send(pdu)
        if not socket.poll("recv", timeout=5):
            raise TestFail("no response to connect within 5 seconds")
        pdu = socket.recv()
        if not pdu.name == "CC":
            raise TestFail("expected CC PDU not {0}".format(pdu.name))
        info("connected with SAP {0}".format(pdu.ssap))
        return pdu
    except nfc.llcp.Error as error:
        socket.close()
        raise TestFail(str(error))

class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]...',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=description)
        parser.add_argument(
            "--cl-echo", type=int, dest="cl_echo_sap", metavar="SAP",
            help="connection-less echo server address")
        parser.add_argument(
            "--co-echo", type=int, dest="co_echo_sap", metavar="SAP",
            help="connection-oriented echo server address")
        super(TestProgram, self).__init__(
            parser, groups="test llcp dbg clf")

    def on_llcp_startup(self, llc):
        self.on_llc_exchange_call = None
        self.on_llc_exchange_exit = None
        self.wrapped_llc_exchange = llc.exchange
        llc.exchange = self.llc_exchange_wrapper
        return super(TestProgram, self).on_llcp_startup(llc)

    def llc_exchange_wrapper(self, send_pdu, timeout):
        if self.on_llc_exchange_call:
            send_pdu = self.on_llc_exchange_call(send_pdu, timeout)
        rcvd_pdu = self.wrapped_llc_exchange(send_pdu, timeout)
        if self.on_llc_exchange_exit:
            rcvd_pdu = self.on_llc_exchange_exit(rcvd_pdu)
        return rcvd_pdu
        
    def test_01(self, llc):
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
        try:
            for i in range(1, 6):
                time.sleep(1)
                assert llc.link.ESTABLISHED, "llcp terminated before 5 seconds"
                info('link running for %d second, %s', i, llc.pcnt)
        except AssertionError as error:
            raise TestFail(str(error))
            
    def test_02(self, llc):
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
        TestData = collections.namedtuple("TestData", "sent rcvd")

        def send_and_receive(socket, send_count, packet_length):
            timestamp = lambda: datetime.datetime.fromtimestamp(time.time())
            test_data = TestData(sent=[], rcvd=[])
            cl_server = socket.getpeername()
            info_text = "  %s message %d at %s"
            try:
                for i in range(1, send_count + 1):
                    data, addr = packet_length * chr(i), cl_server
                    assert socket.sendto(data, addr), "message send failed"
                    test_data.sent.append((data, addr, timestamp()))
                    info(info_text, "sent", i, test_data.sent[-1][2].time())
                    time.sleep(0.5)
                for i in range(1, send_count + 1):
                    if socket.poll("recv", timeout=5.0):
                        data, addr = socket.recvfrom()
                        test_data.rcvd.append((data, addr, timestamp()))
                        info(info_text, "rcvd", i, test_data.rcvd[-1][2].time())
            except (AssertionError, nfc.llcp.Error) as error:
                raise TestFail(error)
            if len(test_data.rcvd) == 0:
                raise TestFail("did not receive any data within 5 seconds")
            return test_data

        def run_step_1(socket):
            info("Step 1: Send one default size datagram")
            test_data = send_and_receive(socket, 1, default_miu)
            if not len(test_data.rcvd) == len(test_data.sent):
                raise TestFail("received wrong number of datagrams")
            for i in range(len(test_data.rcvd)):
                sent_data, sent_addr, sent_time = test_data.sent[i]
                rcvd_data, rcvd_addr, rcvd_time = test_data.rcvd[i]
                if rcvd_addr != sent_addr:
                    raise TestFail("received data from different port")
                if rcvd_data != sent_data:
                    raise TestFail("received data does not match sent data")
                info("  message %d rcvd %.3f s after sent",
                     i+1, (rcvd_time-sent_time).total_seconds())
            return True

        def run_step_2(socket):
            info("Step 2: Send two default size datagrams")
            test_data = send_and_receive(socket, 2, default_miu)
            if not len(test_data.rcvd) == len(test_data.sent):
                raise TestFail("received wrong number of datagrams")
            for i in range(len(test_data.rcvd)):
                sent_data, sent_addr, sent_time = test_data.sent[i]
                rcvd_data, rcvd_addr, rcvd_time = test_data.rcvd[i]
                if rcvd_addr != sent_addr:
                    raise TestFail("received data from different port")
                if rcvd_data != sent_data:
                    raise TestFail("received data does not match sent data")
                info("  message %d rcvd %.3f s after sent",
                     i+1, (rcvd_time-sent_time).total_seconds())
            return True

        def run_step_3(socket):
            info("Step 3: Send three default size datagrams")
            test_data = send_and_receive(socket, 3, default_miu)
            if not len(test_data.rcvd) == len(test_data.sent) - 1:
                raise TestFail("received wrong number of datagrams")
            for i in range(len(test_data.rcvd)):
                sent_data, sent_addr, sent_time = test_data.sent[i]
                rcvd_data, rcvd_addr, rcvd_time = test_data.rcvd[i]
                if rcvd_addr != sent_addr:
                    raise TestFail("received data from different port")
                if rcvd_data != sent_data:
                    raise TestFail("received data does not match sent data")
                info("  message %d rcvd %.3f s after sent",
                     i+1, (rcvd_time-sent_time).total_seconds())
            return True

        def run_step_4(socket):
            info("Step 4: Send one zero-length datagram")
            test_data = send_and_receive(socket, 1, packet_length=0)
            if not len(test_data.rcvd) == len(test_data.sent):
                raise TestFail("received wrong number of datagrams")
            for i in range(len(test_data.rcvd)):
                sent_data, sent_addr, sent_time = test_data.sent[i]
                rcvd_data, rcvd_addr, rcvd_time = test_data.rcvd[i]
                if rcvd_addr != sent_addr:
                    raise TestFail("received data from different port")
                if rcvd_data != sent_data:
                    raise TestFail("received data does not match sent data")
                info("  message %d rcvd %.3f s after sent",
                     i+1, (rcvd_time-sent_time).total_seconds())
            return True

        def run_step_5(socket):
            info("Step 5: Send one maximum length packet")
            miu = socket.getsockopt(nfc.llcp.SO_SNDMIU)
            test_data = send_and_receive(socket, 1, packet_length=miu)
            if not len(test_data.rcvd) == len(test_data.sent):
                raise TestFail("received wrong number of datagrams")
            for i in range(len(test_data.rcvd)):
                sent_data, sent_addr, sent_time = test_data.sent[i]
                rcvd_data, rcvd_addr, rcvd_time = test_data.rcvd[i]
                if rcvd_addr != sent_addr:
                    raise TestFail("received data from different port")
                if rcvd_data != sent_data:
                    raise TestFail("received data does not match sent data")
                info("  message %d rcvd %.3f s after sent",
                     i+1, (rcvd_time-sent_time).total_seconds())
            return True

        cl_echo_server = get_connection_less_echo_server_sap(llc, self.options)
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 10)
        assert socket.getsockopt(nfc.llcp.SO_RCVBUF) == 10
        info("socket recv buffer set to 10")
        socket.connect(cl_echo_server)
        try:
            if run_step_1(socket): info("  PASS")
            if run_step_2(socket): info("  PASS")
            if run_step_3(socket): info("  PASS")
            if run_step_4(socket): info("  PASS")
            if run_step_5(socket): info("  PASS")
        finally:
            socket.close()
            
    def test_03(self, llc):
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
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        if socket.getsockopt(nfc.llcp.SO_RCVBUF) == 2:
            info("socket recv window set 2")
        else: raise TestFail("could not set the socket recv window")
        co_echo_server = self.options.co_echo_sap
        if not co_echo_server:
            co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
        if not co_echo_server:
            raise TestFail("no connection-mode echo server on peer device")
        info("connection-mode echo server on sap {0}".format(co_echo_server))
        socket.connect(co_echo_server)
        peer_sap = socket.getpeername()
        info("connected with sap {0}".format(peer_sap))
        socket.send(default_miu * "\xFF")
        t0 = time.time()
        info("sent one information pdu")
        if socket.poll("acks", timeout = 5):
            elapsed = time.time() - t0
            info("got confirm after {0:.3f}".format(elapsed))
            if not elapsed < 1.9:
                raise TestFail("no confirmation within 1.9 seconds")
            socket.recv()
            elapsed = time.time() - t0
            info("got message after {0:.3f}".format(time.time() - t0))
            if not elapsed > 2.0:
                raise TestFail("echo'd data received too early")
        else: raise TestFail("no data received within 5 seconds")
        socket.close()

    def test_04(self, llc):
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

        def receiver(llc, socket, rcvd_data):
            while socket.poll("recv", timeout=5):
                data = socket.recv()
                if data: rcvd_data.append((data, time.time()))

        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        if socket.getsockopt(nfc.llcp.SO_RCVBUF) == 2:
            info("receive window set to 2")
        else: raise TestFail("failed to set receive window to 2")
        co_echo_server = self.options.co_echo_sap
        if not co_echo_server:
            co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
        if not co_echo_server:
            raise TestFail("no connection-mode echo server on peer device")
        info("connection-mode echo server on sap {0}".format(co_echo_server))
        recv_thread = Thread(target=receiver, args=(llc, socket, rcvd_data))
        try:
            socket.connect(co_echo_server)
            peer_sap = socket.getpeername()
            info("connected with sap {0}".format(peer_sap))
            recv_thread.start()
            count = 20
            info("now sending {0} messages".format(count))
            for i in range(count):
                data = default_miu * chr(i)
                if socket.send(data):
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
            socket.close()

    def test_05(self, llc):
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
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 0)
        if socket.getsockopt(nfc.llcp.SO_RCVBUF) == 0:
            info("receive window set to 0")
        else: raise TestFail("failed to set receive window to 0")
        co_echo_server = self.options.co_echo_sap
        if not co_echo_server:
            co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
        if not co_echo_server:
            raise TestFail("no connection-mode echo server on peer device")
        info("connection-mode echo server on sap {0}".format(co_echo_server))
        try:
            socket.connect(co_echo_server)
            peer_sap = socket.getpeername()
            info("connected with sap {0}".format(peer_sap))
            info("now sending 4 messages")
            for i in range(4):
                data = default_miu * chr(i)
                if socket.send(data):
                    info("sent message {0}".format(i+1))
            for i in range(4):
                time.sleep(1.0)
                if socket.getsockopt(nfc.llcp.SO_SNDBSY):
                    info("connection-mode echo server entered busy state")
                    break
            else:
                raise TestFail("did not recognize server busy state")
        finally:
            socket.close()

    def test_06(self, llc):
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
        socket1 = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket2 = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        co_echo_server = self.options.co_echo_sap
        if not co_echo_server:
            co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
        if not co_echo_server:
            raise TestFail("no connection-mode echo server on peer device")
        info("connection-mode echo server on sap {0}".format(co_echo_server))
        try:
            socket1.connect(co_echo_server)
            peer_sap = socket1.getpeername()
            info("first connection established with sap {0}".format(peer_sap))
            try: socket2.connect(co_echo_server)
            except nfc.llcp.ConnectRefused as e:
                info("second connection rejected with reason {0:02x}h"
                     .format(e.reason))
            else:
                raise TestFail("second connection not rejected")
            finally:
                socket2.close()
        finally:
            socket1.close()

    def test_07(self, llc):
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
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        try:
            socket.connect("urn:nfc:sn:co-echo")
            info("connected to service 'urn:nfc:sn:co-echo'")
            peer_sap = socket.getpeername()
            if peer_sap == 1:
                raise TestFail("connection established with SDP port")
            info("connection established with sap {0}".format(peer_sap))
            if socket.send("here's nfcpy"):
                t0 = time.time()
                info("sent test message")
                if socket.poll("recv", timeout=5):
                    if socket.recv() == "here's nfcpy":
                        info("got echo after {0:.3f} sec"
                             .format(time.time()-t0))
                    else:
                        raise TestFail("received wrong data from echo server")
                else:
                    raise TestFail("no echo response within 5 seconds")
            else:
                raise TestFail("failed to send data")
        finally:
            socket.close()

    def test_08(self, llc):
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
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        try:
            socket.bind()
            socket.setsockopt(nfc.llcp.SO_RCVBUF, 10)
            if socket.getsockopt(nfc.llcp.SO_RCVBUF) != 10:
                raise TestFail("could not set the socket recv buffer")
            info("socket recv buffer set to 10")
            cl_echo_server = self.options.cl_echo_sap
            if not cl_echo_server:
                cl_echo_server = llc.resolve("urn:nfc:sn:cl-echo")
            if not cl_echo_server:
                raise TestFail("connection-less echo server not available")
            info("connection-less echo server on sap %d" % cl_echo_server)
            addr = socket.getsockname()
            sdu1 = 50 * b"\x01"
            sdu2 = 50 * b"\x02"
            sdu3 = 50 * b"\x03"

            info("step 1: send two datagrams with 50 byte payload")
            with llc.lock: # temporarily stop llc (only for testing)
                socket.sendto(sdu1, cl_echo_server, nfc.llcp.MSG_DONTWAIT)
                socket.sendto(sdu2, cl_echo_server, nfc.llcp.MSG_DONTWAIT)
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive first message within 5 sec")
            if not socket.recv() == sdu1:
                raise TestFail("first message came back wrong")
            info("received first message")
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive second message within 5 sec")
            if not socket.recv() == sdu2:
                raise TestFail("second message came back wrong")
            info("received second message")
            
            info("step2: send three datagrams with 50 byte payload")
            with llc.lock: # temporarily stop llc (only for testing)
                socket.sendto(sdu1, cl_echo_server, nfc.llcp.MSG_DONTWAIT)
                socket.sendto(sdu2, cl_echo_server, nfc.llcp.MSG_DONTWAIT)
                socket.sendto(sdu3, cl_echo_server, nfc.llcp.MSG_DONTWAIT)
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive first message within 5 sec")
            if not socket.recv() == sdu1:
                raise TestFail("first message came back wrong")
            info("received first message")
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive second message within 5 sec")
            if not socket.recv() == sdu2:
                raise TestFail("second message came back wrong")
            info("received second message")
            if socket.poll("recv", timeout=5):
                raise TestFail("received third message")
            info("did not receive third message within 5 sec")
        finally:
            socket.close()

    def test_09(self, llc):
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
        addr = llc.resolve("urn:nfc:sn:sdp")
        if not addr:
            raise TestFail("no answer for 'urn:nfc:sn:sdp' lookup")
        info("step 1: resolved 'urn:nfc:sn:sdp' to sap {0}".format(addr))
        addr = llc.resolve("urn:nfc:sn:cl-echo")
        if not addr:
            raise TestFail("no answer for 'urn:nfc:sn:cl-echo' lookup")
        info("step 2: resolved 'urn:nfc:sn:cl-echo' to sap {0}".format(addr))
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        t0 = time.time()
        if socket.sendto(128 * "\xA9", addr):
            info("step 3: sent 128 byte message to sap {0}".format(addr))
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive echo within 5 seconds")
            data, peer = socket.recvfrom()
            if not data == 128 * "\xA9":
                raise TestFail("received wrong data in step 3")
            if not peer == addr:
                raise TestFail("received from wrong sap in step 3")
            t1 = time.time()
            info("step 3: received echo after {0:.3} seconds".format(t1-t0))
        addr = llc.resolve("urn:nfc:sn:sdp-test")
        if not addr == 0:
            raise TestFail("'urn:nfc:sn:sdp-test' did not yield 0")
        info("step 4: resolved 'urn:nfc:sn:sdp-test' as {0}".format(addr))

    def test_10(self, llc):
        """Send more data than allowed"""
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        sap = get_connection_mode_echo_server_sap(llc, self.options)
        pdu = get_data_link_connection(socket, sap, 63, 128, 1)
        sdu = os.urandom(pdu.miu + 1)
        pdu = nfc.llcp.pdu.Information(pdu.ssap, pdu.dsap, 0, 0, sdu)
        info("remote MIU is {0} octet, sending 1 more".format(len(sdu)-1))
        try:
            socket.send(pdu)
            assert socket.poll("recv", 5), "no response in 5 seconds"
            pdu = socket.recv()
            assert pdu.name == "FRMR",  "expected FRMR PDU not %s" % pdu.name
            assert pdu.rej_flags == 4,  "expected FRMR FLAGS == 0100b"
            assert pdu.rej_ptype == 12, "expected FRMR PTYPE == 1100b"
        except (AssertionError, nfc.llcp.Error) as error:
            raise TestFail(str(error))
        finally:
            socket.close()

    def test_11(self, llc):
        """Use invalid send sequence number"""
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        sap = get_connection_mode_echo_server_sap(llc, self.options)
        pdu = get_data_link_connection(socket, sap, 63, 128, 1)
        pdu = nfc.llcp.pdu.Information(pdu.ssap, pdu.dsap, 13, 8, b'wrong seq')
        info("sending N(S)={pdu.ns} and N(R)={pdu.nr}".format(pdu=pdu))
        try:
            socket.send(pdu)
            assert socket.poll("recv", 5), "no response in 5 seconds"
            pdu = socket.recv()
            assert pdu.name == "FRMR",  "expected FRMR PDU not %s" % pdu.name
            assert pdu.rej_flags == 1,  "expected FRMR FLAGS == 0001b"
            assert pdu.rej_ptype == 12, "expected FRMR PTYPE == 1100b"
        except (AssertionError, nfc.llcp.Error) as error:
            raise TestFail(str(error))
        finally:
            socket.close()

    def test_12(self, llc):
        """Use maximum data size on data link connection"""
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        if socket.getsockopt(nfc.llcp.SO_RCVBUF) == 2:
            info("socket recv window set 2")
        else: raise TestFail("could not set the socket recv window")
        socket.setsockopt(nfc.llcp.SO_RCVMIU, 300)
        co_echo_server = self.options.co_echo_sap
        if not co_echo_server:
            co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
        if not co_echo_server:
            raise TestFail("no connection-mode echo server on peer device")
        info("connection-mode echo server on sap {0}".format(co_echo_server))
        socket.connect(co_echo_server)
        peer_sap = socket.getpeername()
        info("connected with sap {0}".format(peer_sap))
        miu = socket.getsockopt(nfc.llcp.SO_SNDMIU)
        socket.send(miu * "\xFF")
        t0 = time.time()
        info("sent one information pdu")
        if socket.poll("acks", timeout = 5):
            elapsed = time.time() - t0
            info("got confirm after {0:.3f}".format(elapsed))
            if not elapsed < 1.9:
                raise TestFail("no confirmation within 1.9 seconds")
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive second message within 5 sec")
            data = socket.recv()
            info("got message after {0:.3f}".format(time.time() - t0))
        else: raise TestFail("no data received within 5 seconds")
        socket.close()

    def test_13(self, llc):
        """Connect, release and connect again"""
        socket1 = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket2 = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        co_echo_server = self.options.co_echo_sap
        if not co_echo_server:
            co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
        if not co_echo_server:
            raise TestFail("no connection-mode echo server on peer device")
        info("connection-mode echo server on sap {0}".format(co_echo_server))
        try:
            socket1.connect(co_echo_server)
            peer_sap = socket1.getpeername()
            info("first connection established with sap {0}".format(peer_sap))
            socket1.send("I'm the first connection")
            assert(socket1.recv() == "I'm the first connection")
            socket1.close()
            info("first connection terminated")
            socket2.connect(co_echo_server)
            peer_sap = socket2.getpeername()
            info("second connection established with sap {0}".format(peer_sap))
            socket2.send("I'm the second connection")
            assert(socket2.recv() == "I'm the second connection")
            socket2.close()
        finally:
            pass

    def test_14(self, llc):
        """Connect to unknown service name

        Verify that a data link connection can be established by
        specifying a service name. The LLCP Link must be activated prior
        to running this scenario and the connection-oriented mode echo
        service must be in the unconnected state.

        1. Send a CONNECT PDU with an SN parameter that encodes the value
           "urn:nfc:sn:co-echo-unknown" to the service discovery service
           access point address and verify that the connect request is
           rejected.
        """
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        service_name = "urn:nfc:sn:co-echo-invalid"
        try:
            socket.connect(service_name)
            raise TestFail("connect to '" + service_name +"' not rejected")
        except nfc.llcp.ConnectRefused as e:
            info("connect to '{0}' rejected with reason {1}".format(
                    service_name, e.reason))
            if not e.reason in (0x02, 0x10, 0x11):
                raise TestFail("invalid DM reason code {0}".format(e.reason))
        except nfc.llcp.Error as error:
            raise TestFail(str(error))
        finally:
            socket.close()

    def test_15(self, llc):
        """Invalid PC(S) in secure data transfer mode (using cl-echo)

        Verify that the remote peer detects an invalid send counter
        when the LLCP Link is established in secure data transport
        mode. This test runs with the connection-mode echo server.

        1. Send one service data unit of 50 octets length to the
           connection-less mode echo service and wait up to 5 seconds
           to receive the same data back.

        2. Increment the send counter by 2 and send one service data
           unit of 50 octets length to the connection-less mode echo
           service. Verify that the LLCP Link is terminated.

        """
        if llc.secure_data_transfer is False:
            raise TestSkip("secure data transfer is not enabled")
        if self.options.test.index('15') != len(self.options.test) - 1:
            log.warn("Test 15 causes link termination, further tests skipped")
            del self.options.test[self.options.test.index('15')+1:]
        
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        try:
            socket.bind()
            cl_echo_server = self.options.cl_echo_sap
            if not cl_echo_server:
                cl_echo_server = llc.resolve("urn:nfc:sn:cl-echo")
            if not cl_echo_server:
                raise TestFail("connection-less echo server not available")
            info("connection-less echo server on sap %d" % cl_echo_server)
            
            sdu1 = 50 * b'\x01'
            sdu2 = 50 * b'\x02'

            info("step 1: send one datagram to verify secure data transfer")
            socket.sendto(sdu1, cl_echo_server)
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive first message within 5 sec")
            if not socket.recv() == sdu1:
                raise TestFail("first message came back wrong")
            info("received first message")

            info("step2: send one datagram with invalid packet send counter")
            llc.sec._pcs += 1
            socket.sendto(sdu2, cl_echo_server)
            if socket.poll("recv", timeout=5):
                raise TestFail("received data but link should be terminated")
            if not llc.link.SHUTDOWN:
                raise TestFail("link not terminated")
            info("link terminated as required")
            
        finally:
            socket.close()

    def test_16(self, llc):
        """Invalid UI-PDU header in secure data transfer mode

        Verify that the remote peer detects an invalid PDU header when
        the LLCP Link is established in secure data transport mode. The
        PDU header is protected as additional authenticated data and
        any modifications must fail decryption-verification.

        1. Send one service data unit of 50 octets length to the
           connection-less mode echo service and wait up to 5 seconds
           to receive the same data back.

        2. Send another service data unit but change the SSAP value of
           the encrypted UI PDU before sending. Verify that the LLCP
           Link is terminated.

        """
        if llc.secure_data_transfer is False:
            raise TestSkip("secure data transfer is not enabled")
        if self.options.test.index('16') != len(self.options.test) - 1:
            log.warn("Test 16 causes link termination, further tests skipped")
            del self.options.test[self.options.test.index('16')+1:]
        
        socket1 = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        socket2 = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        socket1.bind()
        socket2.bind()
        socket1_sap = socket1.getsockname()
        socket2_sap = socket2.getsockname()

        def on_llc_exchange_call(send_pdu, timeout):
            if send_pdu and send_pdu.name=="UI" and send_pdu.ssap==socket1_sap:
                send_pdu.ssap = socket2_sap
            return send_pdu

        try:
            cl_echo_server = self.options.cl_echo_sap
            if not cl_echo_server:
                cl_echo_server = llc.resolve("urn:nfc:sn:cl-echo")
            if not cl_echo_server:
                raise TestFail("connection-less echo server not available")
            info("connection-less echo server on sap %d" % cl_echo_server)
            
            sdu1 = 50 * b'\x01'
            sdu2 = 50 * b'\x02'

            info("step 1: send one datagram to verify secure data transfer")
            socket1.sendto(sdu1, cl_echo_server)
            if not socket1.poll("recv", timeout=5):
                raise TestFail("did not receive first message within 5 sec")
            if not socket1.recv() == sdu1:
                raise TestFail("first message came back wrong")
            info("received first message")

            self.on_llc_exchange_call = on_llc_exchange_call

            info("step2: send one datagram with invalid pdu header ssap")
            socket1.sendto(sdu2, cl_echo_server)
            if socket2.poll("recv", timeout=5):
                raise TestFail("received data but link should be terminated")
            if not llc.link.SHUTDOWN:
                raise TestFail("link not terminated")
            info("link terminated as required")
            
        finally:
            socket1.close()
            socket2.close()

    def test_17(self, llc):
        """Invalid PC(S) in secure data transfer mode (using co-echo)

        Verify that the remote peer detects an invalid send counter
        when the LLCP Link is established in secure data transport
        mode. This test runs with the connection-mode echo server.

        1. Send one service data unit of 50 octets length to the
           connection-oriented mode echo service and wait up to 5
           seconds to receive the same data back.

        2. Increment the send counter by 2 and send one service data
           unit of 50 octets length to the connection-oriented mode
           echo service. Verify that the LLCP Link is terminated.

        """
        if llc.secure_data_transfer is False:
            raise TestSkip("secure data transfer is not enabled")
        if self.options.test.index('17') != len(self.options.test) - 1:
            log.warn("Test 17 causes link termination, further tests skipped")
            del self.options.test[self.options.test.index('17')+1:]
        
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        try:
            co_echo_server = self.options.co_echo_sap
            if not co_echo_server:
                co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
            if not co_echo_server:
                raise TestFail("connection-mode echo server not available")
            info("connection-mode echo server on sap %d" % co_echo_server)
            socket.connect(co_echo_server)
            
            sdu1 = 50 * b'\x01'
            sdu2 = 50 * b'\x02'

            info("step 1: send one message to verify secure data transfer")
            socket.send(sdu1)
            if not socket.poll("recv", timeout=5):
                raise TestFail("did not receive first message within 5 sec")
            if not socket.recv() == sdu1:
                raise TestFail("first message came back wrong")
            info("received first message")

            info("step2: send one message with invalid packet send counter")
            llc.sec._pcs += 1
            socket.send(sdu2)
            if socket.poll("recv", timeout=5):
                raise TestFail("received data but link should be terminated")
            if not llc.link.SHUTDOWN:
                raise TestFail("link not terminated")
            info("link terminated as required")
            
        finally:
            socket.close()

    def test_18(self, llc):
        """Invalid I-PDU header in secure data transfer mode

        Verify that the remote peer detects an invalid PDU header when
        the LLCP Link is established in secure data transport mode. The
        PDU header is protected as additional authenticated data and
        any modifications must fail decryption-verification.

        1. Send one service data unit of 50 octets length to the
           connection-oriented mode echo service and wait up to 5
           seconds to receive the same data back.

        2. Send another service data unit but change the SSAP value of
           the encrypted I PDU before sending. Verify that the LLCP
           Link is terminated.

        """
        if llc.secure_data_transfer is False:
            raise TestSkip("secure data transfer is not enabled")
        if self.options.test.index('18') != len(self.options.test) - 1:
            log.warn("Test 18 causes link termination, further tests skipped")
            del self.options.test[self.options.test.index('18')+1:]
        
        socket1 = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket2 = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket1.bind()
        socket2.bind()
        socket1_sap = socket1.getsockname()
        socket2_sap = socket2.getsockname()

        def on_llc_exchange_call(send_pdu, timeout):
            if send_pdu and send_pdu.name=="I" and send_pdu.ssap==socket1_sap:
                send_pdu.ssap = socket2_sap
            return send_pdu

        try:
            co_echo_server = self.options.co_echo_sap
            if not co_echo_server:
                co_echo_server = llc.resolve("urn:nfc:sn:co-echo")
            if not co_echo_server:
                raise TestFail("connection-mode echo server not available")
            info("connection-mode echo server on sap %d" % co_echo_server)
            socket1.connect(co_echo_server)
            
            sdu1 = 50 * b'\x01'
            sdu2 = 50 * b'\x02'

            info("step 1: send one message to verify secure data transfer")
            socket1.send(sdu1)
            if not socket1.poll("recv", timeout=5):
                raise TestFail("did not receive first message within 5 sec")
            if not socket1.recv() == sdu1:
                raise TestFail("first message came back wrong")
            info("received first message")

            self.on_llc_exchange_call = on_llc_exchange_call

            info("step2: send one message with invalid pdu header ssap")
            socket1.send(sdu2)
            if socket1.poll("recv", timeout=5):
                raise TestFail("received data but link should be terminated")
            if not llc.link.SHUTDOWN:
                raise TestFail("link not terminated")
            info("link terminated as required")
            
        finally:
            socket1.close()
            socket2.close()

if __name__ == '__main__':
    TestProgram().run()
