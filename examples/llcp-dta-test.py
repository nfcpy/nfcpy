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
log = logging.getLogger('test')

import time
import errno
import struct
import argparse

from cli import CommandLineInterface, TestFail, TestSkip

import nfc
import nfc.llcp
import nfc.llcp.pdu
from nfc.llcp.pdu import UnknownProtocolDataUnit

def hexstr(octets, delimiter=''):
    return delimiter.join(["{0:02X}".format(ord(x)) for x in octets])

def info(message, *args, **kwargs):
    log.info(message, *args, **kwargs)

description = """
Logical Link Control Protocol (LLCP) tester. The peer device must have
the LLCP DTA running.
"""

SN_CL_ECHO_IN  = b'urn:nfc:sn:dta-cl-echo-in'
SN_CL_ECHO_OUT = b'urn:nfc:sn:dta-cl-echo-out'
SN_CO_ECHO_IN  = b'urn:nfc:sn:dta-co-echo-in'
SN_CO_ECHO_OUT = b'urn:nfc:sn:dta-co-echo-out'
SN_PATTERN_NR  = b'urn:nfc:sn:pattern-number'

def raw_access_point_wait_recv(socket, timeout=3.0):
    text = "- wait %d seconds to receive a PDU on sap %d"
    info(text, timeout, socket.getsockname())
    if not socket.poll("recv", timeout):
        raise TestFail("expected data but got none within %d seconds" % timeout)
    pdu = socket.recv()
    info("- received %s PDU from sap %d", pdu.name, pdu.ssap)
    return pdu

def raw_access_point_wait_no_recv(socket, timeout=3.0):
    text = "- wait %d seconds to not receive a PDU on sap %d"
    info(text, timeout, socket.getsockname())
    if socket.poll("recv", timeout):
        raise TestFail("expected none but got data within %d seconds" % timeout)

def logical_data_link_send_sot(socket, dsap, ssap):
    pdu = nfc.llcp.pdu.UnnumberedInformation(dsap, ssap, data=b'SOT')
    info("send the start of test command")
    assert socket.send(pdu), "error sending start of test command"

def logical_data_link_wait_recv(socket, timeout=3.0):
    text = "- wait %d seconds to receive a response on sap %d"
    info(text, timeout, socket.getsockname())
    if not socket.poll("recv", timeout):
        raise TestFail("expected data but got none within %d seconds" % timeout)
    data, addr = socket.recvfrom()
    info("- received %d byte from sap %d", len(data), addr)
    return data, addr

def logical_data_link_wait_no_recv(socket, timeout=3.0):
    text = "- wait %d seconds to not receive a response on sap %d"
    info(text, timeout, socket.getsockname())
    if socket.poll("recv", timeout=timeout):
        raise TestFail("expected none but got data within %d seconds" % timeout)

def data_link_connection_wait_recv(socket, timeout=3.0):
    text = "- wait %d seconds to receive a response on sap %d"
    info(text, timeout, socket.getsockname())
    if not socket.poll("recv", timeout):
        raise TestFail("expected data but got none within %d seconds" % timeout)
    data = socket.recv()
    info("- received %d byte from sap %d", len(data), socket.getpeername())
    return data

def data_link_connection_wait_no_recv(socket, timeout=3.0):
    text = "- wait %d seconds to not receive a response on sap %d"
    info(text, timeout, socket.getsockname())
    if socket.poll("recv", timeout):
        raise TestFail("expected none but got data within %d seconds" % timeout)

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

        super(TestProgram, self).__init__(parser, groups="test llcp dbg clf")
        
    def run(self):
        self.lt_cl_in_sap = 0x21
        self.lt_co_in_sap = 0x20
        if len(self.options.test) > 0:
            test_list = self.options.test[:]
            if test_list[0] != 'PREPARE':
                test_list = ['PREPARE'] + test_list
            for test in test_list:
                info("*** START ***")
                if '_INI_' in test:
                    self.options.mode = 'target'
                if '_TAR_' in test:
                    self.options.mode = 'initiator'
                self.options.test = [test]
                try:
                    if self.run_once() is False: break
                except (AssertionError, nfc.llcp.Error) as error:
                    raise TestFail(str(error))
                time.sleep(1)
        else:
            log.error("no tests specified - nothing to do")

    def on_llcp_startup(self, llc):
        func_name = "prep_{0}".format(self.options.test[0])
        try: on_startup = eval("self." + func_name)
        except AttributeError: pass
        else: llc = on_startup(llc)
        if llc:
            socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
            socket.bind(SN_CL_ECHO_OUT)
            self.dta_cl_echo_out = socket
            socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
            socket.bind(SN_CO_ECHO_OUT)
            self.dta_co_echo_out = socket
        return llc

    def on_llcp_connect(self, llc):
        func_name = "init_{0}".format(self.options.test[0])
        try: on_connect = eval("self." + func_name)
        except AttributeError: pass
        else: llc = on_connect(llc)
        super(TestProgram, self).on_llcp_connect(llc)
        info("LLC %s", llc.pcnt)
        info("DEP %s", llc.mac.pcnt)
        return False

    def test_PREPARE(self, llc):
        """Determine Parameters of Implementation Under Test"""
        self.iut_miu = llc.cfg['send-miu']
        self.iut_lto = llc.cfg['recv-lto']
        self.iut_cl_in_sap = llc.resolve(SN_CL_ECHO_IN)
        self.iut_co_in_sap = llc.resolve(SN_CO_ECHO_IN)
        info("IUT MIU = %d", self.iut_miu)
        info("IUT LTO = %d", self.iut_lto)
        info("CL ADDR = %d", self.iut_cl_in_sap)
        info("CO ADDR = %d", self.iut_co_in_sap)
    
    def test_TC_LLC_INI_BV_04(self, llc):
        """Symmetry Procedure as NFC-DEP Initiator
        
        After LLCP Link activation respond to any received PDU with a
        SYMM PDU until 10 SYMM PDUs have been sent. Then deactivate
        the LLCP Link.

        """
        info("send SYMM PDU for 10 times and measure response")
        for i in range(10):
            sent_symm = llc.pcnt.sent['SYMM']
            while llc.pcnt.sent['SYMM'] == sent_symm:
                time.sleep(0.001)
            sent_time = time.time()
            rcvd_pdu_count = llc.pcnt.rcvd_count
            while llc.pcnt.rcvd_count == rcvd_pdu_count:
                time.sleep(0.001)
            elapsed = time.time() - sent_time
            info("- received an LLC PDU after %.3f sec", elapsed)
            assert elapsed <= llc.cfg['recv-lto'], "symmetry timeout"
    
    def test_TC_LLC_TAR_BV_04(self, llc):
        """Symmetry Procedure as NFC-DEP Target
        
        After LLCP Link activation respond to any received PDU with a
        SYMM PDU until 10 SYMM PDUs have been sent. Then deactivate
        the LLCP Link.

        """
        info("send SYMM PDU for 10 times and measure response")
        for i in range(10):
            sent_symm = llc.pcnt.sent['SYMM']
            while llc.pcnt.sent['SYMM'] == sent_symm:
                time.sleep(0.001)
            sent_time = time.time()
            rcvd_pdu_count = llc.pcnt.rcvd_count
            while llc.pcnt.rcvd_count == rcvd_pdu_count:
                time.sleep(0.001)
            elapsed = time.time() - sent_time
            info("- received an LLC PDU after %.3f sec", elapsed)
            assert elapsed <= llc.cfg['recv-lto'], "symmetry timeout"
    
    def prep_TC_CTL_UND_BV_01(self, llc):
        llc.cfg['recv-miu'] = self.iut_miu - 1 # MIUX(LT) = MIUX(IUT) - 1
        llc.cfg['send-lto'] = 1000
        llc.cfg['send-agf'] = False
        return llc

    def test_TC_CTL_UND_BV_01(self, llc):
        """Connectionless Transport Maximum Size of Information Field
        
        Set MIU(LT) equal to MIU(IUT) - 1 and establish the LLCP Link.
        
        First send a UI PDU with an SDU exactly the size of the LT's
        Link MIU. The IUT is expected to return the same SDU.

        Then send a UI PDU with an SDU exactly the size of the IUT's
        Link MIU. The IUT is expected to not return the SDU because it
        exceeds the LT's Link MIU.
        
        """
        if not llc.cfg['send-miu'] > 128:
            raise TestSkip("IUT Link MIU is not more than 128")
        
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        socket.bind(self.lt_cl_in_sap)
        
        dsap, ssap = self.iut_cl_in_sap, self.lt_cl_in_sap
        pdu = nfc.llcp.pdu.UnnumberedInformation(dsap, ssap, data=b'SOT')
        info("send the start of test command")
        assert socket.send(pdu), "error sending start of test command"

        info("send UI PDU with %d-1 octet information", self.iut_miu)
        pdu.data = b'\xA5' * (self.iut_miu - 1)
        assert socket.send(pdu), "error sending UI PDU"
        data, addr = logical_data_link_wait_recv(self.dta_cl_echo_out, 5.0)
        assert data == pdu.data, "received wrong data on echo return path"

        info("send UI PDU with %d octet information", self.iut_miu)
        pdu.data = b'\xA5' * self.iut_miu
        assert socket.send(pdu), "error sending UI PDU"
        logical_data_link_wait_no_recv(self.dta_cl_echo_out, 5.0)

        info("test completed")
        socket.close()

    def prep_TC_CTL_UND_BI_01(self, llc):
        llc.cfg['recv-miu'] = self.iut_miu # MIUX(LT) = MIUX(IUT)
        llc.cfg['send-lto'] = 1000
        llc.cfg['send-agf'] = False
        return llc

    def test_TC_CTL_UND_BI_01(self, llc):
        """Connectionless Transport Maximum Information Unit Exceeded

        Set MIU(LT) equal to MIU(IUT) and establish the LLCP Link.
        
        First send a UI PDU with an SDU exactly the size of the IUT's
        Link MIU. The IUT is expected to return the same SDU.

        Then send a UI PDU with an SDU that exceeds the size of the
        IUT's Link MIU by one. The IUT is expected to not return the
        SDU because it exceeds the IUT's Link MIU.
        
        """
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        socket.bind(self.lt_cl_in_sap)
        
        dsap, ssap = self.iut_cl_in_sap, self.lt_cl_in_sap
        pdu = nfc.llcp.pdu.UnnumberedInformation(dsap, ssap, data=b'SOT')
        info("send the start of test command")
        assert socket.send(pdu), "error sending start of test command"

        info("send UI PDU with an MIU(IUT) size information field")
        pdu.data = b'\xA5' * self.iut_miu
        assert socket.send(pdu), "error sending UI PDU"
        data, addr = logical_data_link_wait_recv(self.dta_cl_echo_out, 5.0)
        assert data == pdu.data, "received wrong data on echo return path"

        info("send UI PDU with an MIU(IUT)+1 size information field")
        pdu.data = b'\xA5' * (self.iut_miu + 1)
        assert socket.send(pdu), "error sending UI PDU"
        logical_data_link_wait_no_recv(self.dta_cl_echo_out, 5.0)

        info("test completed")
        socket.close()

    def prep_TC_CTL_UND_BV_02(self, llc):
        llc.cfg['recv-miu'] = self.iut_miu # MIUX(LT) = MIUX(IUT)
        llc.cfg['send-lto'] = 1000
        llc.cfg['send-agf'] = False
        return llc
    
    def test_TC_CTL_UND_BV_02(self, llc):
        """Connectionless Transport No Reception Acknowledgement

        Set MIU(LT) equal to MIU(IUT) and establish the LLCP Link.
        
        Send a UI PDU with an SDU exactly the size of the IUT's Link
        MIU. Verify for an amount of time that the IUT does not
        respond on the same logical data link. Then verify that the
        IUT responded with the same SDU on the echo server outbound
        data link connection.

        """
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        socket.bind(self.lt_cl_in_sap)
        
        dsap, ssap = self.iut_cl_in_sap, self.lt_cl_in_sap
        pdu = nfc.llcp.pdu.UnnumberedInformation(dsap, ssap, data=b'SOT')
        info("send the start of test command")
        assert socket.send(pdu), "error sending start of test command"

        info("send UI PDU with %d octet information", self.iut_miu)
        pdu.data = b'\xA5' * self.iut_miu
        assert socket.send(pdu), "error sending UI PDU"

        logical_data_link_wait_no_recv(socket, 5.0)

        data, addr = logical_data_link_wait_recv(self.dta_cl_echo_out, 5.0)
        assert data == pdu.data, "received wrong data on echo return path"

        info("test completed")
        socket.close()
    
    def prep_TC_CTL_UND_BI_02(self, llc):
        llc.cfg['recv-miu'] = self.iut_miu + 1 # MIUX(LT) = MIUX(IUT) + 1
        llc.cfg['send-lto'] = 1000
        llc.cfg['send-agf'] = False
        return llc

    def test_TC_CTL_UND_BI_02(self, llc):
        """Connectionless Transport No Acknowledgement for Invalid Frames

        Send a UI PDU with an Information field that is one octet
        larger than the IUT's Link MIU (which must be at least one
        octet less than the maximum possible value). The IUT is
        expected to discard the UI PDU and not send it back (the
        return path would allow sending).

        """
        if llc.cfg['send-miu'] >= 2175:
            raise TestSkip("IUT Link MIU is not less than 2175")
        
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        socket.bind(self.lt_cl_in_sap)
        
        dsap, ssap = self.iut_cl_in_sap, self.lt_cl_in_sap
        pdu = nfc.llcp.pdu.UnnumberedInformation(dsap, ssap, data=b'SOT')
        info("send the start of test command")
        assert socket.send(pdu), "error sending start of test command"

        log.info("send UI PDU with %d+1 octet information field", self.iut_miu)
        pdu.data = b'\xA5' * (self.iut_miu + 1)
        assert socket.send(pdu), "error sending UI PDU with excess SDU"
        logical_data_link_wait_no_recv(self.dta_cl_echo_out, 5.0)

        # TC Note: This part of the test case does not really make
        # sense. An empty SNL PDU is not an invalid PDU. The test
        # succeeds just because an empty SNL PDU does not cause any
        # answer to be returned (there was nothing asked for).
        info("send SNL PDU with no content")
        snl_count = llc.pcnt.rcvd["SNL"]
        socket.send(nfc.llcp.pdu.ServiceNameLookup(1, 1))
        log.info("- wait 5 seconds to not receive an SNL PDU")
        time.sleep(5)
        assert llc.pcnt.rcvd["SNL"] == snl_count, "received SNL PDU response"

        info("test completed")
        socket.close()

    def test_TC_CTO_TAR_BV_01_1(self, llc):
        """Connection Establishment with Specific SAP and no Parameters
        
        Send a CONNECT PDU with no paramteters to the echo server
        inbound SAP. Verify that a CC PDU is received and the IUT
        establishes the outbound connection.
        
        """
        self.exec_TC_CTO_TAR_BV_01_x(llc, x=1)

    def test_TC_CTO_TAR_BV_01_2(self, llc):
        """Connection Establishment with Specific SAP and MIUX
        
        Send a CONNECT PDU with an MIUX parameter to the echo server
        inbound SAP. Verify that a CC PDU is received and the IUT
        establishes the outbound connection.
        
        """
        self.exec_TC_CTO_TAR_BV_01_x(llc, x=2)

    def test_TC_CTO_TAR_BV_01_3(self, llc):
        """Connection Establishment with Specific SAP and RW=0Xh
        
        Send a CONNECT PDU with an RW parameter to the echo server
        inbound SAP. Verify that a CC PDU is received and the IUT
        establishes the outbound connection.
        
        """
        self.exec_TC_CTO_TAR_BV_01_x(llc, x=3)

    def test_TC_CTO_TAR_BV_01_4(self, llc):
        """Connection Establishment with Specific SAP and RW=FXh
        
        Send a CONNECT PDU with an RW parameter (with reserved bits
        set to 1) to the echo server inbound SAP. Verify that a CC PDU
        is received and the IUT establishes the outbound connection.
        
        """
        self.exec_TC_CTO_TAR_BV_01_x(llc, x=4)

    def test_TC_CTO_TAR_BV_01_5(self, llc):
        """Connection Establishment with Specific SAP and Service Name
        
        Send a CONNECT PDU with an SN parameter to the echo server
        inbound SAP. Verify that a CC PDU is received and the IUT
        establishes the outbound connection.
        
        """
        self.exec_TC_CTO_TAR_BV_01_x(llc, x=5)

    def test_TC_CTO_TAR_BV_01_6(self, llc):
        """Connection Establishment with Specific SAP and MIUX,RW,SN
        
        Send a CONNECT PDU with an MIUX, RW, and SN parameter to the
        echo server inbound SAP. Verify that a CC PDU is received and
        the IUT establishes the outbound connection.
        
        """
        self.exec_TC_CTO_TAR_BV_01_x(llc, x=6)

    def test_TC_CTO_TAR_BV_01_7(self, llc):
        """Connection Establishment with Specific SAP and Undefined TLV
        
        Send a CONNECT PDU with an undefined parameter TLV to the echo
        server inbound SAP. Verify that a CC PDU is received and the
        IUT establishes the outbound connection.

        """
        self.exec_TC_CTO_TAR_BV_01_x(llc, x=7)

    def exec_TC_CTO_TAR_BV_01_x(self, llc, x):
        data = {
            1: b'',
            2: struct.pack('!BBH',   2,  2, 1),
            3: struct.pack('!BBB',   5,  1, 0x05),
            4: struct.pack('!BBB',   5,  1, 0xF9),
            5: struct.pack('!BB25s', 6, 25, SN_CL_ECHO_IN),
            7: struct.pack('!BBB', 254,  1, 0),
        }
        data[6] = data[2] + data[3] + data[5]
        
        iut_co_in_sap, lt_co_in_sap = self.iut_co_in_sap, self.lt_co_in_sap
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        send_socket.bind(lt_co_in_sap)

        self.dta_co_echo_out.listen(backlog=1)

        info("send CONNECT PDU with payload '%s'", hexstr(data[x], ':'))
        pdu = {'ptype': 4, 'dsap': iut_co_in_sap, 'ssap': lt_co_in_sap}
        pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(payload=data[x], **pdu)
        send_socket.send(pdu)

        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "CC", "expected CC PDU but got %s" % pdu.name

        recv_socket = self.dta_co_echo_out.accept()
        data_link_connection_wait_no_recv(recv_socket, timeout=1.0)

        pdu = nfc.llcp.pdu.Disconnect(dsap=iut_co_in_sap, ssap=lt_co_in_sap)
        send_socket.send(pdu)

        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "DM", "expected DM PDU but got %s" % pdu.name

        recv_socket.poll("recv", 5)
        
        info("test completed")
        send_socket.close()
        recv_socket.close()
    
    def test_TC_CTO_TAR_BV_02(self, llc):
        """Connection Establishment with Service Name to SAP 1
        
        Send a CONNECT PDU with SN parameter to SAP 1 to establish the
        echo server inbound connection with connect-by-name. Wait for
        the echo server to establish the outbound connection, then
        disconnect.

        """
        iut_co_in_sap, lt_co_in_sap = self.iut_co_in_sap, self.lt_co_in_sap
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        send_socket.bind(lt_co_in_sap)
        
        self.dta_co_echo_out.listen(backlog=1)

        info("connect-by-name to connection-mode echo server")
        pdu = nfc.llcp.pdu.Connect(1, lt_co_in_sap, sn=SN_CO_ECHO_IN)
        send_socket.send(pdu)

        info("waiting for data link connection confirmation")
        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "CC", "expected CC PDU but got %s" % pdu.name
        info("connection complete received from sap %d", pdu.ssap)

        # TC NOTE: Step 2 requires that the CC PDU SSAP is the echo
        # server inbound SAP but it may be any except well-known.
        assert pdu.ssap >= 16, "CC SSAP is in range 0 to 15"

        # Data link connection established with SSAP from CC PDU
        iut_co_in_sap = pdu.ssap

        info("waiting for outbound connection")
        recv_socket = self.dta_co_echo_out.accept()
        data_link_connection_wait_no_recv(recv_socket, timeout=1.0)

        info("disconnecting inbound connection")
        pdu = nfc.llcp.pdu.Disconnect(iut_co_in_sap, lt_co_in_sap)
        send_socket.send(pdu)

        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "DM", "expected DM PDU but got %s" % pdu.name

        recv_socket.poll("recv", 5)
        
        info("test completed")
        send_socket.close()
        recv_socket.close()
    
    def test_TC_CTO_TAR_BV_03(self, llc):
        """Connection Establishment Using Service Discovery
        
        Send an SNL PDU to retrieve the SAP address of the echo server
        inbound connection. Then send a CONNECT PDU to the retrieved
        SAP address to establish the inbound connection. Verify that
        the connection is acknowledged with a CC PDU and that the IUT
        sends a CONNECT PDU to establish the outbound connection. Then
        disconnect the inbound connection and wait for the IUT to
        disconnect the outbound connection.

        """
        iut_co_in_sap, lt_co_in_sap = self.iut_co_in_sap, self.lt_co_in_sap
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        send_socket.bind(lt_co_in_sap)
        
        self.dta_co_echo_out.listen(backlog=1)

        info("resolve SAP for service name '%s'", SN_CO_ECHO_IN)
        addr = llc.resolve(SN_CO_ECHO_IN)
        assert addr == iut_co_in_sap, "service name resolve error"

        info("connect-by-addr to connection-mode echo server")
        pdu = nfc.llcp.pdu.Connect(iut_co_in_sap, lt_co_in_sap)
        send_socket.send(pdu)

        info("waiting for data link connection confirmation")
        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "CC", "expected CC PDU but got %s" % pdu.name
        # TC NOTE: Step 4 requires that the CC PDU SSAP is the echo
        # server inbound SAP but it may be any except well-known.
        assert pdu.ssap >= 16, "CC SSAP is in range 0 to 15"

        info("waiting for outbound connection")
        recv_socket = self.dta_co_echo_out.accept()
        data_link_connection_wait_no_recv(recv_socket, timeout=1.0)

        info("disconnecting inbound connection")
        pdu = nfc.llcp.pdu.Disconnect(iut_co_in_sap, lt_co_in_sap)
        send_socket.send(pdu)

        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "DM", "expected DM PDU but got %s" % pdu.name

        recv_socket.poll("recv", 5)
        
        info("test completed")
        send_socket.close()
        recv_socket.close()
    
    def test_TC_CTO_TAR_BI_01(self, llc):
        """Target Errors in CONNECT PDU No Service Bound to SAP
        
        Send a CONNECT PDU to an unbound service access point. The IUT
        is expected to respond with a DM PDU with reason code 0x02 (no
        service bound to target service access point).

        """
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        send_socket.bind(self.lt_co_in_sap)
        
        pdu = nfc.llcp.pdu.Connect(31, self.lt_co_in_sap)
        send_socket.send(pdu)

        pdu = raw_access_point_wait_recv(send_socket)
        assert pdu.name == "DM", "expected DM PDU but got %s" % pdu.name
        assert pdu.reason == 0x02, "expected DM reason code 02h"
        
        info("test completed")
        send_socket.close()
    
    def test_TC_CTO_TAR_BI_02_1(self, llc):
        """Connect By Name with malformed Service Name URI
        
        Send a CONNECT PDU with service name 'urn:nfc:void' to SAP 1.
        The IUT is expected to return a DM PDU with reason code 02h
        (no service bound to target service access point)
        
        """
        self.exec_TC_CTO_TAR_BI_02_x(llc, x=1)
    
    def test_TC_CTO_TAR_BI_02_2(self, llc):
        """Connect By Name with zero-length Service Name
        
        Send a CONNECT PDU with service name 'urn:nfc:sn:' to SAP 1.
        The IUT is expected to return a DM PDU with reason code 02h
        (no service bound to target service access point)
        
        """
        self.exec_TC_CTO_TAR_BI_02_x(llc, x=2)
    
    def test_TC_CTO_TAR_BI_02_3(self, llc):
        """Connect By Name with SN TLV empty value field
        
        Send a CONNECT PDU with service name '' (SN TLV with zero
        length) to SAP 1. The IUT is expected to return a DM PDU with
        reason code 02h (no service bound to target service access
        point)

        """
        self.exec_TC_CTO_TAR_BI_02_x(llc, x=3)
    
    def test_TC_CTO_TAR_BI_02_4(self, llc):
        """Connect By Name without Service Name TLV
        
        Send a CONNECT PDU with no service name 'urn:nfc:sn:' to SAP 1.
        The SN TLV encodes a complete and valid service name but the
        length field only covers the part 'urn'nfc:sn'. The IUT is
        expected to return a DM PDU with reason code 02h (no service
        bound to target service access point)

        """
        self.exec_TC_CTO_TAR_BI_02_x(llc, x=4)
    
    def test_TC_CTO_TAR_BI_02_5(self, llc):
        """Connect By Name without Service Name TLV
        
        Send a CONNECT PDU with service name TLV to SAP 1. The IUT
        is expected to return a DM PDU with reason code 03h (request
        to connect rejected by service layer) or 10h (permanetly no
        accept any CONNECT PDU to this service access point).

        """
        self.exec_TC_CTO_TAR_BI_02_x(llc, x=5)
    
    def exec_TC_CTO_TAR_BI_02_x(self, llc, x):
        data = {
            1: struct.pack('!BB14s', 6, 14, b'urn:nfc:void\x0d\x0a'),
            2: struct.pack('!BB11s', 6, 11, b'urn:nfc:sn:'),
            3: struct.pack('!BB', 6, 0),
            4: b'',
            5: struct.pack('!BB25s', 6, 11, b'urn:nfc:sn:dta-co-echo-in'),
            # TC Note: For x=5 the service name should be a valid
            # service name that is made invalid by the length byte.
            # TC Note: For x=5 the result is not specified in Acceptance.
        }
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        socket.bind(self.lt_co_in_sap)
        
        info("send CONNECT PDU with payload '%s'", hexstr(data[x], ':'))
        pdu = {'ptype': 0b0100, 'dsap': 1, 'ssap': socket.getsockname()}
        pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(payload=data[x], **pdu)
        socket.send(pdu)
        
        pdu = raw_access_point_wait_recv(socket)
        assert pdu.name == "DM", "expected DM PDU but got %s" % pdu.name
        info("got DM reason code %02Xh (%s)", pdu.reason, pdu.reason_text)
        
        if x != 4: assert pdu.reason == 2, "DM reason code not 02h"
        else: assert pdu.reason in (3,16), "DM reason code not 03h or 10h"
        socket.close()

    def prep_TC_CTO_TAR_BI_03_1(self, llc):
        return self.prep_TC_CTO_TAR_BI_03_x(llc)
        
    def test_TC_CTO_TAR_BI_03_1(self, llc):
        """Service Discovery with malformed Service Name URI

        Send an SNL PDU to the IUT's service discovery component with
        a single SDREQ that contains a malformed service name. The IUT
        is expected to return the SAP value zero.

        """
        self.exec_TC_CTO_TAR_BI_03_x(llc, x=1)
    
    def prep_TC_CTO_TAR_BI_03_2(self, llc):
        return self.prep_TC_CTO_TAR_BI_03_x(llc)
        
    def test_TC_CTO_TAR_BI_03_2(self, llc):
        """Connect By Name with zero-length Service Name

        Send an SNL PDU to the IUT's service discovery component with
        a single SDREQ that contains a zero-length service name. The
        IUT is expected to return the SAP value zero.

        """
        self.exec_TC_CTO_TAR_BI_03_x(llc, x=2)
    
    def prep_TC_CTO_TAR_BI_03_3(self, llc):
        return self.prep_TC_CTO_TAR_BI_03_x(llc)
        
    def test_TC_CTO_TAR_BI_03_3(self, llc):
        """Connect By Name with SN TLV empty value field

        Send an SNL PDU to the IUT's service discovery component with
        a single SDREQ that contains an empty service name field. The
        IUT is expected to return the SAP value zero.

        """
        self.exec_TC_CTO_TAR_BI_03_x(llc, x=3)
    
    def prep_TC_CTO_TAR_BI_03_4(self, llc):
        return self.prep_TC_CTO_TAR_BI_03_x(llc)
        
    def test_TC_CTO_TAR_BI_03_4(self, llc):
        """Connect By Name without Service Name TLV

        Send an SNL PDU to the IUT's service discovery component
        without data (SDREQ or SDRES) in the information field. The
        IUT is expected to not respond.

        """
        self.exec_TC_CTO_TAR_BI_03_x(llc, x=4)
    
    def prep_TC_CTO_TAR_BI_03_5(self, llc):
        return self.prep_TC_CTO_TAR_BI_03_x(llc)
        
    def test_TC_CTO_TAR_BI_03_5(self, llc):
        """Connect By Name without Service Name TLV

        Send an SNL PDU to the IUT's service discovery component with
        a valid and available service name but a length value that
        covers only the leading 'urn:nfc:sn:' part of the name. The
        IUT is expected to return the SAP value zero.

        """
        self.exec_TC_CTO_TAR_BI_03_x(llc, x=5)
    
    def prep_TC_CTO_TAR_BI_03_x(self, llc):
        llc.sap[1] = None # remove SDP
        return llc
        
    def exec_TC_CTO_TAR_BI_03_x(self, llc, x):
        data = {
            1: struct.pack('!BBB14s', 8, 15, 1, b'urn:nfc:void\x0d\x0a'),
            2: struct.pack('!BBB11s', 8, 12, 1, b'urn:nfc:sn:'),
            3: struct.pack('!BBB',    8,  1, 1),
            4: b'',
            5: struct.pack('!BBB25s', 8, 12, 1, b'urn:nfc:sn:dta-co-echo-in'),
            # TC Note: For x=5 the service name should be a valid
            # service name that is made invalid by the length byte.
            # TC Note: For x=5 the result must be same as x=1,2,3 not 4.
        }
        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        socket.bind(1) # bind to SDP address
        
        info("send SNL PDU with payload '%s'", hexstr(data[x], ':'))
        pdu = {'ptype': 0b1001, 'dsap': 1, 'ssap': 1, 'payload': data[x]}
        pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(**pdu)
        socket.send(pdu)

        if x == 4:
            raw_access_point_wait_no_recv(socket)
        else:
            pdu = raw_access_point_wait_recv(socket)
            assert pdu.name == "SNL", "expected SNL PDU not %s" % pdu.name
            assert len(pdu.sdres) > 0, "expected one SDRES not zero"
            assert len(pdu.sdres) < 2, "expected one SDRES not more"
            assert pdu.sdres[0][0] == 1, "wrong transaction identifier"
            assert pdu.sdres[0][1] == 0, "returned SAP is not zero"

        payload = struct.pack('!BBB25s', 8, 26, 1, b'urn:nfc:sn:dta-co-echo-in')
        info("send SNL PDU to resolve urn:nfc:sn:dta-co-echo-in")
        pdu = {'ptype': 0b1001, 'dsap': 1, 'ssap': 1, 'payload': payload}
        pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(**pdu)
        socket.send(pdu)

        pdu = raw_access_point_wait_recv(socket)
        assert pdu.name == "SNL", "expected SNL PDU not %s" % pdu.name
        assert len(pdu.sdres) > 0, "expected one SDRES not zero"
        assert len(pdu.sdres) < 2, "expected one SDRES not more"
        assert pdu.sdres[0][0] == 1, "wrong transaction identifier"
        assert pdu.sdres[0][1] != 0, "returned SAP is zero (service not found)"
        assert pdu.sdres[0][1] > 15, "returned SAP is in well-known range"

    def test_TC_CTO_INI_BV_02(self, llc):
        """IUT connection establishment with parameters in CONNECT
        """
        iut_co_in_sap, lt_co_in_sap = self.iut_co_in_sap, self.lt_co_in_sap
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        send_socket.bind(lt_co_in_sap)

        self.dta_co_echo_out.listen(backlog=1)

        info("connect to echo server at sap %d", iut_co_in_sap)
        pdu = nfc.llcp.pdu.Connect(dsap=iut_co_in_sap, ssap=lt_co_in_sap)
        send_socket.send(pdu)

        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "CC", "expected CC PDU but got %s" % pdu.name

        recv_socket = self.dta_co_echo_out.accept()
        data_link_connection_wait_no_recv(recv_socket, timeout=1.0)

        pdu = nfc.llcp.pdu.Disconnect(dsap=iut_co_in_sap, ssap=lt_co_in_sap)
        send_socket.send(pdu)

        pdu = raw_access_point_wait_recv(send_socket, timeout=5.0)
        assert pdu.name == "DM", "expected DM PDU but got %s" % pdu.name

        recv_socket.poll("recv", 5)
        assert recv_socket._tco.state.SHUTDOWN, "outbound connection not closed"
        
        info("test completed")
        send_socket.close()
        recv_socket.close()
    
if __name__ == '__main__':
    TestProgram().run()
