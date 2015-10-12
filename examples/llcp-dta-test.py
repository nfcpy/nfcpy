#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
log = logging.getLogger('main')

import os
import sys
import time
import errno
import struct
import argparse
from threading import Thread

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface, TestError

import nfc
import nfc.llcp
import nfc.llcp.pdu

default_miu = 128

def info(message, prefix="  "):
    log.info(prefix + message)

description = """
Execute some Logical Link Control Protocol (LLCP) tests. The peer
device must have the LLCP validation test servers running.
"""

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
        if len(self.options.test) > 0:
            test_list = self.options.test[:]
            if test_list[0] != '0_0_00_PREPARE':
                test_list = ['0_0_00_PREPARE'] + test_list
            for test in test_list:
                log.info("*** START ***")
                if '_INI_' in test:
                    self.options.mode = 'initiator'
                elif '_TAR_' in test:
                    self.options.mode = 'target'
                self.options.test = [test]
                self.run_once()
                time.sleep(1)
        else:
            log.error("no tests specified - nothing to do")

    def on_llcp_startup(self, llc):
        self.llc_exchange_sent = dict()
        self.llc_exchange_rcvd = dict()
        self.on_llc_exchange_call = None
        self.on_llc_exchange_exit = None
        self.wrapped_llc_exchange = llc.exchange
        llc.exchange = self.llc_exchange_wrapper
        func_name = "prep_{0}".format(self.options.test[0])
        try: on_startup = eval("self." + func_name)
        except AttributeError: pass
        else: llc = on_startup(llc)
        if llc:
            socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
            socket.bind('urn:nfc:sn:dta-cl-echo-out')
            self.dta_cl_echo_out = socket
            socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
            socket.bind('urn:nfc:sn:dta-co-echo-out')
            self.dta_co_echo_out = socket
        return llc

    def llc_exchange_wrapper(self, send_pdu, timeout):
        if self.on_llc_exchange_call:
            send_pdu = self.on_llc_exchange_call(send_pdu, timeout)
        rcvd_pdu = self.wrapped_llc_exchange(send_pdu, timeout)
        if send_pdu:
            self.llc_exchange_sent[send_pdu.name] \
                = self.llc_exchange_sent.setdefault(send_pdu.name, 0) + 1
        if rcvd_pdu:
            self.llc_exchange_rcvd[rcvd_pdu.name] \
                = self.llc_exchange_rcvd.setdefault(rcvd_pdu.name, 0) + 1
        if self.on_llc_exchange_exit:
            rcvd_pdu = self.on_llc_exchange_exit(rcvd_pdu)
        return rcvd_pdu
        
    def on_llcp_connect(self, llc):
        func_name = "init_{0}".format(self.options.test[0])
        try: on_connect = eval("self." + func_name)
        except AttributeError: pass
        else: llc = on_connect(llc)
        return super(TestProgram, self).on_llcp_connect(llc)

    def test_0_0_00_PREPARE(self, llc):
        """Dummy Test to determine IUT Parameters"""
        self.iut_miu = llc.cfg['send-miu']
        log.info("IUT MIU = %d", self.iut_miu)
        log.info("IUT LTO = %d", llc.cfg['recv-lto'])
        self.iut_sap_cl_in_dest = llc.resolve("urn:nfc:sn:dta-cl-echo-in")
        log.info("CL ADDR = %d", self.iut_sap_cl_in_dest)
        self.iut_sap_co_in_dest = llc.resolve("urn:nfc:sn:dta-co-echo-in")
        log.info("CO ADDR = %d", self.iut_sap_co_in_dest)
    
    def prep_2_1_01_TC_CTL_UND_BV_01(self, llc):
        if self.iut_miu == 128:
            log.error("TC_CTL_UND_BV_01 requires IUT MIU more than 128")
        else:
            llc.cfg['recv-miu'] = self.iut_miu - 1
            llc.cfg['send-lto'] = 1000
            return llc

    def test_2_1_01_TC_CTL_UND_BV_01(self, llc):
        """Connectionless Transport Maximum Size of Information Field"""
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        try:
            dta_cl_echo_in = socket.resolve("urn:nfc:sn:dta-cl-echo-in")
            socket.sendto(b'SOT', dta_cl_echo_in)
            socket.sendto(b'\x00' * (self.iut_miu - 1), dta_cl_echo_in)
            if not self.dta_cl_echo_out.poll("recv", timeout=5):
                raise TestError("expected but got no data within 5 seconds")
            data, addr = self.dta_cl_echo_out.recvfrom()
            log.info("received %d byte from sap %d", len(data), addr)
            socket.sendto(b'\x00' * self.iut_miu, dta_cl_echo_in)
            if self.dta_cl_echo_out.poll("recv", timeout=5):
                raise TestError("expected none but got data within 5 seconds")
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            socket.close()

    def prep_2_1_02_TC_CTL_UND_BI_01(self, llc):
        llc.cfg['recv-miu'] = self.iut_miu
        llc.cfg['send-lto'] = 1000
        return llc

    def init_2_1_02_TC_CTL_UND_BI_01(self, llc):
        llc.cfg['send-miu'] += 1
        return llc
    
    def test_2_1_02_TC_CTL_UND_BI_01(self, llc):
        """Connectionless Transport Maximum Information Unit Exceeded"""
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        try:
            dta_cl_echo_in = socket.resolve("urn:nfc:sn:dta-cl-echo-in")
            socket.sendto(b'SOT', dta_cl_echo_in)
            socket.sendto(b'\x00' * self.iut_miu, dta_cl_echo_in)
            if not self.dta_cl_echo_out.poll("recv", timeout=5):
                raise TestError("expected but got no data within 5 seconds")
            data, addr = self.dta_cl_echo_out.recvfrom()
            log.info("received %d byte from sap %d", len(data), addr)
            socket.sendto(b'\x00' * (self.iut_miu + 1), dta_cl_echo_in)
            if self.dta_cl_echo_out.poll("recv", timeout=5):
                raise TestError("expected none but got data within 5 seconds")
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            socket.close()

    def prep_2_1_03_TC_CTL_UND_BV_02(self, llc):
        llc.cfg['recv-miu'] = self.iut_miu
        llc.cfg['send-lto'] = 1000
        return llc
    
    def test_2_1_03_TC_CTL_UND_BV_02(self, llc):
        """Connectionless Transport No Reception Acknowledgement"""
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        try:
            dta_cl_echo_in = socket.resolve("urn:nfc:sn:dta-cl-echo-in")
            socket.sendto(b'SOT', dta_cl_echo_in)
            socket.sendto(b'\x00' * self.iut_miu, dta_cl_echo_in)
            if socket.poll("recv", timeout=5):
                raise TestError("received data on SAP[LT,CL-IN-SRC]")
            if not self.dta_cl_echo_out.poll("recv", timeout=0):
                raise TestError("received no data on SAP[LT,CL-OUT-DEST]")
            data, addr = self.dta_cl_echo_out.recvfrom()
            log.info("received %d byte from sap %d", len(data), addr)
            if data != b'\x00' * self.iut_miu:
                raise TestError("received wrong data on SAP[LT,CL-OUT-DEST]")
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            socket.close()
    
    def prep_2_1_04_TC_CTL_UND_BI_02(self, llc):
        if self.iut_miu == 2175:
            log.error("TC_CTL_UND_BI_02 requires IUT MIU less than 2175")
        else:
            llc.cfg['recv-miu'] = self.iut_miu + 1
            llc.cfg['send-lto'] = 1000
            return llc

    def init_2_1_04_TC_CTL_UND_BI_02(self, llc):
        llc.cfg['send-miu'] += 1
        return llc
    
    def test_2_1_04_TC_CTL_UND_BI_02(self, llc):
        """Connectionless Transport No Acknowledgement for Invalid Frames"""
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        try:
            dta_cl_echo_in = socket.resolve("urn:nfc:sn:dta-cl-echo-in")
            socket.sendto(b'SOT', dta_cl_echo_in)
            socket.sendto(b'\x00' * (self.iut_miu + 1), dta_cl_echo_in)
            log.info("wait 5 seconds to not receive UI PDU response")
            if self.dta_cl_echo_out.poll("recv", timeout=5):
                raise TestError("expected none but got data within 5 seconds")
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            socket.close()

        socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)        
        try:
            rcvd_snl_count = self.llc_exchange_rcvd.get("SNL", 0)
            socket.send(nfc.llcp.pdu.ServiceNameLookup(1, 1))
            log.info("wait 5 seconds to not receive SNL PDU response")
            time.sleep(5)
            if not self.llc_exchange_rcvd.get("SNL", 0) == rcvd_snl_count:
                raise TestError("received SNL PDU response")
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            self.on_llc_exchange_exit = None
            socket.close()

    def test_3_1_01_TC_CTO_TAR_BV_01_1(self, llc):
        """Connection Establishment with Specific SAP and no Parameters"""
        self.exec_3_1_01_TC_CTO_TAR_BV_01_x(llc, x=1)

    def test_3_1_01_TC_CTO_TAR_BV_01_2(self, llc):
        """Connection Establishment with Specific SAP and MIUX"""
        self.exec_3_1_01_TC_CTO_TAR_BV_01_x(llc, x=2)

    def test_3_1_01_TC_CTO_TAR_BV_01_3(self, llc):
        """Connection Establishment with Specific SAP and RW=0Xh"""
        self.exec_3_1_01_TC_CTO_TAR_BV_01_x(llc, x=3)

    def test_3_1_01_TC_CTO_TAR_BV_01_4(self, llc):
        """Connection Establishment with Specific SAP and RW=FXh"""
        self.exec_3_1_01_TC_CTO_TAR_BV_01_x(llc, x=4)

    def test_3_1_01_TC_CTO_TAR_BV_01_5(self, llc):
        """Connection Establishment with Specific SAP and Service Name"""
        self.exec_3_1_01_TC_CTO_TAR_BV_01_x(llc, x=5)

    def test_3_1_01_TC_CTO_TAR_BV_01_6(self, llc):
        """Connection Establishment with Specific SAP and MIUX,RW,SN"""
        self.exec_3_1_01_TC_CTO_TAR_BV_01_x(llc, x=6)

    def test_3_1_01_TC_CTO_TAR_BV_01_7(self, llc):
        """Connection Establishment with Specific SAP and Undefined TLV"""
        self.exec_3_1_01_TC_CTO_TAR_BV_01_x(llc, x=7)

    def exec_3_1_01_TC_CTO_TAR_BV_01_x(self, llc, x):
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        recv_socket = None
        payload = {
            1: b'',
            2: struct.pack('!BBH', 2, 2, self.iut_miu),
            3: struct.pack('!BBB', 5, 1, 0x05),
            4: struct.pack('!BBB', 5, 1, 0xF9),
            5: struct.pack('!BB25s', 6, 25, b'urn:nfc:sn:dta-co-echo-in'),
            7: struct.pack('!BBB', 254, 1, 0),
        }
        payload[6] = payload[2] + payload[3] + payload[5]
        try:
            self.dta_co_echo_out.listen(backlog=1)
            pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(
                0b0100, self.iut_sap_co_in_dest, 0x20, payload[x])
            send_socket.send(pdu)
            pdu = send_socket.recv()
            if not pdu.name == "CC":
                raise TestError("expected CC PDU but got %s" % pdu.name)
            recv_socket = self.dta_co_echo_out.accept()
            time.sleep(1)
            pdu = nfc.llcp.pdu.Disconnect(self.iut_sap_co_in_dest, 0x20)
            send_socket.send(pdu)
            pdu = send_socket.recv()
            if not pdu.name == "DM":
                raise TestError("expected DM PDU but got %s" % pdu.name)
            recv_socket.poll("recv", 5)
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            if send_socket: send_socket.close()
            if recv_socket: recv_socket.close()
    
    def test_3_1_02_TC_CTO_TAR_BV_02(self, llc):
        """Connection Establishment with Service Name to SAP 1"""
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        recv_socket = None
        payload = struct.pack('!BB25s', 6, 25, b'urn:nfc:sn:dta-co-echo-in')
        try:
            self.dta_co_echo_out.listen(backlog=1)
            pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(4, 1, 32, payload)
            send_socket.send(pdu)
            pdu = send_socket.recv()
            if not pdu.name == "CC":
                raise TestError("expected CC PDU but got %s" % pdu.name)
            if not pdu.ssap == self.iut_sap_co_in_dest:
                errstr = "expected CC SSAP=%d and not %ds"
                raise TestError(errstr % (self.iut_sap_co_in_dest, pdu.ssap))
            recv_socket = self.dta_co_echo_out.accept()
            time.sleep(1)
            pdu = nfc.llcp.pdu.Disconnect(self.iut_sap_co_in_dest, 32)
            send_socket.send(pdu)
            pdu = send_socket.recv()
            if not pdu.name == "DM":
                raise TestError("expected DM PDU but got %s" % pdu.name)
            recv_socket.poll("recv", 5)
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            if send_socket: send_socket.close()
            if recv_socket: recv_socket.close()
    
    def test_3_1_03_TC_CTO_TAR_BV_03(self, llc):
        """Connection Establishment Using Service Discovery"""
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        recv_socket = None
        try:
            self.dta_co_echo_out.listen(backlog=1)
            dsap = llc.resolve('urn:nfc:sn:dta-co-echo-in')
            if not dsap == self.iut_sap_co_in_dest:
                errstr = "expected 'dta-co-echo-in' DSAP=%d and not %ds"
                raise TestError(errstr % (self.iut_sap_co_in_dest, dsap))
            pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(4, dsap, 32, b'')
            send_socket.send(pdu)
            pdu = send_socket.recv()
            if not pdu.name == "CC":
                raise TestError("expected CC PDU but got %s" % pdu.name)
            if not pdu.ssap == self.iut_sap_co_in_dest:
                errstr = "expected CC SSAP=%d and not %ds"
                raise TestError(errstr % (self.iut_sap_co_in_dest, pdu.ssap))
            recv_socket = self.dta_co_echo_out.accept()
            time.sleep(1)
            pdu = nfc.llcp.pdu.Disconnect(self.iut_sap_co_in_dest, 32)
            send_socket.send(pdu)
            pdu = send_socket.recv()
            if not pdu.name == "DM":
                raise TestError("expected DM PDU but got %s" % pdu.name)
            recv_socket.poll("recv", 5)
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            if send_socket: send_socket.close()
            if recv_socket: recv_socket.close()
    
    def test_3_1_04_TC_CTO_TAR_BI_01(self, llc):
        """Target Errors in CONNECT PDU No Service Bound to SAP"""
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        try:
            pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(4, 16, 63, b'')
            send_socket.bind(pdu.ssap)
            send_socket.send(pdu)
            if not send_socket.poll('recv', timeout=5):
                raise TestError("no response within 5 seconds")
            pdu = send_socket.recv()
            if not pdu.name == "DM":
                raise TestError("expected DM PDU but got %s" % pdu.name)
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            if send_socket: send_socket.close()
    
    def test_3_1_05_TC_CTO_TAR_BI_02_1(self, llc):
        """Connect By Name with malformed Service Name URI"""
        self.exec_3_1_05_TC_CTO_TAR_BI_02_x(llc, x=1)
    
    def test_3_1_05_TC_CTO_TAR_BI_02_2(self, llc):
        """Connect By Name with zero-length Service Name"""
        self.exec_3_1_05_TC_CTO_TAR_BI_02_x(llc, x=2)
    
    def test_3_1_05_TC_CTO_TAR_BI_02_3(self, llc):
        """Connect By Name with SN TLV empty value field"""
        self.exec_3_1_05_TC_CTO_TAR_BI_02_x(llc, x=3)
    
    def test_3_1_05_TC_CTO_TAR_BI_02_4(self, llc):
        """Connect By Name without Service Name TLV"""
        self.exec_3_1_05_TC_CTO_TAR_BI_02_x(llc, x=4)
    
    def exec_3_1_05_TC_CTO_TAR_BI_02_x(self, llc, x):
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
        payload = {
            1: struct.pack('!BB14s', 8, 14, b'urn:nfc:void\x0d\x0a'),
            2: struct.pack('!BB11s', 6, 11, b'urn:nfc:sn:'),
            3: struct.pack('!BB', 6, 0),
            4: b''
        }
        try:
            pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(4, 1, 63, payload[x])
            send_socket.bind(pdu.ssap)
            send_socket.send(pdu)
            if not send_socket.poll('recv', timeout=1):
                raise TestError("no response within 1 second")
            pdu = send_socket.recv()
            if not pdu.name == "DM":
                raise TestError("expected DM PDU not %s" % pdu.name)
            if not pdu.reason in {1: (2,), 2: (2,), 3: (2,), 4: (3, 16)}[x]:
                raise TestError("disconnected mode reason %d" % pdu.reason)
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            if send_socket: send_socket.close()

    def prep_3_1_06_TC_CTO_TAR_BI_03_1(self, llc):
        llc.sap[1] = None; return llc
        
    def test_3_1_06_TC_CTO_TAR_BI_03_1(self, llc):
        """Service Discovery with malformed Service Name URI"""
        self.exec_3_1_06_TC_CTO_TAR_BI_03_x(llc, x=1)
    
    def prep_3_1_06_TC_CTO_TAR_BI_03_2(self, llc):
        llc.sap[1] = None; return llc
        
    def test_3_1_06_TC_CTO_TAR_BI_03_2(self, llc):
        """Connect By Name with zero-length Service Name"""
        self.exec_3_1_06_TC_CTO_TAR_BI_03_x(llc, x=2)
    
    def prep_3_1_06_TC_CTO_TAR_BI_03_3(self, llc):
        llc.sap[1] = None; return llc
        
    def test_3_1_06_TC_CTO_TAR_BI_03_3(self, llc):
        """Connect By Name with SN TLV empty value field"""
        self.exec_3_1_06_TC_CTO_TAR_BI_03_x(llc, x=3)
    
    def prep_3_1_06_TC_CTO_TAR_BI_03_4(self, llc):
        llc.sap[1] = None; return llc
        
    def test_3_1_06_TC_CTO_TAR_BI_03_4(self, llc):
        """Connect By Name without Service Name TLV"""
        self.exec_3_1_06_TC_CTO_TAR_BI_03_x(llc, x=4)
    
    def exec_3_1_06_TC_CTO_TAR_BI_03_x(self, llc, x):
        payload = {
            1: struct.pack('!BBB14s', 8, 15, 1, b'urn:nfc:void\x0d\x0a'),
            2: struct.pack('!BBB11s', 8, 12, 1, b'urn:nfc:sn:'),
            3: struct.pack('!BBB', 8, 1, 1),
            4: b''
        }
        send_pdu = nfc.llcp.pdu.UnknownProtocolDataUnit(9, 1, 1, payload[x])
        try:
            send_socket = nfc.llcp.Socket(llc, nfc.llcp.llc.RAW_ACCESS_POINT)
            send_socket.bind(send_pdu.ssap)
            send_socket.send(send_pdu)
            if not send_socket.poll('recv', timeout=1):
                if x == 4: return
                raise TestError("no response within 1 second")
            rcvd_pdu = send_socket.recv()
            if not rcvd_pdu.name == "SNL":
                raise TestError("expected SNL PDU not %s" % rcvd_pdu.name)
            if not pdu.sdres == [(1, 0)]:
                raise TestError("expected SDRES[(1, 0)] not %r"%rcvd_pdu.sdres)
        except nfc.llcp.Error as error:
            raise TestError(repr(error))
        finally:
            if send_socket: send_socket.close()
    
if __name__ == '__main__':
    TestProgram().run()
