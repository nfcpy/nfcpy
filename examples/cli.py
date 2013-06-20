#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

import os
import sys
import time
import os.path
import inspect
import argparse
import itertools
from threading import Thread

import nfc

class TestError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return str(self.value)

class CommandLineInterface(object):
    def __init__(self, argument_parser, groups=None):
        if groups is None:
            groups = "dbg p2p clf iop"
        self.groups = groups.split()
        for group in self.groups:
            eval("self.add_{0}_options".format(group))(argument_parser)
        
        argument_parser.add_argument(
            "-l", "--loop", action="store_true",
            help="restart after termination")
        
        self.options = argument_parser.parse_args()

        if "tst" in self.groups and self.options.test_all:
            self.options.test = []
            for i in itertools.count(1, 1):
                try: eval("self.test_{0:02d}".format(i))
                except AttributeError: break
                else: self.options.test.append(i)

        logformat = '%(message)s'
        verbosity = logging.ERROR if self.options.quiet else logging.INFO
        
        if self.options.debug:
            logformat = '%(levelname)-5s [%(name)s] %(message)s'
            if '' in self.options.debug:
                verbosity = logging.DEBUG
        
        logging.basicConfig(level=verbosity, format=logformat)

        if self.options.debug and 'nfc' in self.options.debug:
            verbosity = logging.DEBUG
            
        if self.options.logfile:
            logfile_format = \
                '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
            logfile = logging.FileHandler(self.options.logfile, "w")
            logfile.setFormatter(logging.Formatter(logfile_format))
            logfile.setLevel(logging.DEBUG)
            logging.getLogger('').addHandler(logfile)

        nfcpy_path = os.path.dirname(inspect.getfile(nfc))
        for name in os.listdir(nfcpy_path):
            if os.path.isdir(os.path.join(nfcpy_path, name)):
                logging.getLogger("nfc."+name).setLevel(verbosity)
            elif name.endswith(".py") and name != "__init__.py":
                logging.getLogger("nfc."+name[:-3]).setLevel(verbosity)
            
        if self.options.debug:
            for module in self.options.debug:
                log.info("enable debug output for module '{0}'".format(module))
                logging.getLogger(module).setLevel(logging.DEBUG)

    def add_dbg_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Debug options")
        group.add_argument(
            "-q", "--quiet", dest="quiet", action="store_true",
            help="do not print anything except errors")
        group.add_argument(
            "-d", metavar="MODULE", dest="debug", action="append",
            help="print debug messages for MODULE, use '' for all")
        group.add_argument(
            "-f", dest="logfile", metavar="FILE",
            help="write log messages to file")
        
    def add_p2p_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="P2P Options")
        group.add_argument(
            "--mode", choices=["t","target","i","initiator"], metavar="{t,i}",
            help="connect as 'target' or 'initiator' (default: both)")
        group.add_argument(
            "--miu", dest="miu", metavar="INT", type=int, default=1024,
            help="set LLCP Link MIU (default: %(default)s octets)")
        group.add_argument(
            "--lto", metavar="INT", type=int, default=500,
            help="set LLCP Link Timeout (default: %(default)s ms)")
        group.add_argument(
            "--listen-time", metavar="INT", type=int, default=250,
            help="set time to listen as target (default: %(default)s ms)")
        group.add_argument(
            "--no-aggregation", action="store_true",
            help="disable outbound packet aggregation")

    def add_tag_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="R/W options")
        group.add_argument(
            "--no-wait", dest="wait", action="store_false",
            help="wait for tag removal before return")

    def add_clf_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Device options")
        group.add_argument(
            "--device", metavar="NAME", action="append",
            help="use specified contactless reader(s): "\
                "usb[:vendor[:product]] (vendor and product in hex), "\
                "usb[:bus[:dev]] (bus and device number in decimal), "\
                "tty[:(usb|com)[:port]] (usb virtual or com port)")
        
    def add_iop_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="IOP options")
        group.add_argument(
            "--quirks", action="store_true",
            help="support non-compliant implementations")
        
    def add_tst_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Test options")
        group.add_argument(
            "-t", "--test", type=int, default=[], action="append",
            metavar="N", help="run test number <N>")
        group.add_argument(
            "-T", "--test-all", action="store_true",
            help="run all available tests")
        argument_parser.description += "\nTests:\n"
        for test_name in [m for m in dir(self) if m.startswith("test_")]:
            test_func = eval("self."+test_name)
            test_info = test_func.__doc__.splitlines()[0]
            argument_parser.description += "  {0:2d} - {1}\n".format(
                int(test_name.split('_')[1]), test_info)
        
    def on_tag_connect(self, llc):
        log.info(tag)
        return True

    def on_p2p_startup(self, llc):
        if "tst" in self.groups and len(self.options.test) == 0:
            log.error("no test specified")
            return False
        return True
    
    def on_p2p_connect(self, llc):
        if "tst" in self.groups:
            self.test_completed = False
            Thread(target=self.run_tests, args=(llc,)).start()
            llc.run(terminate=self.terminate)
        return True

    def terminate(self):
        return self.test_completed

    def run_tests(self, llc):
        if len(self.options.test) > 1:
            log.info("run tests: {0}".format(self.options.test))
        for test in self.options.test:
            test_name = "test_{0:02d}".format(test)
            try:
                test_func = eval("self." + test_name)
            except AttributeError:
                log.error("invalid test number '{0}'".format(test))
                continue
            test_info = test_func.__doc__.splitlines()[0]
            test_name = test_name.capitalize().replace('_', ' ')
            print("{0}: {1}".format(test_name, test_info))
            try:
                test_func(llc)
            except TestError as error:
                print("Test {N:02d}: FAIL ({E})".format(N=test, E=error))
            else:
                print("{0}: PASS".format(test_name))
            if self.options.test.index(test) < len(self.options.test) - 1:
                time.sleep(1)
        self.test_completed = True

    def run_once(self):
        if self.options.device is None:
            self.options.device = ['']
            
        for device in self.options.device:
            try: clf = nfc.ContactlessFrontend(device)
            except LookupError: pass
            else: break
        else:
            log.info("no contactless frontend found")
            raise SystemExit(1)

        if self.options.mode is None:
            self.options.role = None
        elif self.options.mode in ('t', 'target'):
            self.options.role = 'target'
        elif self.options.mode in ('i', 'initiator'):
            self.options.role = 'initiator'
        
        tag_options = {
            'on-connect': self.on_tag_connect,
            }

        p2p_options = {
            'on-startup': self.on_p2p_startup,
            'on-connect': self.on_p2p_connect,
            'role': self.options.role,
            'miu': self.options.miu,
            'lto': self.options.lto,
            'agf': not self.options.no_aggregation,
            }

        try:
            return clf.connect(p2p=p2p_options, tag=tag_options)
        finally:
            clf.close()
            
    def run(self):
        while self.run_once() and self.options.loop:
            log.info("*** RESTART ***")
            pass
