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
log = logging.getLogger('main')

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
    def __init__(self, argument_parser, groups=''):
        self.groups = groups.split()
        for group in self.groups:
            eval("self.add_{0}_options".format(group))(argument_parser)
        
        argument_parser.add_argument(
            "-l", "--loop", action="store_true",
            help="restart after termination")
        
        self.options = argument_parser.parse_args()

        ch = logging.StreamHandler()
        lv = logging.ERROR if self.options.quiet else logging.DEBUG
        lv = logging.INFO if self.options.logfile else lv
        ch.setLevel(lv)
        ch.setFormatter(logging.Formatter('[%(name)s] %(message)s'))
        logging.getLogger().addHandler(ch)

        if self.options.logfile:
            fmt = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
            fh = logging.FileHandler(self.options.logfile, "w")
            fh.setFormatter(logging.Formatter(fmt))
            fh.setLevel(logging.DEBUG)
            logging.getLogger().addHandler(fh)

        logging.getLogger().setLevel(logging.NOTSET)
        logging.getLogger('main').setLevel(logging.INFO)
        for module in self.options.debug:
            log.info("enable debug output for module '{0}'".format(module))
            logging.getLogger(module).setLevel(logging.DEBUG)
        
        log.debug(self.options)
        
        if "test" in self.groups and self.options.test_all:
            self.options.test = []
            for test_name in [m for m in dir(self) if m.startswith("test_")]:
                self.options.test.append(int(test_name.split('_')[1]))
        
    def add_dbg_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Debug Options")
        group.add_argument(
            "-q", "--quiet", dest="quiet", action="store_true",
            help="do not print anything except errors")
        group.add_argument(
            "-d", metavar="MODULE", dest="debug", action="append",
            default=list(),
            help="enable debug log for MODULE (main, nfc.clf, ...)")
        group.add_argument(
            "-f", dest="logfile", metavar="LOGFILE",
            help="write debug logs to LOGFILE")
        group.add_argument(
            "--nolog-symm", action="store_true",
            help="do not log LLCP SYMM PDUs")
        
    def add_llcp_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Peer Mode Options")
        group.add_argument(
            "--mode", choices=["t","target","i","initiator"], metavar="{t,i}",
            help="connect as 'target' or 'initiator' (default: both)")
        group.add_argument(
            "--miu", dest="miu", metavar="INT", type=int, default=2175,
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

    def add_rdwr_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Reader Mode Options")
        group.add_argument(
            "--wait", action="store_true",
            help="wait until tag removed (implicit with '-l')")

    def add_card_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Card Mode Options")

    def add_clf_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Device Options")
        group.add_argument(
            "--device", metavar="PATH", action="append",
            help="use contactless reader at: "\
                "'usb[:vid[:pid]]' (with vendor and product id), "\
                "'usb[:bus[:dev]]' (with bus and device number), "\
                "'tty:port:driver' (with /dev/tty<port> and <driver>), "\
                "'com:port:driver' (with COM<port> and <driver>), "\
                "'udp[:host[:port]]' (with <host> name/addr and <port> number)")
        
    def add_iop_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Interoperability Options")
        group.add_argument(
            "--quirks", action="store_true",
            help="support non-compliant implementations")
        
    def add_test_options(self, argument_parser):
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
        
    def on_rdwr_startup(self, clf, targets):
        return targets

    def on_rdwr_connect(self, tag):
        log.info(tag)
        return True

    def on_llcp_startup(self, clf, llc):
        if "test" in self.groups and len(self.options.test) == 0:
            log.error("no test specified")
            return None
        return llc
    
    def on_llcp_connect(self, llc):
        if "test" in self.groups:
            self.test_completed = False
            Thread(target=self.run_tests, args=(llc,)).start()
            llc.run(terminate=self.terminate)
            return False
        return True

    def on_card_startup(self, clf, targets):
        log.warning("on_card_startup should be customized")
        return targets

    def on_card_connect(self, tag, command):
        log.info("activated as {0}".format(tag))
        if "test" in self.groups:
            self.test_completed = False
            self.run_tests(tag, command)
            return False
        return True

    def on_card_release(self, tag):
        return True

    def terminate(self):
        return self.test_completed

    def run_tests(self, *args):
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
                test_func(*args)
            except TestError as error:
                print("Test {N:02d}: FAIL ({E})".format(N=test, E=error))
            else:
                print("{0}: PASS".format(test_name))
            if self.options.test.index(test) < len(self.options.test) - 1:
                time.sleep(1)
        self.test_completed = True

    def run_once(self):
        if self.options.device is None:
            self.options.device = ['usb']
            
        for device in self.options.device:
            try: clf = nfc.ContactlessFrontend(device)
            except IOError: pass
            else: break
        else:
            log.error("no contactless reader found")
            raise SystemExit(1)

        if "rdwr" in self.groups:
            rdwr_options = {
                'on-startup': self.on_rdwr_startup,
                'on-connect': self.on_rdwr_connect,
                }
        else:
            rdwr_options = None
        
        if "llcp" in self.groups:
            if self.options.mode is None:
                self.options.role = None
            elif self.options.mode in ('t', 'target'):
                self.options.role = 'target'
            elif self.options.mode in ('i', 'initiator'):
                self.options.role = 'initiator'
            llcp_options = {
                'on-startup': self.on_llcp_startup,
                'on-connect': self.on_llcp_connect,
                'role': self.options.role,
                'miu': self.options.miu,
                'lto': self.options.lto,
                'agf': not self.options.no_aggregation,
                'symm-log': not self.options.nolog_symm,
                }
        else:
            llcp_options = None
            
        if "card" in self.groups:
            card_options = {
                'on-startup': self.on_card_startup,
                'on-connect': self.on_card_connect,
                'on-release': self.on_card_release,
                'targets': [],
                }
        else:
            card_options = None

        try:
            kwargs = {'llcp': llcp_options,
                      'rdwr': rdwr_options,
                      'card': card_options}
            return clf.connect(**kwargs)
        finally:
            clf.close()
            
    def run(self):
        while self.run_once() and self.options.loop:
            log.info("*** RESTART ***")
