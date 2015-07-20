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

import os, sys, errno, time, argparse
from threading import Thread
import nfc

def log_device_access_denied(path):
    log.info("access denied for device with path " + path)
    if path.split(':')[0] == "usb": log_usb_device_access_denied(path)

def log_device_found_busy(path):
    log.info("the reader on " + path + " is busy")
    if path.split(':')[0] == "usb": log_usb_device_found_busy(path)

def log_usb_device_access_denied(path):
    # The path arguments is either 'usb:bus:dev' or 'usb:vid:pid'. For
    # the first form the length is 11 characters (bus and dev are 3
    # char decimal strings). For the second form the total length is
    # 13 (vid and pid are 4 char hex strings)
    if sys.platform.startswith("linux"):
        sysfs = '/sys/bus/usb/devices/'
        for d in os.listdir(sysfs):
            if d.startswith("usb") or ':' in d: continue
            vid = open(sysfs + d + '/idVendor').read().strip()
            pid = open(sysfs + d + '/idProduct').read().strip()
            bus = int(open(sysfs + d + '/busnum').read().strip())
            dev = int(open(sysfs + d + '/devnum').read().strip())
            if len(path) == 11 and [bus, dev] == map(int, path.split(':')[1:]):
                break
            if len(path) == 13 and [vid, pid] == path.split(':')[1:]:
                msg = "first match for path {path} is usb:{bus:03}:{dev:03}"
                log.info(msg.format(path=path, bus=bus, dev=dev))
                break
            
        devnode = "/dev/bus/usb/{0:03d}/{1:03d}".format(bus, dev)
        if not os.access(devnode, os.R_OK | os.W_OK):
            import pwd, grp
            username = pwd.getpwuid(os.getuid()).pw_name
            devinfo = os.stat(devnode)
            dev_usr = pwd.getpwuid(devinfo.st_uid).pw_name
            dev_grp = grp.getgrgid(devinfo.st_gid).gr_name
            msg = "usb:{bus:03}:{dev:03} is owned by {owner} but you are {usr}"
            log.info(msg.format(bus=bus, dev=dev, owner=dev_usr, usr=username))
            msg = "members of the {group} group may use usb:{bus:03}:{dev:03}"
            log.info(msg.format(bus=bus, dev=dev, group=dev_grp))
            groups = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]
            if "plugdev" in groups:
                msg = "you may want to add a udev rule to access this device"
                log.info(msg)
                udr = 'SUBSYSTEM==\\"usb\\", ACTION==\\"add\\", ' \
                      'ATTRS{{idVendor}}==\\"{vid}\\", ' \
                      'ATTRS{{idProduct}}==\\"{pid}\\", ' \
                      'GROUP=\\"plugdev\\"'.format(vid=vid, pid=pid)
                msg = "sudo sh -c 'echo {0} >> /etc/udev/rules.d/nfcdev.rules'"
                log.info(msg.format(udr))

def log_usb_device_found_busy(path):
    # The path arguments is either 'usb:bus:dev' or 'usb:vid:pid'. For
    # the first form the length is 11 characters (bus and dev are 3
    # char decimal strings). For the second form the total length is
    # 13 (vid and pid are 4 char hex strings)
    if sys.platform.startswith("linux"):
        sysfs = '/sys/bus/usb/devices/'
        for d in os.listdir(sysfs):
            if d.startswith("usb") or ':' in d: continue
            sysfs_device_entry = sysfs + d + '/'
            vid = open(sysfs_device_entry + 'idVendor').read().strip()
            pid = open(sysfs_device_entry + 'idProduct').read().strip()
            bus = int(open(sysfs_device_entry + 'busnum').read().strip())
            dev = int(open(sysfs_device_entry + 'devnum').read().strip())
            if len(path) == 11 and [bus, dev] == map(int, path.split(':')[1:]):
                break
            if len(path) == 13 and [vid, pid] == path.split(':')[1:]:
                msg = "first match for path {path} is usb:{bus:03}:{dev:03}"
                log.info(msg.format(path=path, bus=bus, dev=dev))
                break

        # We now have the sysfs entry for the device in question. All
        # known contactless devices have only a single configuration
        # and it will shown if a foreign driver has claimed the
        # device.
        sysfs_config_entry = sysfs_device_entry[:-1] + ":1.0/"
        if os.access(sysfs_config_entry + "nfc", os.F_OK):
            driver = os.readlink(sysfs_config_entry + "driver").split('/')[-1]
            msg = "device at usb:{bus:03}:{dev:03} used by {drv} kernel driver"
            log.info(msg.format(bus=bus, dev=dev, drv=driver))
            msg = "use 'sudo modprobe -r {drv}' to temporarily free the device"
            log.info(msg.format(drv=driver))
            msg = "you may want to blacklist the {drv} kernel driver"
            log.info(msg.format(drv=driver))
            msg = "echo blacklist {drv} >> /etc/modprobe.d/blacklist-nfc.conf"
            log.info("sudo sh -c '{0}'".format(msg.format(drv=driver)))
        elif os.access(sysfs_config_entry + "driver", os.F_OK):
            driver = os.readlink(sysfs_config_entry + "driver").split('/')[-1]
            msg = "device at usb:{bus:03}:{dev:03} used by {drv} kernel driver"
            log.info(msg.format(bus=bus, dev=dev, drv=driver))
            if driver == "usbfs":
                msg = "try 'sudo lsof /dev/bus/usb/{bus:03}/{dev:03}' " \
                      "to see which process is using the device"
                log.info(msg.format(bus, dev))

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

        lvl = logging.ERROR if self.options.quiet else logging.INFO
        if self.options.debug and not self.options.logfile:
            lvl = logging.DEBUG - (1 if self.options.verbose else 0)
        
        fmt = '[%(name)s] %(message)s'
        if self.options.reltime: fmt = '%(relativeCreated)d ms ' + fmt
        if self.options.abstime: fmt = '%(asctime)s ' + fmt
        
        ch = ColorStreamHandler()
        ch.setLevel(lvl)
        ch.setFormatter(logging.Formatter(fmt))
        logging.getLogger().addHandler(ch)

        if self.options.logfile:
            fmt = '%(asctime)s [%(name)s] %(message)s'
            fh = logging.FileHandler(self.options.logfile, "w")
            fh.setFormatter(logging.Formatter(fmt))
            fh.setLevel(logging.DEBUG - (1 if self.options.verbose else 0))
            logging.getLogger().addHandler(fh)

        logging.getLogger().setLevel(logging.NOTSET)
        logging.getLogger('main').setLevel(logging.INFO)
        for module in self.options.debug:
            log.info("enable debug output for '{0}'".format(module))
            logging.getLogger(module).setLevel(1)
        
        log.debug(self.options)
        
        if "test" in self.groups and self.options.test_all:
            self.options.test = []
            for test_name in [m for m in dir(self) if m.startswith("test_")]:
                self.options.test.append(int(test_name.split('_')[1]))
        
    def add_dbg_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Debug Options")
        group.add_argument(
            "-d", metavar="MODULE", dest="debug", action="append",
            default=list(),
            help="enable debug log for MODULE (main, nfc.clf, ...)")
        group.add_argument(
            "-v", "--verbose", action="store_true",
            help="show more information")
        group.add_argument(
            "-q", "--quiet", action="store_true",
            help="show less information")
        group.add_argument(
            "-f", dest="logfile", metavar="LOGFILE",
            help="write debug logs to LOGFILE (with date and time)")
        group.add_argument(
            "--reltime", action="store_true",
            help="show relative timestamps in screen log")
        group.add_argument(
            "--abstime", action="store_true",
            help="show absolute timestamps in screen log")
        
    def add_llcp_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Peer Mode Options")
        group.add_argument(
            "--miu", type=int, default=2175, metavar='',
            help="LLCP Link MIU octets (default: %(default)s octets)")
        group.add_argument(
            "--lto", type=int, default=500, metavar='',
            help="LLCP Link Timeout in ms (default: %(default)s ms)")
        group.add_argument(
            "--rwt", type=int, default=8, metavar='',
            help="response waiting time index (default: %(default)s)")
        group.add_argument(
            "--mode", choices=["t","target","i","initiator"], metavar='',
            help="connect as [t]arget or [i]nitiator (default: both)")
        group.add_argument(
            "--bitrate", type=int, default=424, metavar='',
            choices=(106, 212, 424),
            help="initiator bitrate 106/212/424 (default: %(default)s)")
        group.add_argument(
            "--passive-only", action="store_true",
            help="only passive mode activation when initiator")
        group.add_argument(
            "--listen-time", type=int, default=250, metavar='',
            help="target listen time in ms (default: %(default)s ms)")
        group.add_argument(
            "--no-aggregation", action="store_true",
            help="disable outbound packet aggregation")

    def add_rdwr_options(self, argument_parser):
        group = argument_parser.add_argument_group(
            title="Reader Mode Options")
        group.add_argument(
            "--wait", action="store_true",
            help="wait until tag removed (implicit with '-l')")
        group.add_argument(
            "--technology", choices=list("ABFabf"), metavar="{A,B,F}",
            help="poll for a single technology (default: all)")

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
        
    def on_rdwr_startup(self, targets):
        return targets

    def on_rdwr_connect(self, tag):
        log.info(tag)
        return True

    def on_llcp_startup(self, llc):
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

    def on_card_startup(self, target):
        log.warning("on_card_startup should be customized")
        return None

    def on_card_connect(self, tag):
        log.info("activated as {0}".format(tag))
        if "test" in self.groups:
            self.test_completed = False
            self.run_tests(tag)
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
            
        for path in self.options.device:
            try:
                clf = nfc.ContactlessFrontend(path)
            except IOError as error:
                if error.errno == errno.ENODEV:
                    log.info("no contactless reader found on " + path)
                elif error.errno == errno.EACCES:
                    log_device_access_denied(path)
                elif error.errno == errno.EBUSY:
                    log_device_found_busy(path)
                else:
                    log.debug(repr(error) + "when trying " + path)
            else:
                log.debug("found a usable reader on " + path)
                break
        else:
            log.error("no contactless reader available")
            raise SystemExit(1)

        if "rdwr" in self.groups:
            rdwr_options = {
                'on-startup': self.on_rdwr_startup,
                'on-connect': self.on_rdwr_connect,
                }
            if self.options.technology:
                rdwr_options["targets"] = {
                    "A": [nfc.clf.RemoteTarget("106A")],
                    "B": [nfc.clf.RemoteTarget("106B")],
                    "F": [nfc.clf.RemoteTarget("212F")],
                }[self.options.technology.upper()]
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
                'brs': (106, 212, 424).index(self.options.bitrate),
                'acm': not self.options.passive_only,
                'miu': self.options.miu,
                'lto': self.options.lto,
                'rwt': self.options.rwt,
                'agf': not self.options.no_aggregation,
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


# ColorStreamHandler for python logging framework.
# based on: http://stackoverflow.com/questions/384076/1336640#1336640
 
# Copyright (c) 2014 Markus Pointner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

class AnsiColorStreamHandler(logging.StreamHandler):
    DEFAULT = '\x1b[0m'
    RED     = '\x1b[31m'
    GREEN   = '\x1b[32m'
    YELLOW  = '\x1b[33m'
    CYAN    = '\x1b[36m'

    CRITICAL = RED
    ERROR    = RED
    WARNING  = YELLOW
    INFO     = GREEN
    DEBUG    = CYAN

    @classmethod
    def _get_color(cls, level):
        if level >= logging.CRITICAL:  return cls.CRITICAL
        elif level >= logging.ERROR:   return cls.ERROR
        elif level >= logging.WARNING: return cls.WARNING
        elif level >= logging.INFO:    return cls.INFO
        elif level >= logging.DEBUG:   return cls.DEBUG
        else:                          return cls.DEFAULT

    def format(self, record):
        text = logging.StreamHandler.format(self, record)
        color = self._get_color(record.levelno)
        return color + text + self.DEFAULT

class WindowsColorStreamHandler(logging.StreamHandler):
    # wincon.h
    FOREGROUND_BLACK     = 0x0000
    FOREGROUND_BLUE      = 0x0001
    FOREGROUND_GREEN     = 0x0002
    FOREGROUND_CYAN      = 0x0003
    FOREGROUND_RED       = 0x0004
    FOREGROUND_MAGENTA   = 0x0005
    FOREGROUND_YELLOW    = 0x0006
    FOREGROUND_GREY      = 0x0007
    FOREGROUND_INTENSITY = 0x0008 # foreground color is intensified.
    FOREGROUND_WHITE     = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED

    BACKGROUND_BLACK     = 0x0000
    BACKGROUND_BLUE      = 0x0010
    BACKGROUND_GREEN     = 0x0020
    BACKGROUND_CYAN      = 0x0030
    BACKGROUND_RED       = 0x0040
    BACKGROUND_MAGENTA   = 0x0050
    BACKGROUND_YELLOW    = 0x0060
    BACKGROUND_GREY      = 0x0070
    BACKGROUND_INTENSITY = 0x0080 # background color is intensified.

    DEFAULT  = FOREGROUND_WHITE
    CRITICAL = BACKGROUND_YELLOW | FOREGROUND_RED | FOREGROUND_INTENSITY \
               | BACKGROUND_INTENSITY
    ERROR    = FOREGROUND_RED | FOREGROUND_INTENSITY
    WARNING  = FOREGROUND_YELLOW | FOREGROUND_INTENSITY
    INFO     = FOREGROUND_GREEN
    DEBUG    = FOREGROUND_CYAN

    @classmethod
    def _get_color(cls, level):
        if level >= logging.CRITICAL:  return cls.CRITICAL
        elif level >= logging.ERROR:   return cls.ERROR
        elif level >= logging.WARNING: return cls.WARNING
        elif level >= logging.INFO:    return cls.INFO
        elif level >= logging.DEBUG:   return cls.DEBUG
        else:                          return cls.DEFAULT

    def _set_color(self, code):
        import ctypes
        ctypes.windll.kernel32.SetConsoleTextAttribute(self._outhdl, code)

    def __init__(self, stream=None):
        super(WindowsColorStreamHandler, self).__init__(stream)
        # get file handle for the stream
        import ctypes, ctypes.util
        crtname = ctypes.util.find_msvcrt()
        crtlib = ctypes.cdll.LoadLibrary(crtname)
        self._outhdl = crtlib._get_osfhandle(self.stream.fileno())

    def emit(self, record):
        color = self._get_color(record.levelno)
        self._set_color(color)
        logging.StreamHandler.emit(self, record)
        self._set_color(self.FOREGROUND_WHITE)

# select ColorStreamHandler based on platform
import platform
if platform.system() == 'Windows':
    ColorStreamHandler = WindowsColorStreamHandler
else:
    ColorStreamHandler = AnsiColorStreamHandler
