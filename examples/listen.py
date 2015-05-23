#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import os, sys
sys.path.insert(1, os.path.split(sys.path[0])[0])

import time
import errno
import argparse
import logging
logging.basicConfig(format='%(relativeCreated)d ms [%(name)s] %(message)s')

import nfc
from nfc.clf import TTA, TTF, DEP

ba = lambda hexstr: bytearray.fromhex(hexstr)

def main(args):
    if args.debug:
        loglevel = logging.DEBUG - (1 if args.verbose else 0)
        logging.getLogger("nfc.clf").setLevel(loglevel)

    clf = nfc.ContactlessFrontend()
    if clf.open(args.device):
        try:
            while True:
                args.listen(clf, options=args)
                if not args.repeat: break
                time.sleep(args.waittime)
        except IOError as error:
            if error.errno == errno.EIO:
                print("lost connection to local device")
            else: print(error)
        except NotImplementedError as error:
            print(error)
        except KeyboardInterrupt:
            pass
        finally:
            clf.close()

def listen_tta(clf, options):
    target = TTA(options.bitrate)
    target.sens_res = bytearray("\x01\x01")
    target.sdd_res = options.uid
    target.sel_res = bytearray("\x00" if options.tag == "tt2" else "\x20")
    target = clf.listen(target, options.timeout)
    if target:
        print("{0} {1}".format(time.strftime("%X"), target))

def listen_ttf(clf, options):
    target = TTF(options.bitrate)
    target.sens_res = "\x01" + options.idm + options.pmm + options.sys
    target = clf.listen(target, options.timeout)
    if target:
        print("{0} {1}".format(time.strftime("%X"), target))

def listen_dep(clf, options):
    tta = TTA(sens_res=ba("0101"),sdd_res=ba("08010203"),sel_res=ba("40"))
    ttf = TTF(sens_res="\x01" + options.id3[0:8] + bytearray(8) + "\xFF\xFF")
    dep = DEP(tta=tta, ttf=ttf)
    
    atr = "\xD5\x01" + options.id3 + "\x00\x00\x00\x08\x32" + options.gbt
    tta.atr_res = ttf.atr_res = atr
    if options.acm: dep.atr_res = atr
    
    target = clf.listen(dep, options.timeout)
    if target:
        mode = "passive" if target.tta or target.ttf else "active"
        print("{0} DEP {1} kbps {2} communication mode, CMD={3}"
              .format(time.strftime("%X"), target.bitrate, mode,
                      str(target.cmd).encode("hex").upper()))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t", dest="timeout", type=float, default=2.5, metavar="TIME",
        help="listen time in seconds (default %(default)s sec)")
    parser.add_argument(
        "-w", dest="waittime", type=float, default=1.0, metavar="TIME",
        help="time between repetations (default %(default)s sec)")
    parser.add_argument(
        "-r", "--repeat", action="store_true",
        help="repeat listen forever (cancel with Ctrl-C)")
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="output debug log messages to stderr")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="output even more debug log messages")
    parser.add_argument(
        "--device", metavar="PATH", default="usb",
        help="local device search path (default %(default)s)")
    
    subparsers = parser.add_subparsers(help="possible listen targets")
    
    tta_parser = subparsers.add_parser("tta")
    tta_parser.set_defaults(listen=listen_tta)
    tta_parser.add_argument(
        "--bitrate", type=int, metavar="INT", default=106,
        help="target bitrate (default %(default)s kbps)")
    tta_parser.add_argument(
        "--tag", choices=("tt2","tt4"), default="tt2",
        help="select tag response (default %(default)s)")
    tta_parser.add_argument(
        "--uid", type=bytearray.fromhex, default="08010203",
        help="four byte UID (default %(default)s)", metavar="HEXSTR")
    
    ttf_parser = subparsers.add_parser("ttf")
    ttf_parser.set_defaults(listen=listen_ttf)
    ttf_parser.add_argument(
        "--bitrate", type=int, metavar="INT", default=212,
        help="target bitrate (default %(default)s kbps)")
    ttf_parser.add_argument(
        "--idm", type=bytearray.fromhex, default="02FE010203040506",
        help="card IDm (default %(default)s)", metavar="HEXSTR")
    ttf_parser.add_argument(
        "--pmm", type=bytearray.fromhex, default="FFFFFFFFFFFFFFFF",
        help="card PMm (default %(default)s)", metavar="HEXSTR")
    ttf_parser.add_argument(
        "--sys", type=bytearray.fromhex, default="12FC",
        help="system code (default %(default)s)", metavar="HEXSTR")
    
    dep_parser = subparsers.add_parser("dep")
    dep_parser.set_defaults(listen=listen_dep)
    dep_parser.add_argument(
        "--acm", action="store_true",
        help="enable active communication mode")
    dep_parser.add_argument(
        "--id3", type=bytearray.fromhex, default="01FE0102030405060708",
        help="NFCID3 (default %(default)s)", metavar="HEXSTR")
    dep_parser.add_argument(
        "--gbt", type=bytearray.fromhex, default="46666D010110",
        help="general bytes (default %(default)s)", metavar="HEXSTR")
    
    main(parser.parse_args())
