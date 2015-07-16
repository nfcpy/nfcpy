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

import os, sys, time
sys.path.insert(1, os.path.split(sys.path[0])[0])

import re
import time
import errno
import argparse
import logging
logging.basicConfig(format='%(relativeCreated)d ms [%(name)s] %(message)s')

import nfc
import nfc.clf

brty_for_dep = ("106A", "212F", "424F")
target_pattern = re.compile(r'([0-9]+[A-Z]{1})(?: +(.*)|.*)')

def main(args):
    if args.debug:
        loglevel = logging.DEBUG - (1 if args.verbose else 0)
        logging.getLogger("nfc.clf").setLevel(loglevel)

    if args.atr and len(args.atr) < 16:
        print("--atr must supply at least 16 byte")

    clf = nfc.ContactlessFrontend()
    if clf.open(args.device):
        targets = list()
        for target in args.targets:
            target_pattern_match = target_pattern.match(target)
            if not target_pattern_match:
                logging.error("invalid target pattern {!r}".format(target))
            else:
                brty, attributes = target_pattern_match.groups()
                target = nfc.clf.RemoteTarget(brty)
                if attributes:
                    for attr in map(str.strip, attributes.split(' ')):
                        name, value = map(str.strip, attr.split('='))
                        value = bytearray.fromhex(value)
                        setattr(target, name, value)
                targets.append(target)

        try:
            while True:
                target = clf.sense(*targets, iterations=args.iterations,
                                   interval=args.interval)
                print("{0} {1}".format(time.strftime("%X"), target))
                
                if (target and args.atr and target.brty in brty_for_dep and
                    ((target.sel_res and target.sel_res[0] & 0x40) or
                     (target.sensf_res and target.sensf_res[1:3]=='\1\xFE'))):
                    atr_req = args.atr[:]
                    if atr_req[0] == 0xFF: atr_req[0] = 0xD4
                    for i in (1, 12, 13, 14):
                        if atr_req[i] == 0xFF: atr_req[i] = 0x00
                    if target.sensf_res:
                        for i in range(2, 10):
                            if atr_req[i] == 0xFF:
                                atr_req[i] = target.sensf_res[i-1]
                    if atr_req[15] == 0xFF:
                        atr_req[15] = 0x30 | (len(atr_req)>16)<<1
                    try:
                        data = chr(len(atr_req)+1) + atr_req
                        if target.brty == "106A": data.insert(0, 0xF0)
                        data = clf.exchange(data, 1.0)
                        if target.brty == "106A": assert data.pop(0) == 0xF0
                        assert len(data) == data.pop(0)
                        target.atr_res = data
                        target.atr_req = atr_req
                    except nfc.clf.CommunicationError as error:
                        print(repr(error) + " for NFC-DEP ATR_REQ")
                    except AssertionError:
                        print("invalid ATR_RES: %r" % str(data.encode("hex")))
                
                if target and target.atr_res:
                    did = target.atr_req[12]
                    psl = "06D404%02x1203" % did # PSL_REQ
                    rls = ("04D40A%02x"%did) if did else "03D40A"
                    if target.brty == "106A": psl = "F0" + psl
                    psl, rls = map(bytearray.fromhex, (psl, rls))
                    try: clf.exchange(psl, 1.0)
                    except nfc.clf.CommunicationError as error:
                        print(repr(error) + " for NFC-DEP PSL_REQ")
                    else:
                        target.brty = "424F"
                        try: clf.exchange(rls, 1.0)
                        except nfc.clf.CommunicationError as error:
                            print(repr(error) + " for NFC-DEP RLS_REQ")

                if (target and target.sensf_res and
                    target.sensf_res[1:3] != '\x01\xFE'):
                    request_system_code = "\x0A\x0C"+target.sensf_res[1:9]
                    try: clf.exchange(request_system_code, timeout=1.0)
                    except nfc.clf.CommunicationError as error:
                        print(repr(error) + " for Request System Code Command")
                
                if not args.repeat: break
                time.sleep(args.waittime)
        except IOError as error:
            if error.errno == errno.EIO:
                print("lost connection to local device")
            else: print(error)
        except nfc.clf.UnsupportedTargetError as error:
            print error
        except KeyboardInterrupt:
            pass
        finally:
            clf.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "targets", nargs="*", metavar="target",
        help="bitrate/type string to sense")
    parser.add_argument(
        "-i", dest="iterations", metavar="number", type=int, default=1,
        help="number of iterations to run (default: %(default)s)")
    parser.add_argument(
        "-t", dest="interval", metavar="seconds", type=float, default=0.2,
        help="time between iterations (default: %(default)s sec)")
    parser.add_argument(
        "-r", "--repeat", action="store_true",
        help="repeat forever (terminate with Ctrl-C)")
    parser.add_argument(
        "-w", dest="waittime", type=float, default=0.1, metavar="seconds",
        help="time between repetitions (default: %(default)s sec)")
    parser.add_argument(
        "--atr", type=bytearray.fromhex, metavar="HEXSTR",
        help="activate passive device (FF bytes get corrected)")
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="output debug log messages to stderr")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="output even more debug log messages")
    parser.add_argument(
        "--device", metavar="path", default="usb",
        help="local device search path (default: %(default)s)")
    
    main(parser.parse_args())
