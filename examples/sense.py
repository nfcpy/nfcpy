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
import errno
import argparse
import logging
logging.basicConfig(format='%(relativeCreated)d ms [%(name)s] %(message)s')

import nfc
import nfc.clf

ba = lambda hexstr: bytearray.fromhex(hexstr)
target_pattern = re.compile(r'(\d+[A-Z]{1})(?:\((.*)\)|.*)')

def main(args):
    if args.debug:
        loglevel = logging.DEBUG - (1 if args.verbose else 0)
        logging.getLogger("nfc.clf").setLevel(loglevel)

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
                    for attr in map(str.strip, attributes.split(',')):
                        name, value = map(str.strip, attr.split('='))
                        value = bytearray.fromhex(value)
                        setattr(target, name, value)
                targets.append(target)

        try:
            while True:
                target = clf.sense(*targets, iterations=args.iterations,
                                   interval=args.interval)
                print("{0} {1}".format(time.strftime("%X"), target))
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
        help="number of iterations to run (default %(default)s)")
    parser.add_argument(
        "-t", dest="interval", metavar="seconds", type=float, default=0.2,
        help="time between iterations (default %(default)s sec)")
    parser.add_argument(
        "-r", "--repeat", action="store_true",
        help="repeat forever (terminate with Ctrl-C)")
    parser.add_argument(
        "-w", dest="waittime", type=float, default=0.1, metavar="seconds",
        help="time between repetitions (default %(default)s sec)")
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="output debug log messages to stderr")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="output even more debug log messages")
    parser.add_argument(
        "--device", metavar="path", default="usb",
        help="local device search path (default %(default)s)")
    
    main(parser.parse_args())
