#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import os
import os.path
import inspect
import nfc.clf
import nfc.dep
import logging
from time import sleep

log = logging.getLogger()


def dta_lis_p2p(clf, args):
    dep = nfc.dep.Target(clf)
    gbt = ''  # 'Ffm' + "010111".decode("hex")
    if dep.activate(timeout=1.0, wt=8, gbt=gbt) is not None:
        log.info("enter nfc-dep target loop")
        rwt = 4096/13.56E6 * 2**8
        data = dep.exchange(None, timeout=1.0)
        while data is not None:
            # log.info("rcvd data {0}".format(data.encode("hex")))
            if data == "FFFFFF0103".decode("hex"):
                if dep.send_timeout_extension(2) == 2:
                    sleep(1.5 * rwt)
                else:
                    break
            if len(data) == 6 and data.startswith("\xFF\x00\x00\x00"):
                log.info("pattern number: " + data[4:6].encode("hex"))
                # pattern_number = data[4:6]
            # log.info("send back {0}".format(data.encode("hex")))
            data = dep.exchange(data, timeout=1.0)
        dep.deactivate()
        log.info("exit nfc-dep target loop")


def dta_pol_p2p(clf, args):
    sot = "004000011002010E".decode("hex")  # start of test command
    gbi = ''  # 'Ffm' + "010111".decode("hex") # general bytes from initiator
    ato = 1.0  # activation timeout
    lto = 1.0  # link timeout

    dep = nfc.dep.Initiator(clf)
    if dep.activate(timeout=ato, brs=1, gbi=gbi) is not None:
        log.info("enter nfc-dep initiator loop")
        log.info("link timeout set to {0} seconds".format(lto))
        try:
            data = dep.exchange(send_data=sot, timeout=lto)
            while data is not None:
                # log.info("rcvd data {0}".format(data.encode("hex")))
                if data == "FFFFFF0101".decode("hex"):
                    dep.deactivate(release=False)
                    break
                if data == "FFFFFF0102".decode("hex"):
                    dep.deactivate(release=True)
                    break
                # log.info("send back {0}".format(data.encode("hex")))
                data = dep.exchange(send_data=data, timeout=lto)
        except nfc.clf.DigitalProtocolError as error:
            log.error(repr(error))
        finally:
            log.info("exit nfc-dep target loop")


def main(args):
    for device in args.device:
        try:
            clf = nfc.ContactlessFrontend(device)
            break
        except IOError:
            pass
    else:
        log.error("no contactless reader found")
        raise SystemExit(1)

#    connected = clf.connect({'tag': {}})
#    if connected == 'tag':
#        nfc.tag.get_ndef()
#        while nfc.tag.connected():
#            sleep(0.1)

    while True:
        try:
            if args.mode is None or args.mode == "t":
                dta_lis_p2p(clf, args)
            if args.mode is None or args.mode == "i":
                dta_pol_p2p(clf, args)
                # sleep(1)
        except KeyboardInterrupt:
            clf.close()
            raise SystemExit

    return


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", dest="quiet", action="store_true",
        help="print minimum information'")
    parser.add_argument(
        "-v", dest="verbose", action="store_true",
        help="print verbose information'")
    parser.add_argument(
        "-d", dest="debug", action="append", default=[], metavar="MODULE",
        help="print debug log messages for MODULE")
    parser.add_argument(
        "--pattern-number", metavar="INT", type=int, default=0,
        help="select a test configuration")
    parser.add_argument(
        "--mode", choices=["t", "target", "i", "initiator"], metavar="{t,i}",
        help="connect as Target 't' or Initiator 'i' (default: both)")
    parser.add_argument(
        "--device", metavar="NAME", action="append",
        help=("use specified contactless reader(s): "
              "usb[:vendor[:product]] (vendor and product in hex), "
              "usb[:bus[:dev]] (bus and device number in decimal), "
              "tty[:(usb|com)[:port]] (usb virtual or com port)"))

    args = parser.parse_args()
    print args

    if args.device is None:
        args.device = ['']

    verbosity = logging.INFO if args.verbose else logging.ERROR
    console_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
    logging.basicConfig(level=verbosity, format=console_format)

    nfcpy_path = os.path.dirname(inspect.getfile(nfc))
    for name in os.listdir(nfcpy_path):
        if os.path.isdir(os.path.join(nfcpy_path, name)):
            logging.getLogger("nfc."+name).setLevel(verbosity)
        elif name.endswith(".py") and name != "__init__.py":
            logging.getLogger("nfc."+name[:-3]).setLevel(verbosity)

    if args.debug:
        logging.getLogger('').setLevel(logging.DEBUG)
        logging.getLogger('nfc').setLevel(logging.DEBUG)
        for module in args.debug:
            log.info("enable debug output for module '{0}'".format(module))
            logging.getLogger(module).setLevel(logging.DEBUG)

    main(args)
