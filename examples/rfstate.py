#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
"""Observe the state of an external RF field.

**Usage:** ::

  rfstate.py [options]

This is a simple utility to observe when a remote device activates and
deactivates the 13.56 MHz carrier frequency. For each state change a
message is printed with timestamp, the transition and time elapsed
since the previous state change. This only works with some devices
based on PN53x and uses nfcpy internal interfaces.

**Options:**

  -h, --help     show this help message and exit
  -t, --time T   listen time in seconds [default: 2.5]
  -d, --debug    output debug log messages to stderr
  -v, --verbose  print and log more information
  --device PATH  local device search path [default: usb]

"""
from __future__ import print_function

import re
import sys
import time
import errno
import logging

import nfc
import nfc.clf
import nfc.clf.pn53x

def main(args):
    if args["--debug"]:
        loglevel = logging.DEBUG - (1 if args["--verbose"] else 0)
        logging.getLogger("nfc.clf").setLevel(loglevel)

    try:
        time_to_return = time.time() + float(args['--time'])
    except ValueError as e:
        logging.error("while parsing '--time' " + str(e)); sys.exit(-1)
    
    clf = nfc.ContactlessFrontend()
    if clf.open(args['--device']):
        try:
            assert isinstance(clf.device, nfc.clf.pn53x.Device), \
                "rfstate.py does only work with PN53x based devices"
            chipset = clf.device.chipset
            
            regs = [("CIU_FIFOLevel", 0b10000000)] # clear fifo
            regs.extend(zip(25*["CIU_FIFOData"], bytearray(25)))
            regs.extend([
                ("CIU_Command",   0b00000001), # Configure command
                ("CIU_Control",   0b00000000), # act as target (b4=0)
                ("CIU_TxControl", 0b10000000), # disable output on TX1/TX2
                ("CIU_TxAuto",    0b00100000), # wake up when rf level detected
                ("CIU_CommIRq",   0b01111111), # clear interrupt request bits
                ("CIU_DivIRq",    0b01111111), # clear interrupt request bits
            ])
            chipset.write_register(*regs)

            if args["--verbose"]:
                time_t0 = time.time()
                chipset.read_register("CIU_Status1", "CIU_Status2")
                delta_t = time.time() - time_t0
                print("approx. %d samples/s" % int(1/delta_t))
            
            status = chipset.read_register("CIU_Status1", "CIU_Status2")
            rfstate = "ON" if status[1] & 0b00100000 else "OFF"
            time_t0 = time.time()
            print("%.6f RF %s" % (time_t0, rfstate))
            
            while time.time() < time_to_return:
                status = chipset.read_register("CIU_Status1", "CIU_Status2")
                if rfstate == "OFF" and status[1] & 0x20 == 0x20:
                    rfstate = "ON"
                    time_t1 = time.time()
                    delta_t = time_t1 - time_t0
                    print("%.6f RF ON  after %.6f" % (time_t1, delta_t))
                    time_t0 = time_t1
                if rfstate == "ON" and status[1] & 0x20 == 0x00:
                    rfstate = "OFF"
                    time_t1 = time.time()
                    delta_t = time_t1 - time_t0
                    print("%.6f RF OFF after %.6f" % (time_t1, delta_t))
                    time_t0 = time_t1
        except nfc.clf.UnsupportedTargetError as error:
            print(repr(error))
        except IOError as error:
            if error.errno == errno.EIO:
                print("lost connection to local device")
            else: print(repr(error))
        except (NotImplementedError, AssertionError) as error:
            print(str(error))
        except KeyboardInterrupt:
            pass
        finally:
            clf.close()

if __name__ == '__main__':
    logging.basicConfig(format='%(relativeCreated)d ms [%(name)s] %(message)s')

    try:
        from docopt import docopt
    except ImportError:
        sys.exit("the 'docopt' module is needed to execute this program")
    
    # remove restructured text formatting before input to docopt
    usage = re.sub(r'(?<=\n)\*\*(\w+:)\*\*.*\n', r'\1', __doc__)
    sys.exit(main(docopt(usage)))
