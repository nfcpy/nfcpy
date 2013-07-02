#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

from subprocess import Popen, PIPE, STDOUT
import shlex
import time
import sys
import os

test_programs = [
    ("llcp-test-server.py --mode t --miu 128",
     "llcp-test-client.py --mode i --miu 128 -T"),
    ("llcp-test-server.py --mode i --miu 128",
     "llcp-test-client.py --mode t --miu 128 -T"),
    ("llcp-test-server.py --mode t --miu 2176",
     "llcp-test-client.py --mode i --miu 2176 -T"),
    ("llcp-test-server.py --mode i --miu 2176",
     "llcp-test-client.py --mode t --miu 2176 -T"),
    ("snep-test-server.py --mode t",
     "snep-test-client.py --mode i -T"),
    ("snep-test-server.py --mode i",
     "snep-test-client.py --mode t -T"),
    ("handover-test-server.py --mode t",
     "handover-test-client.py --mode i -T"),
    ("handover-test-server.py --mode i",
     "handover-test-client.py --mode t -T"),
    ("phdc-test-manager.py --mode t",
     "phdc-test-agent.py p2p --mode i -T"),
    ("phdc-test-manager.py --mode i",
     "phdc-test-agent.py p2p --mode t -T"),
    ("phdc-test-manager.py --mode i",
     "phdc-test-agent.py tag -t 1"),
    ("phdc-test-manager.py --mode i",
     "phdc-test-agent.py tag -t 2"),
    ("phdc-test-manager.py --mode i",
     "phdc-test-agent.py tag -t 3"),
    ("phdc-test-manager.py --mode i",
     "phdc-test-agent.py tag -t 4"),
    ]

examples = os.path.relpath(os.path.split(sys.path[0])[0] + "/examples")
device = sys.argv[1] if len(sys.argv) > 1 else 'udp'

started = time.time()
for server, client in test_programs:
    print "*** {0} ***".format(client)
    
    server = examples + "/{0} --device {1} -q".format(server, device)
    print server
    server = Popen(shlex.split(server), stderr=PIPE, stdout=PIPE)

    client = examples + "/{0} --device {1} -q".format(client, device)
    print client
    client = Popen(shlex.split(client), stderr=STDOUT)

    print "waiting for client to terminate"
    client.wait()
    print "waiting for server to terminate"
    server.wait()
    print "allow some time for readers to recover"
    time.sleep(5)

elapsed = int(time.time() - started)
print("completed tests in {0} minutes {1} seconds"
      .format(elapsed/60, elapsed%60))
