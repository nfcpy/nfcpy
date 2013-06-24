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
import sys
import os

test_programs = [
    ("llcp-test-server.py --mode t", "llcp-test-client.py --mode i"),
    ("llcp-test-server.py --mode i", "llcp-test-client.py --mode t"),
    ("snep-test-server.py --mode t", "snep-test-client.py --mode i"),
    ("snep-test-server.py --mode i", "snep-test-client.py --mode t"),
    ("handover-test-server.py --mode t", "handover-test-client.py --mode i"),
    ("handover-test-server.py --mode i", "handover-test-client.py --mode t"),
    ("phdc-test-manager.py --mode t", "phdc-test-agent.py p2p --mode i"),
    ("phdc-test-manager.py --mode i", "phdc-test-agent.py p2p --mode t"),
    ("phdc-test-manager.py --mode i --loop", "phdc-test-agent.py tag"),
    ]

examples = os.path.split(sys.path[0])[0] + "/examples/"

for server, client in test_programs:
    print "*** {0} ***".format(client)
    
    server = examples + "{0} --device udp -q".format(server)
    print server
    server = Popen(shlex.split(server), stderr=PIPE, stdout=PIPE)

    client = examples + "{0} --device udp -q -T".format(client)
    print client
    client = Popen(shlex.split(client), stderr=STDOUT)

    client.wait()
    server.terminate()
