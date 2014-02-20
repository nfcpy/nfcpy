# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

"""
The nfc.llcp module implements the NFC Forum Logical Link Control
Protocol (LLCP) specification and provides a socket interface to use
the connection-less and connection-mode transport facilities of LLCP.
"""

import logging
log = logging.getLogger(__name__)

from socket import Socket
from llc import LOGICAL_DATA_LINK, DATA_LINK_CONNECTION
from err import *
from opt import *

