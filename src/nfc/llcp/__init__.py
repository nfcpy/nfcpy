# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
"""
The nfc.llcp module implements the NFC Forum Logical Link Control
Protocol (LLCP) specification and provides a socket interface to use
the connection-less and connection-mode transport facilities of LLCP.
"""
from .socket import Socket                                         # noqa: F401
from .llc import LOGICAL_DATA_LINK, DATA_LINK_CONNECTION           # noqa: F401
from .err import Error, ConnectRefused, errno                      # noqa: F401

SO_SNDMIU = 1
SO_RCVMIU = 2
SO_SNDBUF = 3
SO_RCVBUF = 4
SO_SNDBSY = 5
SO_RCVBSY = 6

MSG_DONTWAIT = 0b00000001
