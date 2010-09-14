# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
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
log = logging.getLogger(__name__)

import llc
from llc import LOGICAL_DATA_LINK, DATA_LINK_CONNECTION
from err import *
from opt import *

_llc = None

def startup(miu, lto):
    global _llc
    _llc = llc.LogicalLinkControl(miu, lto)
    return _llc.parameter_string

def activate(mac):
    _llc.activate(mac)
    _llc.start()

def deactivate():
    _llc.shutdown()
    _llc.join()

def shutdown():
    global _llc
    deactivate()
    _llc = None

def resolve(name):
    """resolve() converts a service name into an address. This may involve
    conversation with the remote service discovery instance if the name is
    to be resolved for the first time.
    """
    return _llc.resolve(name)

def socket(socket_type):
    return _llc.socket(socket_type)

def setsockopt(sid, option, value):
    return _llc.setsockopt(sid, option, value)

def getsockopt(sid, option):
    return _llc.getsockopt(sid, option)

def bind(sid, addr_or_name):
    """bind() assigns a local address for the socket referred to by sid.
    The parameter addr_or_name may be either an integer value specifying
    the local addr to use or a fully qualified service name string. If
    addr_or_name is a valid service name string the address assignment
    will be from the well-known address range is the name is well-known,
    otherwise it will be from the dynamic service address range (16-31).
    If addr_or_name is an address, that address must be within the private
    address range (32-63).
    """
    return _llc.bind(sid, addr_or_name)

def listen(sid, backlog):
    """listen() marks the socket referred to by sid as a passive socket,
    that is, as a socket that will be used to accept incoming connection
    requests using accept(). The backlog argument defines the maximum
    length to which the queue of pending connections for the socket may
    grow. A backlog of zero disables queuing of connection requests.
    """
    return _llc.listen(sid, backlog)

def accept(sid):
    """accept() is used with DATA_LINK_CONNECTION sockets. It extracts the
    first connection request from the queue of pending connections for the
    listening socket referred to by sid, creates a new connected socket and
    returns the socket identifier referring to that socket. The original
    socket sid continues to be in the listening state.
    """
    return _llc.accept(sid)

def connect(sid, dest):
    """connect() attempts to establish a data link connection with the
    destination service identified by dest. The destination parameter may 
    be specified as the service access point address value or as a service
    name string.
    """
    return _llc.connect(sid, dest)

def send(sid, message):
    return _llc.send(sid, message)

def sendto(sid, message, dest):
    return _llc.sendto(sid, message, dest)

def recv(sid):
    return _llc.recv(sid)

def recvfrom(sid):
    return _llc.recvfrom(sid)

def poll(sid, event, timeout=None):
    return _llc.poll(sid, event, timeout)

def close(sid):
    return _llc.close(sid)

def getsockname(sid):
    return _llc.getsockname(sid)

def getpeername(sid):
    return _llc.getpeername(sid)
