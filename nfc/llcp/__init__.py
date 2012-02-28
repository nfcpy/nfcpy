# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import logging
log = logging.getLogger(__name__)

import llc
from llc import LOGICAL_DATA_LINK, DATA_LINK_CONNECTION
from err import *
from opt import *

_llc = None

class Config(object):
    def __getitem__(self, key):
        return _llc.cfg.get(key)
    def __str__(self):
        return _llc.parameter_string

config = Config()
    
def startup(config):
    global _llc
    _llc = llc.LogicalLinkControl(config)
    return _llc.parameter_string

def activate(mac):
    _llc.activate(mac)
    _llc.start()

def connected():
    if _llc is not None:
        return _llc.is_alive()

def deactivate():
    if _llc is not None:
        _llc.shutdown()
        _llc.join()

def shutdown():
    global _llc
    deactivate()
    _llc = None

def resolve(name):
    """resolve() converts a service name into an address. This may involve
    conversation with the remote service discovery instance if the name is
    to be resolved for the first time. The return value is the service
    access point address number for the given service name if that name is
    available at the remote device. The return value is zero if the name was
    not known to the remote device. Link termination makes resolve() return
    None.
    """
    if _llc is not None:
        return _llc.resolve(name)

def socket(type):
    """socket() creates an endpoint for communication.and returns a socket
    descriptor. The *type* parameter specifies the communication semantics.
    Currently defined types are:
    LOGICAL_DATA_LINK - provides unreliable, connectionless transmission of
        messages of a fixed maximum length
    DATA_LINK_CONNECTION - provides sequenced, reliable, two-way connection-
        based transmission of messages of a fixed maximum length
    """
    if _llc is not None:
        return _llc.socket(type)

def setsockopt(sid, option, value):
    if _llc is not None:
        return _llc.setsockopt(sid, option, value)

def getsockopt(sid, option):
    if _llc is not None:
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
    if _llc is not None:
        return _llc.bind(sid, addr_or_name)

def listen(sid, backlog):
    """listen() marks the socket referred to by sid as a passive socket,
    that is, as a socket that will be used to accept incoming connection
    requests using accept(). The backlog argument defines the maximum
    length to which the queue of pending connections for the socket may
    grow. A backlog of zero disables queuing of connection requests.
    """
    if _llc is not None:
        return _llc.listen(sid, backlog)

def accept(sid):
    """accept() is used with DATA_LINK_CONNECTION sockets. It extracts the
    first connection request from the queue of pending connections for the
    listening socket referred to by sid, creates a new connected socket and
    returns the socket identifier referring to that socket. The original
    socket sid continues to be in the listening state.
    """
    if _llc is not None:
        return _llc.accept(sid)

def connect(sid, dest):
    """connect() attempts to establish a data link connection with the
    destination service identified by dest. The destination parameter may 
    be specified as the service access point address value or as a service
    name string.
    """
    if _llc is not None:
        return _llc.connect(sid, dest)

def send(sid, message):
    """send() is used to transmit a message to a remote socket. It may be 
    used only if the socket is in a connected state (so that the intended
    recipient is known).
    """
    if _llc is not None:
        return _llc.send(sid, message)

def sendto(sid, message, dest):
    """sendto() is used to transmit a message to a remote socket. If sendto()
    is used on a connection-mode socket, the argument *dest* is ignored. 
    Otherwise *dest* is the service access point address to which *message*
    is to be sent.
    """
    return _llc.sendto(sid, message, dest)

def recv(sid):
    if _llc is not None:
        return _llc.recv(sid)

def recvfrom(sid):
    if _llc is not None:
        return _llc.recvfrom(sid)

def poll(sid, event, timeout=None):
    if _llc is not None:
        return _llc.poll(sid, event, timeout)

def close(sid):
    """close() closes the socket referred to by *sid*. If the socket was of
    type DATA_LINK_CONNECTION, close() will perform termination of the data
    link connection if one was established earlier and has not yet been 
    closed by the remote endpoint.
    """
    if _llc is not None:
        return _llc.close(sid)

def getsockname(sid):
    """getsockname() returns the address to which the socket *sid* is bound.
    This may be None if the socket has not yet be bound, either explicitely 
    calling bind() or implicitely by a send() or sendto() operation on a 
    logical data link socket or connect() on a data link connection socket.
    """
    if _llc is not None:
        return _llc.getsockname(sid)

def getpeername(sid):
    """getpeername() returns the address of the peer connected to the
    socket *sid*, or None if the socket is presently not connected.
    """
    if _llc is not None:
        return _llc.getpeername(sid)
