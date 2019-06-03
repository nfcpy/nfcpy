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


class Socket(object):
    """
    Create a new LLCP socket with the given socket type. The
    socket type should be one of:

    * :const:`nfc.llcp.LOGICAL_DATA_LINK` for best-effort
      communication using LLCP connection-less PDU exchange

    * :const:`nfc.llcp.DATA_LINK_CONNECTION` for reliable
      communication using LLCP connection-mode PDU exchange

    * :const:`nfc.llcp.llc.RAW_ACCESS_POINT` for unregulated LLCP PDU
      exchange (useful to implement test programs)
    """
    def __init__(self, llc, sock_type):
        self._tco = None if sock_type is None else llc.socket(sock_type)
        self._llc = llc

    @property
    def llc(self):
        """The :class:`~nfc.llcp..llc.LogicalLinkController` instance
        to which this socket belongs. This attribute is read-only."""
        return self._llc

    def resolve(self, name):
        """Resolve a service name into an address. This may involve
        conversation with the remote service discovery component if
        the name is hasn't yet been resolved. The return value is the
        service access point address for the service name bound at the
        remote device. The address value 0 indicates that the remote
        device does not have a service with the requested name. The
        address value 1 indicates that the remote device has a data
        link connection service with the requested name that can only
        be connected by service name. The return value is None when
        communication with the peer device terminated while waiting
        for a response.

        """
        return self.llc.resolve(name)

    def setsockopt(self, option, value):
        """Set the value of the given socket option and return the
        current value which may have been corrected if it was out of
        bounds."""
        return self.llc.setsockopt(self._tco, option, value)

    def getsockopt(self, option):
        """Return the value of the given socket option."""
        return self.llc.getsockopt(self._tco, option)

    def bind(self, address=None):
        """Bind the socket to address. The socket must not already be
        bound. The address may be a service name string, a service
        access point number, or it may be omitted. If address is a
        well-known service name the socket will be bound to the
        corresponding service access point address, otherwise the
        socket will be bound to the next available service access
        point address between 16 and 31 (inclusively). If address is a
        number between 32 and 63 (inclusively) the socket will be
        bound to that service access point address. If the address
        argument is omitted the socket will be bound to the next
        available service access point address between 32 and 63."""
        return self.llc.bind(self._tco, address)

    def connect(self, address):
        """Connect to a remote socket at address. Address may be a
        service name string or a service access point number."""
        return self.llc.connect(self._tco, address)

    def listen(self, backlog):
        """Mark a socket as a socket that will be used to accept
        incoming connection requests using accept(). The *backlog*
        defines the maximum length to which the queue of pending
        connections for the socket may grow. A backlog of zero
        disables queuing of connection requests.
        """
        return self.llc.listen(self._tco, backlog)

    def accept(self):
        """Accept a connection. The socket must be bound to an address
        and listening for connections. The return value is a new
        socket object usable to send and receive data on the
        connection."""
        socket = Socket(self._llc, None)
        socket._tco = self.llc.accept(self._tco)
        return socket

    def send(self, data, flags=0):
        """Send data to the socket. The socket must be connected to a remote
        socket. Returns a boolean value that indicates success or
        failure. A false value is typically an indication that the
        socket or connection was closed.

        """
        return self.llc.send(self._tco, data, flags)

    def sendto(self, data, addr, flags=0):
        """Send data to the socket. The socket should not be connected
        to a remote socket, since the destination socket is specified
        by addr. Returns a boolean value that indicates success
        or failure. Failure to send is generally an indication that
        the socket was closed."""
        return self.llc.sendto(self._tco, data, addr, flags)

    def recv(self):
        """Receive data from the socket. The return value is a bytes object
        representing the data received. The maximum amount of data
        that may be returned is determined by the link or connection
        maximum information unit size."""
        return self.llc.recv(self._tco)

    def recvfrom(self):
        """Receive data from the socket. The return value is a pair
        (bytes, address) where string is a string representing the
        data received and address is the address of the socket sending
        the data."""
        return self.llc.recvfrom(self._tco)

    def poll(self, event, timeout=None):
        """Wait for a socket event. Posssible *event* values are the strings
        "recv", "send" and "acks". Whent the timeout is present and
        not :const:`None`, it should be a floating point number
        specifying the timeout for the operation in seconds (or
        fractions thereof). For "recv" or "send" the :meth:`poll`
        method returns :const:`True` if a next :meth:`recv` or
        :meth:`send` operation would be non-blocking. The "acks" event
        may only be used with a data-link-connection type socket; the
        call then returns :const:`True` if the counter of received
        acknowledgements was greater than zero and decrements the
        counter by one.

        """
        return self.llc.poll(self._tco, event, timeout)

    def getsockname(self):
        """Obtain the address to which the socket is bound. For an
        unbound socket the returned value is None.
        """
        return self.llc.getsockname(self._tco)

    def getpeername(self):
        """Obtain the address of the peer connected on the socket. For
        an unconnected socket the returned value is None.
        """
        return self.llc.getpeername(self._tco)

    def close(self):
        """Close the socket. All future operations on the socket
        object will fail. The remote end will receive no more data
        Sockets are automatically closed when the logical link
        controller terminates (gracefully or by link disruption). A
        connection-mode socket will attempt to disconnect the data
        link connection (if in connected state)."""
        return self.llc.close(self._tco)
