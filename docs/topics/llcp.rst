.. _llcp-tutorial:
.. currentmodule:: nfc.llcp

*****************************
Logical Link Control Protocol
*****************************

The Logical Link Control Protocol allows multiplexed communications
between two NFC Forum Peer Devices where either peer can send protocol
data units at any time (asynchronous balanced mode). The communication
endpoints are called Service Access Points (SAP) and are addressed by
a 6 bit numerical identifier. Protocol data units are exchanged
between exactly two service access points, from a source SAP (SSAP) to
a destination SAP (DSAP). The service access point address space is
split into 3 parts: an address between 0 and 15 identifies a
well-known service, an address between 16 and 31 identifies a service
that is registered in the local service environment, and addresses
between 32 and 63 are unregistered and normally used as a source
address by client applications that send or connect to peer services.

The interface to realize LLCP client and server applications in nfcpy
is implemented by the :class:`nfc.llcp.Socket` class. A socket is
created with a :class:`~nfc.llcp.llc.LogicalLinkController` instance
and the *socket type* as arguments to the :class:`Socket`
constructor. The :meth:`nfc.ContactlessFrontend.connect` method
accepts callback functions that will receive the active
:class:`~nfc.llcp.llc.LogicalLinkController` instance as argument. ::

   import nfc
   import nfc.llcp

   def client(socket):
       socket.sendto("message", addr=16)

   def connected(llc):
       socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
       Thread(target=client, args=(socket,)).start()
       return True
   
   clf = nfc.ContactlessFrontend()
   clf.connect(llcp={'on-connect': connected})

Although service access points are generally identified by a numerical
address, the LLCP service discovery component allows SAPs to be
associated with a globally unique service name and become discoverable
by remote applications. A service name may represent either an NFC
Forum well-known or an externally defined service name.

* The format ``urn:nfc:sn:<servicename>`` represents a well-known
  service name, for example the service name ``urn:nfc:sn:snep``
  identifies the NFC Forum Simple NDEF Data Exchange (SNEP) default
  server.
* The format ``urn:nfc:xsn:<domain>:<servicename>`` represents a
  service name that is defined by the *domain* owner, for example the
  service name ``urn:nfc:xsn:nfc-forum.org:snep-validation`` is the
  service name of a special SNEP server used by the NFC Forum during
  validation of the SNEP secification.

In nfcpy a service name can be registered with :meth:`Socket.bind`
and a service name string as the address parameter. The allocated
service access point address number can then be retrived with
:meth:`~Socket.getsockname`. A remote service name can be resolved
into a service access point address number with
:meth:`~Socket.resolve`. ::

   def server(socket):
       message, address = socket.recvfrom()
       socket.sendto("It's me!", address)

   def client(socket):
       address = socket.resolve( 'urn:nfc:xsn:nfcpy.org:test-service' )
       socket.sendto("Hi there!", address)
       message, address = socket.recvfrom()
       print("SAP {0} said: {1}".format(address, message))

   def startup(llc):
       socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
       socket.bind( 'urn:nfc:xsn:nfcpy.org:test-service' )
       print("server bound to SAP {0}".format(socket.getsockname()))
       Thread(target=server, args=(socket,)).start()
       return llc
   
   def connected(llc):
       socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
       Thread(target=client, args=(socket,)).start()
       return True
   
   clf = nfc.ContactlessFrontend()
   clf.connect(llcp={'on-startup': startup, 'on-connect': connected})

Connection-mode sockets must be connected before data can be
exchanged. For a server socket this involves calls to
:meth:`~Socket.bind`, :meth:`~Socket.listen` and
:meth:`~Socket.accept`, and for a client socket to call
:meth:`~Socket.resolve` and :meth:`~Socket.connect` with the address
returned by :meth:`~Socket.resolve` or to simply call
:meth:`~Socket.connect` with the service name as *address* (note that
:meth:`~Socket.resolve` becomes more efficient when queries for
multiple service names are needed). ::

   def server(socket):
       # note that this server only accepts one connection
       # for multiple connections spawn a thread per accept
       while True:
          client = socket.accept()
          while True:
              message = client.recv()
              print("Client said: {0}".format(message))
              client.send("It's me!")

   def client(socket):
       socket.connect( 'urn:nfc:xsn:nfcpy.org:test-service' )
       socket.send("Hi there!")
       message = socket.recv()
       print("Server said: {0}".format(message))

   def startup(llc):
       socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
       socket.bind( 'urn:nfc:xsn:nfcpy.org:test-service' )
       print("server bound to SAP {0}".format(socket.getsockname()))
       socket.listen()
       Thread(target=server, args=(socket,)).start()
       return llc
   
   def connected(llc):
       socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
       Thread(target=client, args=(socket,)).start()
       return True
   
   clf = nfc.ContactlessFrontend()
   clf.connect(llcp={'on-startup': startup, 'on-connect': connected})

Data can be send and received with :meth:`~Socket.sendto` and
:meth:`~Socket.recvfrom` on connection-less sockets and
:meth:`~Socket.send` and :meth:`~Socket.recv` on connection-mode
sockets. Send data is guaranteed to be delivered to the remote device
when the send methods return (although not necessarily to the remote
service access point - only for a connection-mode socket this can be
safely assumed but note that even then data may not yet have been
arrived at the service user). Receiving data with either
:meth:`~Socket.recv` or :meth:`~Socket.recvfrom` blocks until some
data has become available or all LLCP communication has been
terminated (if either one peer intentionally closes the LLCP Link or
the devices are moved out of communication range). To implement a
communication timeout during normal operation, the
:meth:`~Socket.poll` method can be used to waI will "fix" this bug by
adding to the documentationI will "fix" this bug by adding to the
documentationit for a 'recv' event with a given timeout. ::

   def client(socket):
       socket.connect( 'urn:nfc:xsn:nfcpy.org:test-service' )
       socket.send("Hi there!")
       if socket.poll('recv', timeout=1.0):
           message = socket.recv()
           print("Server said: {0}".format(message))
       else:
           print("Server said nothing within 1 second")

Sockets of type :const:`nfc.llcp.LOGICAL_DATA_LINK`,
:const:`DATA_LINK_CONNECTION` and :const:`RAW_ACCESS_POINT` (which
should normally not be used) do not provide fragmentation for messages
that do not fit into a single protocol data unit but raise an
:exc:`nfc.llcp.Error` exception with :const:`errno.EMSGSIZE`. An
application can learn the maximum nuber of bytes for sending or
receiving by calling :meth:`~Socket.getsockopt` with option
:const:`nfc.llcp.SO_SNDMIU` or :const:`nfc.llcp.SO_RCVMIU`. ::

   send_miu = socket.getsockopt(nfc.llcp.SO_SNDMIU)
   recv_miu = socket.getsockopt(nfc.llcp.SO_RCVMIU)

When opening or accepting a data link connection an application may
specify the maximum number of octets to receive with the
:const:`nfc.llcp.SO_RCVMIU` option in :meth:`~Socket.setsockopt`. The
value must be between 128 and 2176, inclusively. If the RCVMIU is not
explicitely set for a data link connection the default value applied
by the peer is 128 octets.

On connection-mode sockets options :const:`nfc.llcp.SO_SNDBUF` and
:const:`nfc.llcp.SO_RCVBUF` can be used to learn the local and remote
receive window values established during connection setup. The local
receive window can also be set with :meth:`~Socket.setsockopt` before
the socket gets connected. ::

  def server(llc):
      socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
      socket.setsockopt(nfc.llcp.SO_RCVMIU, 1000)
      socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
      socket.bind( "urn:nfc:sn:snep" )
      socket.listen()
      socket.accept()
      ...

  def client(llc):
      socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
      socket.setsockopt(nfc.llcp.SO_RCVMIU, 1000)
      socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
      socket.connect( "urn:nfc:sn:snep" )
      ...

LLCP data link connections use sliding window flow-control. The
receive window set with :const:`nfc.llcp.SO_RCVBUF` dictates the
number of connection-oriented information PDUs that the remote side of
the data link connection may have outstanding (sent but not
acknowledged) at any time. A connection-mode socket is able to receive
and buffer that number of packets. Whenever the service user (the
application) retrieves one or more messages from the socket, reception
of the messages will be acknowledged to the remote SAP.

A common application architecture is that messages are received in a
dedicated thread and then added to a message queue that the
application will query for data to process at a later time. Unless the
message queue can grow indefinitely it may happen that the receive
thread is unable to add more data to the queue because the application
is not consuming data for some reason. For such situations LLCP
provides a mechanism to convey a *busy* indication to the remote
service user. In nfcpy an application uses :meth:`~Socket.setsockopt`
with option :const:`nfc.llcp.SO_RCVBSY` and value :const:`True` to set
the *busy* state or value :const:`False` to clear the *busy* state. An
application can use :meth:`~Socket.getsockopt` with option
:const:`nfc.llcp.SO_RCVBSSY` to learn it's own *busy* state and
:const:`nfc.llcp.SO_SNDBSY` to learn the remote application's *busy*
state.

