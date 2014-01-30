.. _snep-tutorial:
.. currentmodule:: nfc.snep

*****************************
Simple NDEF Exchange Protocol
*****************************

The NFC Forum Simple NDEF Exchange Protocol (SNEP) allows two NFC
devices to exchange NDEF Messages. It is implemented in many
smartphones and typically used to push phonebook contacts or web page
URLs to another phone.

SNEP is a stateless request/response protocol. The client sends a
request to the server, the server processes that request and returns a
response. On the protocol level both the request and response have no
consequences for further request/response exchanges. Information units
transmitted through SNEP are NDEF messages. The client may use a SNEP
PUT request to send an NDEF message and a SNEP GET request to retrieve
an NDEF message. The message to retrieve with a GET request depends on
an NDEF message sent with the GET request but the rules to determine
equivalence are an application layer contract and not specified by
SNEP.

NDEF messages can easily be larger than the maximum information unit
(MIU) supported by the LLCP data link connection that a SNEP client
establishes with a SNEP server. The SNEP layer handles fragmentation
and reassembly so that an application must not be concerned. To avoid
exhaustion of the limited NFC bandwidth if an NDEF message would
exceed the SNEP receiver's capabilities, the receiver must acknowledge
the first fragment of an NDEF message that can not be transmitted in a
single MIU. The acknowledge can be either the request/response codes
CONTINUE or REJECT. If CONTINUE is received, the SNEP sender shall
transmit all further fragments without further acknowledgement (the
LLCP data link connection guarantees successful transmission). If
REJECT isreceived, the SNEP sender shall abort
tranmsission. Fragmentation and reassembly are handled transparently
by the :class:`nfc.snep.SnepClient` and :class:`nfc.snep.SnepServer`
implementation and only a REJECT would be visible to the user.

A SNEP server may return other response codes depending on the
result of a request:

* A SUCCESS response indicates that the request has succeeded. For a
  GET request the response will include an NDEF message. For a PUT
  request the response is empty.
* A NOT FOUND response says that the server has not found anything
  matching the request. This may be a temporary of permanent
  situation, i.e. the same request send later could yield a different
  response.
* An EXCESS DATA response may be received if the server has found a
  matching response but sending it would exhaust the SNEP client's
  receive capabilities.
* A BAD REQUEST response indicates that the server detected a syntax
  error in the client's request. This should almost never be seen.
* The NOT IMPLEMENTED response will be returned if the client sent a
  request that the server has not implemented. It applies to existing
  as well as yet undefined (future) request codes. The client can
  learn the difference from the version field transmitted withnthe
  response, but in reality it doesn't matter - it's just not
  supported.
* With UNSUPPORTED VERSION the server reacts to a SNEP version number
  sent with the request that it doesn't support or refuses to
  support. This should be seen only if the client sends with a higher
  major version number than the server has implemented. It could be
  received also if the client sends with a lower major version number
  but SNEP servers are likely to support historic major versions if
  that ever happens (the current SNEP version is 1.0).

Besides the protocol layer the SNEP specification also defines a
*Default SNEP Server* with the well-known LLCP service access point
address 4 and service name `urn:nfc:sn:snep`. Certified NFC Forum
Devices must have the *Default SNEP Server* implemented. Due to that
requirement the feature set and guarantees of the *Default SNEP
Server* are quite limited - it only implements the PUT request and the
NDEF message to put could be rejected if it is more than 1024 octets,
though smartphones generally seem to support more.

Default Server
--------------

A basic *Default SNEP Server* can be built with *nfcpy* like in the
following example, where all error and exception handling has been sacrified for brevity. ::

  import nfc
  import nfc.snep
  
  class DefaultSnepServer(nfc.snep.SnepServer):
      def __init__(self, llc):
          nfc.snep.SnepServer.__init__(self, llc, "urn:nfc:sn:snep")

      def put(self, ndef_message):
          print "client has put an NDEF message"
          print ndef_message.pretty()
          return nfc.snep.Success

  def startup(clf, llc):
      global my_snep_server
      my_snep_server = DefaultSnepServer(llc)
      return llc

  def connected(llc):
      my_snep_server.start()
      return True

  my_snep_server = None
  clf = nfc.ContactlessFrontend("usb")
  clf.connect(llcp={'on-startup': startup, 'on-connect': connected})

This server will accept PUT requests with NDEF messages up to 1024
octets and return NOT IMPLEMENTED for any GET request. To increase the
size of NDEF messages that can be received, the
*max_ndef_message_recv_size* parameter can be passed to the
:class:`nfc.snep.SnepServer` class. ::

  class DefaultSnepServer(nfc.snep.SnepServer):
      def __init__(self, llc):
          nfc.snep.SnepServer.__init__(self, llc, "urn:nfc:sn:snep", 10*1024)

Using SNEP Put
--------------

Sending an NDEF message to the *Default SNEP Server* is easily done
with an instance of :class:`nfc.snep.SnepClient` and is basically to
call :meth:`nfc.snep.SnepClient.put` with the message to send. The
example below shows how the function to send the NDEF message is
started as a separate thread - it cannot be directly called in
:func:`connected` because the main thread context is used to run the
LLCP link. ::

  import nfc
  import nfc.snep
  import threading

  def send_ndef_message(llc):
      sp = nfc.ndef.SmartPosterRecord('http://nfcpy.org', title='nfcpy home')
      snep = nfc.snep.SnepClient(llc)
      snep.put( nfc.ndef.Message(sp) )

  def connected(llc):
      threading.Thread(target=send_ndef_message, args=(llc,)).start()
      return True

  clf = nfc.ContactlessFrontend("usb")
  clf.connect(llcp={'on-connect': connected})

Some phones require that a SNEP be present even if they are not going
to send anything (Windows Phone 8 is such example). The solution is to
also run a SNEP server on `urn:nfc:sn:snep` which may just do
nothing. ::

  import nfc
  import nfc.snep
  import threading

  server = None

  def send_ndef_message(llc):
      sp = nfc.ndef.SmartPosterRecord('http://nfcpy.org', title='nfcpy home')
      snep = nfc.snep.SnepClient(llc)
      snep.put( nfc.ndef.Message(sp) )

  def startup(clf, llc):
      global server
      server = nfc.snep.SnepServer(llc, "urn:nfc:sn:snep")
      return llc

  def connected(llc):
      server.start()
      threading.Thread(target=send_ndef_message, args=(llc,)).start()
      return True

  clf = nfc.ContactlessFrontend("usb")
  clf.connect(llcp={'on-startup': startup, 'on-connect': connected})

Private Servers
---------------

The SNEP protocol can be used for other, non-standard, communication
between a server and client component. A private server can be run on
a dynamically assigned service access point if a private service name
is used. A private server may also implement the GET request if it
defines what a GET shall mean other than to return something. Below is
an example of a private SNEP server that implements bot PUT and GET
with the simple contract that whatever is put to the server will be
returned for a GET request that requests the same or empty NDEF type
and name values (for anything else the answer is NOT FOUND). ::

  import nfc
  import nfc.snep
  
  class PrivateSnepServer(nfc.snep.SnepServer):
      def __init__(self, llc):
          self.ndef_message = nfc.ndef.Message(nfc.ndef.Record())
          service_name = "urn:nfc:xsn:nfcpy.org:x-snep"
          nfc.snep.SnepServer.__init__(self, llc, service_name, 2048)
      
      def put(self, ndef_message):
          print "client has put an NDEF message"
          self.ndef_message = ndef_message
          return nfc.snep.Success
      
      def get(self, acceptable_length, ndef_message):
          print "client requests an NDEF message"
          if ((ndef_message.type == '' and ndef_message.name == '') or
              ((ndef_message.type == self.ndef_message.type) and
               (ndef_message.name == self.ndef_message.name))):
              if len(str(self.ndef_message)) > acceptable_length:
                  return nfc.snep.ExcessData
              return self.ndef_message
          return nfc.snep.NotFound
  
  def startup(clf, llc):
      global my_snep_server
      my_snep_server = PrivateSnepServer(llc)
      return llc
  
  def connected(llc):
      my_snep_server.start()
      return True
  
  my_snep_server = None
  clf = nfc.ContactlessFrontend("usb")
  clf.connect(llcp={'on-startup': startup, 'on-connect': connected})

A client application knowing the private server above may then use PUT
and GET to set an NDEF message on the server and retrieve it back. The
example code below also shows how results other than SUCCESS must be
catched in try-except clauses. Note that *max_ndef_msg_recv_size*
parameter is a policy sent to the SNEP server with every GET
request. It is a arbitrary restriction of the
:class:`nfc.snep.SnepClient` that this parameter can only be set when
the object is created; the SNEP protocol would allow it to be
different for every GET request but unless there's demand for such
flexibility that won't change. ::

  import nfc
  import nfc.snep
  import threading

  def send_ndef_message(llc):
      sp = nfc.ndef.SmartPosterRecord('http://nfcpy.org', title='nfcpy home')
      snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=2048)
      snep.connect("urn:nfc:xsn:nfcpy.org:x-snep")
      snep.put( nfc.ndef.Message(sp) )

      print "*** get whatever the server has ***"
      print snep.get().pretty()

      print "*** get a smart poster with no name ***"
      r = nfc.ndef.Record(record_type="urn:nfc:wkt:Sp", record_name="")
      print snep.get( nfc.ndef.Message(r) ).pretty()

      print "*** get something that isn't there ***"
      r = nfc.ndef.Record(record_type="urn:nfc:wkt:Uri")
      try:
          snep.get( nfc.ndef.Message(r) )
      except nfc.snep.SnepError as error:
          print repr(error)

  def connected(llc):
      threading.Thread(target=send_ndef_message, args=(llc,)).start()
      return True

  clf = nfc.ContactlessFrontend("usb")
  clf.connect(llcp={'on-connect': connected})


