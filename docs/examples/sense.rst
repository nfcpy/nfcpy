========
sense.py
========

The **sense** example demonstrates the use of the
:meth:`nfc.clf.ContactlessFrontend.sense` method to discover
contactless targets. ::

  $ sense.py [target [target ...]] [options]

The *target* arguments define the type, bitrate and optional
attributes for the contactless targets that may be discovered in a
single sense loop. An empty loop (no targets) is allowed but is only
useful to verify the :meth:`nfc.clf.ContactlessFrontend.sense` method
behavior. Optional arguments allow to set an iteration count and
interval, continously repeat the (iterated) loop after a wait time,
activate standard or verbose debug logs, and to specify the local
device to use.

A *target* is specified by bitrate and a type identifier ``A``, ``B``,
``F``. The following example would first sense for a DEP Target at
106kbps (in active communication mode), then for a Type A Target at
106 kbps, a Type B Target at 106kbps and a Type F Target at
212kbps. ::

  $ sense.py 106A 106B 212F

Additional parameters can be supplied as comma-delimited name=value
pairs in brackets. The example below searches for a 106 kbps DEP
Target (in active communication mode) and then changes communication
speed to 424 kbps. ::

  $ sense.py '106A(atr_req=d400FFFFFFFFFFFFFFFF62260000003246666d010110)'

  $ sense.py 106A --atr d400FFFFFFFFFFFFFFFF62260000003246666d010110

Options
=======

.. option:: -h, --help
   
   Show a help message and exit.

.. option:: --dep params

   Attempt a DEP Target activation in passive communication mode when
   an appropriate Type A or Type F Target was discovered in in the
   main sense loop. The *params* argument defines optional attributes
   for the :class:`nfc.clf.DEP` target object. The example below would
   try a DEP Target activation (in passive communication mode) with a
   parameter change to 424 kbps after 106 kbps Type A Target
   discovery. ::

     $ sense.py 106A --dep 'psl_req=D404001203'

.. option:: -i number
   
   Specifies the number of iterations to run (default is 1
   iteration). Each iteration is a sense for all the targets given as
   positional arguments.

.. option:: -t seconds
   
   The time between two iterations (default is 0.2 sec). It is
   measured from the start of one iteration to the start of the next
   iteration, effectively it will thus never be shorter than the
   execution time of an iteration.

.. option:: -r, --repeat
   
   Forever repeat the sense loop (including the number of
   iterations). Execution can be terminated with Ctrl-C.

.. option:: -w seconds
   
   Wait the specified number of seconds between repetitions (the
   default wait time is 0.1 sec).

.. option:: -d, --debug
   
   Activate debug log messages on standard error output.

.. option:: -v, --verbose
   
   Activate more debug log messages, most notably all commands send to
   the local device will be logged as well as their responses.

.. option:: --device path
   
   Specify a local device search path (the default is ``usb``). For device
   path construction rules see :meth:`nfc.clf.ContactlessFrontend.open`.

