.. nfcpy documentation master file, created by
   sphinx-quickstart on Mon Sep 19 18:10:55 2011.

===================
nfcpy documentation
===================

The *nfcpy* module implements NFC Forum specifications for wireless short-range data exchange with NFC devices and tags. It is written in Python and aims to provide an easy-to-use, yet powerful NFC API for Python applications.

.. warning::

   The documentation is work in progress and pretty much
   incomplete. Bear with me that this changes.

.. toctree::
   :hidden:

   overview

:doc:`overview`
   Hardware and software requirements, implementation status and references.

Concepts
========

.. toctree::
   :hidden:

   topics/clf
   topics/tag
   topics/ndef

:doc:`topics/clf`
    Find and use NFC contactless readers.

:doc:`topics/tag`
    Supported tag types and how to use them.

:doc:`topics/ndef`
    How to parse or generate NDEF records and messages.

Examples
========

.. toctree::
   :hidden:

   examples/helloworld

:doc:`examples/helloworld`
   A straightforward example of NDEF encoding and decoding with NFC tags.

Reference
=========

.. toctree::
   :hidden:

   reference

:doc:`reference`

Indices
=======

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

