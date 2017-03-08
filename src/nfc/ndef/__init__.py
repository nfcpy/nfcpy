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
#
# NFC Data Exchange Format (NDEF) package
#
"""
Support for decoding and encoding of NFC Data Exchange Format (NDEF)
records and messages.
"""

from nfc.ndef.error import *
from nfc.ndef.message import Message
from nfc.ndef.record import Record
from nfc.ndef.text_record import TextRecord
from nfc.ndef.uri_record import UriRecord
from nfc.ndef.smart_poster import SmartPosterRecord
from nfc.ndef.handover import HandoverRequestMessage
from nfc.ndef.handover import HandoverSelectMessage
from nfc.ndef.handover import HandoverCarrierRecord
from nfc.ndef.bt_record import BluetoothConfigRecord
from nfc.ndef.wifi_record import WifiConfigRecord
from nfc.ndef.wifi_record import WifiPasswordRecord
