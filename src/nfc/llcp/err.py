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
import os
import errno


class Error(IOError):
    def __init__(self, errno):
        super(Error, self).__init__(errno, os.strerror(errno))

    def __str__(self):
        return "nfc.llcp.Error: [{0}] {1}".format(
            errno.errorcode[self.errno], self.strerror)


class ConnectRefused(Error):
    def __init__(self, reason):
        super(ConnectRefused, self).__init__(errno.ECONNREFUSED)
        self.reason = reason

    def __str__(self):
        return "nfc.llcp.ConnectRefused: [{0}] {1} with reason {2}".format(
            errno.errorcode[self.errno], self.strerror, self.reason)
