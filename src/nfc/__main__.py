# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2016 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import nfc
import nfc.clf.device
import nfc.clf.transport

import os
import errno
import logging
import platform
import argparse
import subprocess

description = """

The nfcpy module implements a near field communication software stack
for reading and writing NFC Tags or peer-to-peer communication with
another NFC Device. It requires an NFC radio module connected through
either USB or serial interface. The nfcpy module is supposed to be
used within other applications, executing it as a module will try to
locate contactless devices connected to this machine.

"""


def main(args):
    print("This is the %s version of nfcpy run in Python %s\non %s" %
          (nfc.__version__, platform.python_version(), platform.platform()))
    print("I'm now searching your system for contactless devices")

    logging.basicConfig()
    log_levels = (logging.WARN, logging.INFO, logging.DEBUG, logging.DEBUG-1)
    log_level = log_levels[min(args.verbose, len(log_levels) - 1)]
    logging.getLogger('nfc').setLevel(log_level)

    found = 0
    for vid, pid, bus, dev in nfc.clf.transport.USB.find("usb"):
        if (vid, pid) in nfc.clf.device.usb_device_map:
            path = "usb:{0:03d}:{1:03d}".format(bus, dev)
            try:
                clf = nfc.ContactlessFrontend(path)
                print("** found %s" % clf.device)
                clf.close()
                found += 1
            except IOError as error:
                if error.errno == errno.EACCES:
                    usb_device_access_denied(bus, dev, vid, pid, path)
                elif error.errno == errno.EBUSY:
                    usb_device_found_is_busy(bus, dev, vid, pid, path)

    if args.search_tty:
        for dev in nfc.clf.transport.TTY.find("tty")[0]:
            path = "tty:{0}".format(dev[8:])
            try:
                clf = nfc.ContactlessFrontend(path)
                print("** found %s" % clf.device)
                clf.close()
                found += 1
            except IOError as error:
                if error.errno == errno.EACCES:
                    print("access denied for device with path %s" % path)
                elif error.errno == errno.EBUSY:
                    print("the device with path %s is busy" % path)
    else:
        print("I'm not trying serial devices because you haven't told me")
        print("-- add the option '--search-tty' to have me looking")
        print("-- but beware that this may break other serial devs")

    if not found:
        print("Sorry, but I couldn't find any contactless device")


def usb_device_access_denied(bus, dev, vid, pid, path):
    info = "** found usb:{vid:04x}:{pid:04x} at {path} but access is denied"
    print(info.format(vid=vid, pid=pid, path=path))
    if platform.system().lower() == "linux":
        devnode = "/dev/bus/usb/{0:03d}/{1:03d}".format(bus, dev)
        if not os.access(devnode, os.R_OK | os.W_OK):
            import pwd
            import grp
            usrname = pwd.getpwuid(os.getuid()).pw_name
            devinfo = os.stat(devnode)
            dev_usr = pwd.getpwuid(devinfo.st_uid).pw_name
            dev_grp = grp.getgrgid(devinfo.st_gid).gr_name
            try:
                plugdev = grp.getgrnam("plugdev")
            except KeyError:
                plugdev = None

            udev_rule = 'SUBSYSTEM==\\"usb\\", ACTION==\\"add\\", ' \
                        'ATTRS{{idVendor}}==\\"{vid:04x}\\", ' \
                        'ATTRS{{idProduct}}==\\"{pid:04x}\\", ' \
                        '{action}'
            udev_file = "/etc/udev/rules.d/nfcdev.rules"

            print("-- the device is owned by '{dev_usr}' but you are '{user}'"
                  .format(dev_usr=dev_usr, user=usrname))
            print("-- also members of the '{dev_grp}' group would be permitted"
                  .format(dev_grp=dev_grp))
            print("-- you could use 'sudo' but this is not recommended")

            if plugdev is None:
                print("-- it's better to adjust the device permissions")
                action = 'MODE=\\"0666\\"'
                udev_rule = udev_rule.format(vid=vid, pid=pid, action=action)
                print("   sudo sh -c 'echo {udev_rule} >> {udev_file}'"
                      .format(udev_rule=udev_rule, udev_file=udev_file))
                print("   sudo udevadm control -R # then re-attach device")
            elif dev_grp != "plugdev":
                print("-- better assign the device to the 'plugdev' group")
                action = 'GROUP=\\"plugdev\\"'
                udev_rule = udev_rule.format(vid=vid, pid=pid, action=action)
                print("   sudo sh -c 'echo {udev_rule} >> {udev_file}'"
                      .format(udev_rule=udev_rule, udev_file=udev_file))
                print("   sudo udevadm control -R # then re-attach device")
                if usrname not in plugdev.gr_mem:
                    print("-- and make yourself member of the 'plugdev' group")
                    print("   sudo adduser {0} plugdev".format(usrname))
                    print("   su - {0} # or logout once".format(usrname))
            elif usrname not in plugdev.gr_mem:
                print("-- you should add yourself to the 'plugdev' group")
                print("   sudo adduser {0} plugdev".format(usrname))
                print("   su - {0} # or logout once".format(usrname))
            else:
                print("-- but unfortunately I have no better idea than that")


def usb_device_found_is_busy(bus, dev, vid, pid, path):
    info = "** found usb:{vid:04x}:{pid:04x} at {path} but it's already used"
    print(info.format(vid=vid, pid=pid, path=path))
    if platform.system().lower() == "linux":
        sysfs = '/sys/bus/usb/devices/'
        for entry in os.listdir(sysfs):
            if not entry.startswith("usb") and ':' not in entry:
                sysfs_device_entry = sysfs + entry + '/'
                busnum = open(sysfs_device_entry + 'busnum').read().strip()
                devnum = open(sysfs_device_entry + 'devnum').read().strip()
                if int(busnum) == bus and int(devnum) == dev:
                    break
        else:
            print("-- impossible but nothing found in /sys/bus/usb/devices")
            return

        # We now have the sysfs entry for the device in question. All
        # supported contactless devices have a single configuration
        # that will be listed if the device is used by another driver.

        blf = "/etc/modprobe.d/blacklist-nfc.conf"
        sysfs_config_entry = sysfs_device_entry[:-1] + ":1.0/"
        print("-- scan sysfs entry at '%s'" % sysfs_config_entry)
        driver = os.readlink(sysfs_config_entry + "driver").split('/')[-1]
        print("-- the device is used by the '%s' kernel driver" % driver)
        if os.access(sysfs_config_entry + "nfc", os.F_OK):
            print("-- this kernel driver belongs to the linux nfc subsystem")
            print("-- you can remove it to free the device for this session")
            print("   sudo modprobe -r %s" % driver)
            print("-- and blacklist the driver to prevent loading next time")
            print("   sudo sh -c 'echo blacklist %s >> %s'" % (driver, blf))
        elif driver == "usbfs":
            print("-- this indicates a user mode driver with libusb")
            devnode = "/dev/bus/usb/{0:03d}/{1:03d}".format(bus, dev)
            print("-- find the process that uses " + devnode)
            try:
                subprocess.check_output("which lsof".split())
            except subprocess.CalledProcessError:
                print("-- there is no 'lsof' command, can't help further")
            else:
                lsof = "lsof -t " + devnode
                try:
                    pid = subprocess.check_output(lsof.split()).strip()
                except subprocess.CalledProcessError:
                    pid = None
                if pid is not None:
                    ps = "ps --no-headers -o cmd -p %s" % pid
                    cmd = subprocess.check_output(ps.split()).strip()
                    cwd = os.readlink("/proc/%s/cwd" % pid)
                    print("-- found that process %s uses the device" % pid)
                    print("-- process %s is '%s'" % (pid, cmd))
                    print("-- in directory '%s'" % cwd)
                else:
                    print("   ps --no-headers -o cmd -p `sudo %s`" % lsof)


parser = argparse.ArgumentParser(
    prog="python -m nfc", description=description)

parser.add_argument(
    "--search-tty", action="store_true",
    help="do also search for serial devices on linux")

parser.add_argument(
    "--verbose", "-v", action="count", default=0,
    help="be verbose. Multiple -v options increase the verbosity.")

main(parser.parse_args())
