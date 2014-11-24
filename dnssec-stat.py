#!/bin/env python

# The MIT License (MIT)
#
# Copyright (c) 2014 The Badmin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import os
import re
from time import strftime, gmtime
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--list", action="store_true",
                    help="List keys by zone")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Show status of all keys")
parser.add_argument("-K", "--keydir", nargs=1, type=str,
                    default="/etc/pki/dnssec-keys",
                    help="Directory to search for key files")
args = parser.parse_args()

def parse_keyfile(fname):
    kinfo = { 'type': "", 'id': None }

    for line in open(fname):
        match = re.search(r'zone-signing key, keyid (\d+), for (.*)\.$', line)
        if match:
            kinfo['id'] = match.group(1)
            kinfo['zone'] = match.group(2)
            kinfo['type'] += 'ZSK'

        match = re.search(r'key-signing key, keyid (\d+), for (.*)\.$', line)
        if match:
            kinfo['id'] = match.group(1)
            kinfo['zone'] = match.group(2)
            kinfo['type'] += 'KSK'

        match = re.search('Publish: ([0-9]+)', line)
        if match: kinfo['P'] = match.group(1)

        match = re.search('Activate: ([0-9]+)', line)
        if match: kinfo['A'] = match.group(1)

        match = re.search('Inactive: ([0-9]+)', line)
        if match: kinfo['I'] = match.group(1)

        match = re.search('Delete: ([0-9]+)', line)
        if match: kinfo['D'] = match.group(1)

    if fname.endswith(".key"): 
        try:
            kinfo['priv'] = parse_keyfile(fname[:-4]+".private")
        except:
            kinfo['priv'] = None

    return kinfo

def check_key(kinfo):
    err = None

    if kinfo['type'] not in ['ZSK', 'KSK']:
        err = "Unknown key type"

    if kinfo['id'] and re.search(r'\+0*'+kinfo['id']+r'\.', fname) == None:
        err = "Filename does not match key ID"

    if kinfo['id'] and re.match(r'K'+kinfo['zone']+r'\.', fname) == None:
        err = "Filename does not match zone"

    if kinfo['P'] > kinfo['A']:
        err = "Publish date comes after activation date"

    if kinfo['A'] > kinfo['I']:
        err = "Activation date comes after inactivation date"

    if kinfo['I'] > kinfo['D']:
        err = "Inactivation date comes after deletion date"

    if kinfo['priv']:
        for dtype in ['P', 'A', 'I', 'D']:
            if kinfo[dtype] != kinfo['priv'][dtype]:
                err = "Date mismatch between public and private keys"

    if (err):
        print(args.keydir + fname + " is malformed: " + err)
        sys.exit(-1)

now = strftime("%Y%m%d%H%M%S", gmtime())
def complete_key(kinfo):
    if now < kinfo['P']:
        kinfo['state'] = 'U'
        kinfo['next'] = kinfo['P']

    if kinfo['P'] < now and now < kinfo['A']:
        kinfo['state'] = 'P'
        kinfo['next'] = kinfo['A']

    if kinfo['A'] < now and now < kinfo['I']:
        kinfo['state'] = 'A'
        kinfo['next'] = kinfo['I']

    if kinfo['I'] < now and now < kinfo['D']:
        kinfo['state'] = 'I'
        kinfo['next'] = kinfo['D']

    if kinfo['D'] < now:
        kinfo['state'] = 'D'
        kinfo['next'] = None

keys = {}
zones = {}
for fname in os.listdir(args.keydir):
    if not fname.startswith("K") or not fname.endswith(".key"):
        continue

    kname = fname[:-4]
    kinfo = parse_keyfile(args.keydir + "/" + fname)
    check_key(kinfo)
    complete_key(kinfo)
    keys[kname] = kinfo
    zones[kinfo['zone']] = None

def print_tasks():
    for name,key in keys.items():
        line = None
        if key['state'] == 'D':
            line = name + " may be deleted."
        if key['state'] == 'P' and not key['priv']:
            line = name + " needs a private key before activation."
        if key['state'] == 'A' and not key['priv']:
            line = name + " is activated, but has no private key."
        if key['state'] == 'I' and not key['priv']:
            line = name + " is inactivated, but has no private key."
        if line:
            print(line)

    for zone in zones:
        line = None
        if 'A' not in [key['state'] for name,key in keys.items()
                       if key['zone'] == zone and key['type'] == "KSK"]:
            line = zone + " has no active KSKs."
        if line: print(line)

        line = None
        if 'A' not in [key['state'] for name,key in keys.items()
                       if key['zone'] == zone and key['type'] == "ZSK"]:
            line = zone + " has no active ZSKs."
        if line: print(line)


def sort_klist(item):
    (name, key) = item;
    return key['zone'] + key['type'] + str(key['A'])

def print_keylist():
    for name,key in sorted(keys.items(), key=sort_klist):
        line = name
        if key['state'] == 'U': line += " Unpublished "
        if key['state'] == 'P': line += " Published "
        if key['state'] == 'A': line += " Activated "
        if key['state'] == 'I': line += " Inactivated "
        if key['state'] == 'D': line += " Deleted "
        line += key['type']

        if key['next']:
            line += " until " + key['next']
        else:
            line += " since " + key['D']

        if args.verbose or key['state'] != 'U':
            print(line)

if args.list:
    print_keylist()
else:
    print_tasks()
