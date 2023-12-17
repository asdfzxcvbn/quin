#!/usr/bin/env python3
import os
import atexit
import zipfile
import argparse
from plistlib import load as pload
from subprocess import run, DEVNULL
from tempfile import NamedTemporaryFile as NTF

import lief

parser = argparse.ArgumentParser(description="quin: quickly inject dylibs into an IPA without unzipping.")
parser.add_argument("-i", metavar="ipa", type=str, required=True,
                    help="the ipa to inject into")
parser.add_argument("-f", metavar="dylib", type=str, nargs="+", required=True,
                    help="the dylibs to inject")
args = parser.parse_args()

# ipa checks
if not (IPA := os.path.realpath(args.i)).endswith(".ipa"):
    parser.error("input must be an ipa file")
elif not os.path.isfile(IPA):
    parser.error(f"'{IPA}' does not exist")
elif not zipfile.is_zipfile(IPA):
    parser.error(f"'{IPA}' is an invalid zipfile/ipa")

for dylib in (DYLIBS := {os.path.realpath(dylib) for dylib in args.f}):
    if not dylib.endswith(".dylib"):
        parser.error(f"'{dylib}' is not a dylib")
    elif not os.path.isfile(dylib):
        parser.error(f"'{dylib}' does not exist")


@atexit.register
def del_tmp():
    try:
        os.remove(temp_macho)
    except NameError:
        pass


with zipfile.ZipFile(IPA, "a") as zf:
    # get .app name
    for name in (nl := zf.namelist()):
        if len((spl := name.split("/"))) > 1 and spl[1].endswith(".app"):
            APP = spl[1]
            del spl
            break
    else:
        parser.error(f"couldn't find app in '{IPA}'")

    with zf.open(f"Payload/{APP}/Info.plist") as pl:
        EXEC_IPATH = f"Payload/{APP}/{pload(pl)['CFBundleExecutable']}"
    
    # write dylibs to ipa
    if f"Payload/{APP}/Frameworks/" not in nl:
        zf.mkdir(f"Payload/{APP}/Frameworks")
    for dylib in DYLIBS:
        zf.write(dylib, f"Payload/{APP}/Frameworks/{os.path.basename(dylib)}")

    # get executable as tmpfile
    with NTF(delete=False) as tmp:
        tmp.write(zf.read(EXEC_IPATH))

        # inject weak load commands to executable
        lief.logging.disable()
        executable = lief.parse((temp_macho := tmp.name))
        for dylib in DYLIBS:
            executable.add(lief.MachO.DylibCommand.weak_lib(f"@rpath/{os.path.basename(dylib)}"))
        executable.write(temp_macho)

# we need to delete the binary to remove it from the namelist, or else the ipa will just "break"
# since we're writing the modified executable back into the ipa
run(["zip", "-d", IPA, EXEC_IPATH], stdout=DEVNULL)
with zipfile.ZipFile(IPA, "a") as zf:
    zf.write(temp_macho, EXEC_IPATH)

print("[*] done!")