#!/usr/bin/env python3

import os
import logging
from pathlib import Path

from boa3.boa3 import Boa3
from boa3.builtin.type import UInt160
from boa3.neo.cryptography import hash160

from contextlib import contextmanager
import sys, os

@contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout

#def fix_files():
#    for filename in os.listdir(CONTRACT_DIR):
#        os.rename(CONTRACT_DIR + filename, CONTRACT_DIR + filename.replace('_cleaned', ''))


#def cleanup(cleaned=False):
#    if not cleaned:
#        if os.path.exists(CONTRACT_PATH_NEF):
#            os.remove(CONTRACT_PATH_NEF)
#        if os.path.exists(CONTRACT_PATH_NEFDBG):
#            os.remove(CONTRACT_PATH_NEFDBG)
#        if os.path.exists(CONTRACT_PATH_JSON):
#            os.remove(CONTRACT_PATH_JSON)
#    else: 
#        if os.path.exists(CONTRACT_PATH_PY_CLEANED):
#            os.remove(CONTRACT_PATH_PY_CLEANED)

def preprocess_contract(to_remove, path, path_cleaned):
    with open(path) as oldfile, open(path_cleaned, 'w') as newfile:
        debug_block = False
        for line in oldfile:

            if any(dbg_block in line for dbg_block in list(debug_block_start)):
                print("found start")
                debug_block = True

            if any(dbg_block in line for dbg_block in list(debug_block_end)):
                print("found end")
                debug_block = False
                continue

            if debug_block:
                continue

            if not any(to_remove in line for to_remove in to_remove):
                newfile.write(line)

def build_contract(path):
    Boa3.compile_and_save(path)

GHOST_ROOT = str(os.getcwd())
to_remove = ['debug(']
debug_block_start = ['#DEBUG_START']
debug_block_end = ['#DEBUG_END']

CONTRACT_DIR = GHOST_ROOT + '/contracts/NEP11/'
CONTRACT_PATH_PY = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.debug.py'
CONTRACT_PATH_JSON = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.debug.manifest.json'
CONTRACT_PATH_NEFDBG = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.debug.nefdbgnfo'
CONTRACT_PATH_NEF = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.debug.nef'

CONTRACT_PATH_PY_CLEANED = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.py'

preprocess_contract(to_remove, CONTRACT_PATH_PY, CONTRACT_PATH_PY_CLEANED)
with suppress_stdout():
    build_contract(CONTRACT_PATH_PY_CLEANED)


