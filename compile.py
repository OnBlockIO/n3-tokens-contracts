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

def fix_files():
    for filename in os.listdir(CONTRACT_DIR):
        os.rename(CONTRACT_DIR + filename, CONTRACT_DIR + filename.replace('_cleaned', ''))


def cleanup(cleaned=False):
    if not cleaned:
        if os.path.exists(CONTRACT_PATH_NEF):
            os.remove(CONTRACT_PATH_NEF)
        if os.path.exists(CONTRACT_PATH_NEFDBG):
            os.remove(CONTRACT_PATH_NEFDBG)
        if os.path.exists(CONTRACT_PATH_JSON):
            os.remove(CONTRACT_PATH_JSON)
    else: 
        if os.path.exists(CONTRACT_PATH_PY_CLEANED):
            os.remove(CONTRACT_PATH_PY_CLEANED)

def preprocess_contract(to_remove, path, path_cleaned):
    with open(path) as oldfile, open(path_cleaned, 'w') as newfile:
        for line in oldfile:
            if not any(to_remove in line for to_remove in to_remove):
                newfile.write(line)

def build_contract(path):
    Boa3.compile_and_save(path)

GHOST_ROOT = str(os.getcwd())
to_remove = ['debug(']

CONTRACT_DIR = GHOST_ROOT + '/contracts/NEP11/'
CONTRACT_PATH_PY = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.py'
CONTRACT_PATH_JSON = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.manifest.json'
CONTRACT_PATH_NEFDBG = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.nefdbgnfo'
CONTRACT_PATH_NEF = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT.nef'

CONTRACT_PATH_PY_CLEANED = GHOST_ROOT + '/contracts/NEP11/GhostMarket.NFT_cleaned.py'

cleanup()
preprocess_contract(to_remove, CONTRACT_PATH_PY, CONTRACT_PATH_PY_CLEANED)
with suppress_stdout():
    build_contract(CONTRACT_PATH_PY_CLEANED)
cleanup(True)
fix_files()


