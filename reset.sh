#!/bin/bash
dotnet neoxp reset --force

./compile.py
./compile2.py

rm -rf checkpoints
./setup-express.sh
