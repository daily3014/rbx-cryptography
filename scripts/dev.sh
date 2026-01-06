#!/bin/sh

set -e

rojo.exe serve dev.project.json \
    & rojo.exe sourcemap dev.project.json -o sourcemap.json --watch
