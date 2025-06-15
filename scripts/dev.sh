#!/bin/sh

set -e

rojo serve dev.project.json \
    & rojo sourcemap dev.project.json -o sourcemap.json --watch