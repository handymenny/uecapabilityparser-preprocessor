#!/usr/bin/env sh

python3 preprocessor.py "$@"
printf "%s " "Press enter to continue..."
read -r ans
