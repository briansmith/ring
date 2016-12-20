#!/bin/sh

exec 1>&2

cargo fmt -- --write-mode=Diff
