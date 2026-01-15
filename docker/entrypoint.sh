#!/bin/bash
set -e

# If arguments are provided, pass them to secuscan
exec secuscan "$@"
