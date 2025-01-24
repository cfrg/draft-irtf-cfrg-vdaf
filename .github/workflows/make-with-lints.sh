#!/bin/bash

set -e

make |& (! grep -E "Warning|Error")
