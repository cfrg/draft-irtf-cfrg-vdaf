#!/bin/bash

set -e

make |& \
	grep -v 'Warning: Found SVG with width or height specified, which will make the artwork not scale.  Specify a viewBox only to let the artwork scale.' | \
	(! grep -E "Warning|Error")
