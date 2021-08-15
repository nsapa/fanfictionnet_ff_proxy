#!/bin/bash

set -e
set -x

TEMPDIR=$(mktemp -d)
ICODIR=$(pwd)

SVGFILE="${ICODIR}/aiohttp.svg"

pushd $TEMPDIR

# Create PNG from the SVG
inkscape -w 16 -h 16 -o 16.png "${SVGFILE}"
inkscape -w 32 -h 32 -o 32.png "${SVGFILE}"
inkscape -w 48 -h 48 -o 48.png "${SVGFILE}"

# Convert the PNG to a ico
convert 16.png 32.png 48.png icon.ico

# Move back the generated ico
mv icon.ico "${ICODIR}"

popd

# Remove temp dir
rm -rf -- "${TEMPDIR}"
