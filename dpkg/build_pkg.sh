#!/bin/sh

cd content

mkdir -p usr/lib/kaifareader/
mkdir -p etc/kaifareader/
mkdir -p lib/systemd/system/

# copy files to debian package structure
cp -v ../../kaifareader.py usr/lib/kaifareader/
cp -v ../../meter.json etc/kaifareader/
cp -v ../../systemd/kaifareader.service lib/systemd/system/

dpkg-buildpackage -uc -us

if [ $? -ne 0 ]; then
  echo "Error creating debian package"
  exit 1
fi

cd ..
