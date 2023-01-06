#!/usr/bin/env bash
VERSION=3.0

docker build -t phil1pp/kaifareader:$VERSION .
docker push phil1pp/kaifareader:$VERSION
docker tag phil1pp/kaifareader:$VERSION phil1pp/kaifareader:latest
docker push phil1pp/kaifareader:latest
