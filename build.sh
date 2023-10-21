#!/usr/bin/env bash
VERSION=4.1

docker build -t phil1pp/kaifareader:$VERSION .
docker push phil1pp/kaifareader:$VERSION
docker tag phil1pp/kaifareader:$VERSION phil1pp/kaifareader:latest
docker push phil1pp/kaifareader:latest
