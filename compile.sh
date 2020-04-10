#!/bin/bash

DIR="./build"
OS="linux"
ARCH="amd64"

if [ ! -d "$DIR" ]; then
  mkdir build
fi

CGO_ENABLED=0 GOARM=5 gox -ldflags "-w -X main.version=$(git describe --always)" \
-os=$OS -arch=$ARCH -output "build/pkg/{{.OS}}_{{.Arch}}/{{.Dir}}" \
./cmd/tunnel ./cmd/tunneld
