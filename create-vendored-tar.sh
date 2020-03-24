#!/bin/sh

WORKDIR=./vendored-tar
TARFILE=archived-tar.tar.gz

rm -rf ${WORKDIR}
mkdir ${WORKDIR}

# Copy all relevant files
cp -r ./src/ ./Cargo.toml ./Cargo.lock ./LICENSE ./README.md ${WORKDIR}
cd ${WORKDIR}

cargo vendor --locked ./vendor

mkdir ./.cargo
cat <<EOF > ./.cargo/config
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

tar -czf ${TARFILE} ./*

cd ..
mv ${WORKDIR}/${TARFILE} .
rm -rf ${WORKDIR}
