#!/bin/bash

WORKDIR=./vendored-tar
TAG=$(git describe --tags)
echo "On tag ${TAG}"
# Remove the v prefix from semver versions.
if [[ "${TAG}" =~ ^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(|-.*)$ ]]; then
    TAG=${TAG:1}
fi
TARFILE=$PWD/hal-${TAG}-vendored.tar.gz


echo Creating tarball ${TARFILE}

rm -rf ${WORKDIR}
mkdir ${WORKDIR}

# Copy all relevant files
cp -r ./src/ ./Cargo.toml ./Cargo.lock ./LICENSE ./README.md ${WORKDIR}
pushd ${WORKDIR}

cargo vendor --locked ./vendor

mkdir ./.cargo
cat <<EOF > ./.cargo/config
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

tar -czf ${TARFILE} .

popd
rm -rf ${WORKDIR}

# Sign tarball with
# $ gpg --detach-sign --armor <tarbar>
