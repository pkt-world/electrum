#!/bin/bash
cd "${GITHUB_WORKSPACE}"

if [ "${GITHUB_REF_TYPE}" != tag ]; then
  echo "GITHUB_REF_TYPE=${GITHUB_REF_TYPE} - not releasing"
  CODESIGN_CERT=
  ./contrib/osx/make_osx || exit 100
else
  echo "GITHUB_REF_TYPE=${GITHUB_REF_TYPE} - RELEASE!"
  ./contrib/osx/make_osx || exit 100
fi

