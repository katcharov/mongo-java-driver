#!/bin/bash

set -o xtrace
set -o errexit  # Exit the script with error if any of the commands fail


RELATIVE_DIR_PATH="$(dirname "${BASH_SOURCE:-$0}")"
. "${RELATIVE_DIR_PATH}/javaConfig.bash"

echo "Running MONGODB-OIDC-Azure authentication tests"

set +x # ensure no secrets are printed in log files


#if [ -z "${AZUREOIDC_AUDIENCE:-}" ]; then
#    echo "Must specify an AZUREOIDC_AUDIENCE"
#    exit 1
#fi
set +x   # turn off xtrace for this portion
export OIDC_ADMIN_USER=$AZUREOIDC_USERNAME
export OIDC_ADMIN_PWD=pwd123
set -x
export MONGODB_URI=${MONGODB_URI:-"mongodb://localhost"}
MONGODB_URI_SINGLE="${MONGODB_URI}/?authMechanism=MONGODB-OIDC"
MONGODB_URI_SINGLE="${MONGODB_URI_SINGLE}&authMechanismProperties=PROVIDER_NAME:azure"
export MONGODB_URI_SINGLE="${MONGODB_URI_SINGLE},TOKEN_AUDIENCE:${AZUREOIDC_AUDIENCE}"
export MONGODB_URI_MULTI=$MONGODB_URI_SINGLE

# As this script may be executed multiple times in a single task, with different values for MONGODB_URI, it's necessary
# to run cleanTest to ensure that the test actually executes each run
#./gradlew -PjavaVersion="${JAVA_VERSION}" -Dorg.mongodb.test.uri="${MONGODB_URI}" \
#-Dorg.mongodb.test.aws.credential.provider="${AWS_CREDENTIAL_PROVIDER}" \
#--stacktrace --debug --info --no-build-cache driver-core:cleanTest driver-core:test \
#--tests OidcAuthenticationProseTests
