#!/bin/bash
# *********************************************************************
# Script: awsswitchrole.sh
# Author: Richard Knechtel
# Date: 08/05/2021
# Description: This will switch user to sepcified role and set
#              necessary environmetn variables.
#
# Parameters: Role ARN
#               Note: This comes from: .aws/config
#             Role Session Name
#
# Note: Requires program: jq
#       sudo apt-get install -y jq
#
#       Requires AWS CLI
#       Install AWS CLI in Linux:
#       curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
#       unzip awscliv2.zip
#       sudo ./aws/install
#
# Immportant: These work in Bash - they have issues in ZShell.
#
# Example Call (bash)
# source awsswitchrole.sh <ROLE ARN> <ROLE SESSION NAME>
#
#
# *********************************************************************

echo
echo "Running as user: $USER"
echo

# Get parameters
#echo Parameters Passed = $1
#echo

ROLE_ARN=$1
ROLE_SESSION_NAME=$2

usage()
{
  echo "[USAGE]: awsswitchrole.sh arg1 arg1"
  echo "arg1 = Role ARN (from .aws/config) (Example: arn:aws:iam::412098244858:role/production-admin-cross-account-role)"
  echo "arg2 = Role Session Name (Example: AWSCLI-Session)"
  echo "NOTE: Requires AWSCLI and program jq !"
}


# Check if we got ALL parameters
if [ $# -eq 0 ]  && [ -z "${ROLE_ARN}" ]&& [ -z "${ROLE_SESSION_NAME}" ]
 then
  usage
  return 1
fi


function checkforjq() {

  # Set default value:
  SKIP_LIBJQL_CHECK="no"

  IS_INSTALLED=$(dpkg -l | grep "jq")
  if [ -z "${IS_INSTALLED}" ]; then
    INSTALL_JQ="yes"
  else
    #echo "Check if jq is installed"
    if [[ ${IS_INSTALLED} = *"jq"* ]]; then
      echo "jq is installed - continuing"
      INSTALL_JQ="no"
      SKIP_LIBJQL_CHECK="yes"
    fi

    #echo "Checkif if only libjql is installed, if so intall jq command"
    if [[ ${SKIP_LIBJQL_CHECK} = "no" ]] && [[ ${IS_INSTALLED} != *"libjql"* ]]; then
      INSTALL_JQ="yes"
    fi

  fi

  if [[ ${INSTALL_JQ} = "yes" ]]; then
    echo "Required jq is not installed, installing"
    sudo apt install jq
  fi

  return 0
}


# Requires program: jq
# Uncomment to check if you have jq installed, if not it will install for you (on Ubuntu)
# Note: Also picks up libjq1
echo "Checking if required jq command is installed"
checkforjq

# STS_CREDS=`aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$ROLE_SESSION_NAME" --duration-seconds 43200`
STS_CREDS=`aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$ROLE_SESSION_NAME" --duration-seconds 21600`

#echo "STS_CREDS = " $STS_CREDS

export AWS_ACCESS_KEY_ID=$(echo $STS_CREDS | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $STS_CREDS | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $STS_CREDS | jq -r .Credentials.SessionToken)


# END

