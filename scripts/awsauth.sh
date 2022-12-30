# #!/bin/bash
# *********************************************************************
# Script: awsauth.sh
# Author: Richard Knechtel
# Date: 06/04/2021
# Description: This will get the AWS STS Session Token and set
#              necessary environmetn variables.
#
# Parameters: MFA Token Code
# Note: This comes from:
# 1Password --> Account --> one time password
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
# source awsauth.sh <TOKEN_CODE>
#
#
# *********************************************************************

echo
echo "Running as user: $USER"
echo

# Get parameters
#echo Parameters Passed = $1
#echo

TOKEN_CODE=$1

usage()
{
  echo "[USAGE]: awsauth.sh arg1"
  echo "arg1 = Token Code (from 1Password --> Account --> one time password) (Example: 123456)"
  echo "NOTE: Requires AWS CLI and program jq !"
}


# Check if we got ALL parameters
if [ $# -eq 0 ]  && [ -z "${TOKEN_CODE}" ]; then
 usage
 return 1 
fi

OS_TYPE=$OSTYPE
UNSUPPORTED_OS=0

function checkostype() {

  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    OS_TYPE="linux"
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Mac OSX
    OS_TYPE="mac"
  elif [[ "$OSTYPE" == "cygwin" ]]; then
    # POSIX compatibility layer and Linux environment emulation for Windows
    OS_TYPE="cygwin"
  elif [[ "$OSTYPE" == "msys" ]]; then
    # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
    OS_TYPE="windows"
  elif [[ "$OSTYPE" == "win32" ]]; then
    # I'm not sure this can happen.
    OS_TYPE="windows"
  elif [[ "$OSTYPE" == "freebsd"* ]]; then
    # FreeBSD
    OS_TYPE="freebsd"
  else
    # Unknown.
    OS_TYPE="unknown"
  fi

  return 0 
}

function checkforjq() {

  # Note To check for an install package on MAC:
  # pkgutil --pkgs=.\+Xjq.\+
  # To install on MAC:
  # brew install jq

  # Set default values:
  IS_INSTALLED="NULL"
  SKIP_LIBJQL_CHECK="no"
  checkostype

  echo "OS Type = $OS_TYPE"

  if [[ $OS_TYPE == "linux" ]]; then
    IS_INSTALLED=$(dpkg -l | grep "jq")
  elif [[ $OS_TYPE == "mac" ]]; then
    IS_INSTALLED=$(pkgutil --pkgs=.\+Xjq.\+)	
  fi
  
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

  # Check if JQ is installed, if not install it (based on OS Type)
  if [[ ${INSTALL_JQ} = "yes" ]]; then
    echo "Required jq is not installed, installing"

    if [[ $OS_TYPE == "linux" ]]; then
      sudo apt install jq
    elif [[ $OS_TYPE == "mac" ]]; then
      brew install jq
    else
      # We are not running on a supported OS
      echo "ALERT! This script does not support your OS yet. It only supports Ubuntu Linux and MAC OS. Exiting!"
      UNSUPPORTED_OS=1
    fi 

  fi

  return 0
}


# Requires program: jq
# Uncomment to check if you have jq installed, if not it will install for you (on Ubuntu)
# Note: Also picks up libjq1
echo "Checking if required jq command is installed"
checkforjq

#echo "Unsupoprted OS = $UNSUPPORTED_OS"

if [[ $UNSUPPORTED_OS == 0 ]]; then

  MFA_SERIAL_NUMBER=`aws iam list-mfa-devices | jq -r .MFADevices[0].SerialNumber`
  STS_CREDS=`aws sts get-session-token --serial-number "$MFA_SERIAL_NUMBER" --token-code "$TOKEN_CODE" --duration-seconds 43200`

  #echo "STS_CREDS = " $STS_CREDS

  export AWS_MFA_SERIAL_NUMBER=$MFA_SERIAL_NUMBER
  export AWS_ACCESS_KEY_ID=$(echo $STS_CREDS | jq -r .Credentials.AccessKeyId)
  export AWS_SECRET_ACCESS_KEY=$(echo $STS_CREDS | jq -r .Credentials.SecretAccessKey)
  export AWS_SESSION_TOKEN=$(echo $STS_CREDS | jq -r .Credentials.SessionToken)
 
 else
  echo "Exiting!"

fi


# END
