#!/bin/sh

if [! -f "./awstools.py" ];
  echo "Unable to find awstools.py"
  exit 1
fi

mkdir -p $HOME/awstools
cp ./awstools.py $HOME/awstools

if [ "$SHELL" == "/bin/bash" ];
then
  ALIAS_FILE=".bash_profile"

elif [ "$SHELL" == "/bin/zsh" ];
then
  ALIAS_FILE=".zshrc"
else
  echo "unsupported shell"
  exit 1
fi

grep "alias awstools=" "${HOME}/${ALIAS_FILE}" >/dev/null 2>&1

if [ "$?" -eq 0 ];
then
  sed -i 's@alias awstools=.*@alias awstools='"'python3 ${HOME}/awstools/awstools.py'"'@' "${HOME}/${ALIAS_FILE}"
else
  echo "" >> "${HOME}/${ALIAS_FILE}"
  echo "alias awstools='python3 ${HOME}/awstools/awstools.py'" >> "${HOME}/${ALIAS_FILE}"
fi

