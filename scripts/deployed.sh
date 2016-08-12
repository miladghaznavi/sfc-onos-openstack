#! /bin/bash

NAME=$1
URL=$2

echo 'remove old files'
echo ''
echo ''

rm -r $NAME
rm $NAME".zip"

echo 'get new'
echo ''

wget $URL

unzip $NAME
cd $NAME

echo '########## make:'
echo ''
echo ''

make
