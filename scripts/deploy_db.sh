#!/bin/bash

DIR_NAME=$1 
zip -r $DIR_NAME'.zip' $DIR_NAME >/dev/null
mv $DIR_NAME'.zip' ~/Dropbox/$DIR_NAME'.zip'
date
echo 'done.'