#!/bin/bash

DIR_NAME=$1
VM_NUM=$2
KEY_PATH=~/DevEnv/devstack/osKey.pem

source /home/weich/DevEnv/devstack/openrc admin
zip -r $DIR_NAME'.zip' $DIR_NAME

IP_ADDR=$(nova floating-ip-list |grep 'public' | sed -n $VM_NUM'p'| awk '{print $4}')
DEPLOY_CMD='rm -r '$DIR_NAME'; unzip '$DIR_NAME'.zip && cd '$DIR_NAME' && export RTE_SDK=/home/ubuntu/dpdk && make'

scp -i $KEY_PATH $DIR_NAME'.zip' ubuntu@$IP_ADDR:~
ssh -i $KEY_PATH ubuntu@$IP_ADDR $DEPLOY_CMD

