#! /bin/bash

IMG_PATH='../wily-server-cloudimg-amd64-disk1.img'
HOST_1='10gbe1'
HOST_2='10gbe2'

glance image-create --name ubuntu --disk-format qcow2 --container-format bare --file $IMG_PATH

neutron net-create sfcNet
neutron subnet-create sfcNet 10.1.0.0/24 --name sfcSubNet
neutron router-create router2 
neutron router-interface-add router2 sfcSubNet

neutron port-create --name p01 sfcNet
neutron port-create --name p02 sfcNet
neutron port-create --name p03 sfcNet
neutron port-create --name p04 sfcNet
neutron port-create --name p05 sfcNet
neutron port-create --name p06 sfcNet
neutron port-create --name p07 sfcNet
neutron port-create --name p08 sfcNet
neutron port-create --name p09 sfcNet
neutron port-create --name p10 sfcNet
neutron port-create --name p11 sfcNet
neutron port-create --name p12 sfcNet
neutron port-create --name p13 sfcNet
neutron port-create --name p14 sfcNet
neutron port-create --name p15 sfcNet
neutron port-create --name p16 sfcNet
neutron port-create --name p17 sfcNet
neutron port-create --name p18 sfcNet
neutron port-create --name p19 sfcNet
neutron port-create --name p20 sfcNet

neutron port-update p01 --no-security-groups --port-security-enabled=False
neutron port-update p02 --no-security-groups --port-security-enabled=False
neutron port-update p03 --no-security-groups --port-security-enabled=False
neutron port-update p04 --no-security-groups --port-security-enabled=False
neutron port-update p05 --no-security-groups --port-security-enabled=False
neutron port-update p06 --no-security-groups --port-security-enabled=False
neutron port-update p07 --no-security-groups --port-security-enabled=False
neutron port-update p08 --no-security-groups --port-security-enabled=False
neutron port-update p09 --no-security-groups --port-security-enabled=False
neutron port-update p10 --no-security-groups --port-security-enabled=False
neutron port-update p11 --no-security-groups --port-security-enabled=False
neutron port-update p12 --no-security-groups --port-security-enabled=False
neutron port-update p13 --no-security-groups --port-security-enabled=False
neutron port-update p14 --no-security-groups --port-security-enabled=False
neutron port-update p15 --no-security-groups --port-security-enabled=False
neutron port-update p16 --no-security-groups --port-security-enabled=False
neutron port-update p17 --no-security-groups --port-security-enabled=False
neutron port-update p18 --no-security-groups --port-security-enabled=False
neutron port-update p19 --no-security-groups --port-security-enabled=False
neutron port-update p20 --no-security-groups --port-security-enabled=False

#nova keypair-delete osKey
rm ~/.ssh/known_hosts # think twice about this!
rm osKey.pem
nova keypair-add osKey > osKey.pem
chmod 600 osKey.pem

openstack flavor create --ram 1024 --disk 10 --vcpus 1 sf.small
#nova flavor-key sf.small set "hw:mem_page_size=large"

nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p01 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p20 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:$HOST_1 bench
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p02 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p03 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p04 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p05 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:$HOST_1 w1
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p06 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p07 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p08 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p09 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:$HOST_2 w2
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p10 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p11 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p12 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p13 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:$HOST_2 w3
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p14 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p15 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:$HOST_1 fw1
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p16 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p17 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:$HOST_2 fw2
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p18 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p19 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:$HOST_2 fw3

neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.3 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.4 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.5 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.6 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.7 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.8 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.9 |awk '{print $2}')

nova floating-ip-create public;\
    nova floating-ip-create public;\
    nova floating-ip-create public;\
    nova floating-ip-create public;\
    nova floating-ip-create public;\
    nova floating-ip-create public;\
    nova floating-ip-create public

nova floating-ip-associate bench $(nova floating-ip-list |grep 'public' | sed -n '1p'| awk '{print $4}')
nova floating-ip-associate w1 $(nova floating-ip-list |grep 'public' | sed -n '2p'| awk '{print $4}')
nova floating-ip-associate w2 $(nova floating-ip-list |grep 'public' | sed -n '3p'| awk '{print $4}')
nova floating-ip-associate w3 $(nova floating-ip-list |grep 'public' | sed -n '4p'| awk '{print $4}')
nova floating-ip-associate fw1 $(nova floating-ip-list |grep 'public' | sed -n '5p'| awk '{print $4}')
nova floating-ip-associate fw2 $(nova floating-ip-list |grep 'public' | sed -n '6p'| awk '{print $4}')
nova floating-ip-associate fw3 $(nova floating-ip-list |grep 'public' | sed -n '7p'| awk '{print $4}')
