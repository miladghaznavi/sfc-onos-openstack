# OPENSTACK and ONOS Integration

## Install OVS with NSH patch

```
chmod +x scripts/install_ovs.sh
./scripts/install_ovs.sh
```

## Install ONOS

Read the onos_install.sh and run it.

```
chmod +x scripts/install_onos.sh
./scripts/install_onos.sh
```

### Install below features on ONOS

```
feature:install onos-openflow
feature:install onos-openflow-base
feature:install onos-ovsdatabase
feature:install onos-ovsdb-base
feature:install onos-drivers-ovsdb
feature:install onos-ovsdb-provider-host
feature:install onos-app-vtn-onosfw
externalportname-set -n onos_port2
```

## Install OpenStack

```
git clone https://git.openstack.org/openstack-dev/devstack -b stable/mitaka
```

### configure Openstack

Copy the local.conf file to the devstack directory.

```
cp local.conf devstack/local.conf
```

### Remove existing openstack code for Fresh installation
```
rm -rf /opt/stack
```

### start Devstack
If there are probolems with mySQL or rabbit restart the PC and unstack three times.

```
./unstack.sh ;./clean.sh; ./stack.sh
```

## Modify for ONOS integration

```
git clone https://github.com/openstack/networking-onos.git
cd networking-onos
sudo python setup.py install
```

### ONOS credentials
Copy conf_onos.ini from ~/.../networking_onos/etc to /etc/neutron/plugins/ml2/ and modify /etc/neutron/plugins/ml2/conf_onos.ini with appropriate url, username and password

Url: http://127.0.0.1:8181/onos/vtn
vim 
user: karaf
password: karaf

### networking-onos setup

in /etc/neutron/plugins/ml2/ml2.conf replace

```
mechanism_drivers = ...
```

with

```
mechanism_drivers = onos_ml2
```

in /opt/stack/neutron/neutron*.egg-info/entry_points.txt

```
[neutron.ml2.mechanism_drivers]
...
onos_ml2 = networking_onos.plugins.ml2.driver:ONOSMechanismDriver

[neutron.service_plugins]
...
onos_router = networking_onos.plugins.l3.driver:ONOSL3Plugin
```

### for DNS

in /etc/neutron/dhcp_agent.ini

```
dnsmasq_dns_servers = 8.8.8.8, 8.8.4.4
```
restart q-dhcp

### /etc/libvirt/qemu.conf

  cgroup_controllers = [ "cpu", "devices", "memory", "blkio", "cpuset", "cpuacct" ]

  cgroup_device_acl = [
  "/dev/null", "/dev/full", "/dev/zero", "/dev/random",
  "/dev/urandom", "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
  "/dev/rtc", "/dev/hpet", "/dev/net/tun", "/mnt/huge",
  "/dev/vhost-net"
  ]

  hugetlbfs_mount = "/mnt/huge"


### /etc/default/qemu-kvm

  VHOST_NET_ENABLED=1
  KVM_HUGEPAGES=1


### /etc/apparmor.d/abstractions/libvirt-qemu

On ubuntu, without this KVM won't be able to acces hugepages on `/mnt/huge`.
VM's WILL boot, but all network interfaces won't work.

    owner "/mnt/huge/libvirt/qemu/**" rw,
    /var/run/openvswitch/** rw,
    /run/openvswitch/** rw,


### with sed 
Configure ml2.conf, dhcp_agent.ini, entry_points.txt with sed:

```
sed -i 's/mechanism_drivers =.*/mechanism_drivers = onos_ml2/g' /etc/neutron/plugins/ml2/ml2_conf.ini
sed -i '/\[neutron.ml2.mechanism_drivers\]/a onos_ml2 = networking_onos.plugins.ml2.driver:ONOSMechanismDriver' /opt/stack/neutron/neutron*.egg-info/entry_points.txt
sed -i '/\[neutron.service_plugins\]/a onos_router = networking_onos.plugins.l3.driver:ONOSL3Plugin' /opt/stack/neutron/neutron*.egg-info/entry_points.txt
sed -i 's/#dnsmasq_dns_servers =.*/dnsmasq_dns_servers = 8.8.8.8, 8.8.4.4/g' /etc/neutron/dhcp_agent.ini
```

### for internet connectivity
replace `eth1` with the interface which has internet connectivity.

```
sudo sysctl net.ipv4.ip_forward=1 
sudo iptables -A FORWARD -d 172.24.4.0/24 -j ACCEPT 
sudo iptables -A FORWARD -s 172.24.4.0/24 -j ACCEPT 
sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE 
```

### restart Neutron

```
screen -x -r stack
```

ctrl+a+n until q-svc. restart all processes from q-svc to n-cpu.

start q-svc with (new conf_onos.ini config-file):

```
/usr/local/bin/neutron-server \
    --config-file /etc/neutron/neutron.conf \
    --config-file /etc/neutron/plugins/ml2/ml2_conf.ini \
    --config-file /etc/neutron/plugins/ml2/conf_onos.ini \
    & echo $! >/opt/stack/status/stack/q-svc.pid; fg || echo "q-svc failed to start" | tee "/opt/stack/status/stack/q-svc.failure"
```

### set ovs manager on compute node

```
sudo ovs-vsctl set-manager tcp:20.0.0.12:6640
```

### enable commandline
```
source openrc admin
```

### verify neutron is running
```
neutron net-list
```

### Test integration, create network

```
neutron net-create sfcNet
neutron subnet-create sfcNet 10.1.0.0/24 --name sfcSubNet
neutron router-create router2 
neutron router-interface-add router2 sfcSubNet
```

verify that network was created:
`http://<ip_onos>:8181/onos/vtn/networks`

### create image, ports and VMs


```
glance image-create --name ubuntu --disk-format qcow2 --container-format bare --file wily-server-cloudimg-amd64-disk1.img

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
          --key-name osKey --availability-zone nova:i72tb12 bench
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p02 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p03 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p04 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p05 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:i72tb12 w1
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p06 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p07 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p08 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p09 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:i72tb11 w2
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p10 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p11 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p12 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p13 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:i72tb11 w3
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p14 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p15 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:i72tb12 fw1
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p16 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p17 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:i72tb11 fw2
nova boot --image ubuntu --flavor sf.small --nic net-name=private \
          --nic port-id=$(neutron port-list |grep p18 |awk '{print $2}') \
          --nic port-id=$(neutron port-list |grep p19 |awk '{print $2}') \
          --key-name osKey --availability-zone nova:i72tb11 fw3

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
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.10 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.11 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.12 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.13 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.14 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.15 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.16 |awk '{print $2}')
neutron port-update --no-security-groups  --port-security-enabled=False \
        $(neutron port-list |grep 10.0.0.17 |awk '{print $2}')

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
```

### ssh into VMs

```
ssh -i osKey.pem ubuntu@$(nova floating-ip-list |grep 'public' | sed -n '1p'| awk '{print $4}')
ssh -i osKey.pem ubuntu@$(nova floating-ip-list |grep 'public' | sed -n '2p'| awk '{print $4}')
ssh -i osKey.pem ubuntu@$(nova floating-ip-list |grep 'public' | sed -n '3p'| awk '{print $4}')
ssh -i osKey.pem ubuntu@$(nova floating-ip-list |grep 'public' | sed -n '4p'| awk '{print $4}')
ssh -i osKey.pem ubuntu@$(nova floating-ip-list |grep 'public' | sed -n '5p'| awk '{print $4}')
ssh -i osKey.pem ubuntu@$(nova floating-ip-list |grep 'public' | sed -n '6p'| awk '{print $4}')
ssh -i osKey.pem ubuntu@$(nova floating-ip-list |grep 'public' | sed -n '7p'| awk '{print $4}')
```
### Setup NICs
setup the interfaces in the vms (src, dst, sf1, sf2)

```
sudo ip link set dev eth1 down
sudo dhclient eth1
```

only in sf1 und sf2

```
sudo ip link set dev eth2 down
sudo dhclient eth2
```

## setup the sfc (wrapper only)

### port pairs, pair group, Flow classifier, port chain
```
neutron port-pair-create PP_W1 --ingress p02 --egress p04 # w1
neutron port-pair-group-create --port-pair PP_W1 PPG_W1
neutron port-pair-create PP_W2 --ingress p06 --egress p08 # w2
neutron port-pair-group-create --port-pair PP_W2 PPG_W2
neutron port-pair-create PP_W3 --ingress p10 --egress p12 # w3
neutron port-pair-group-create --port-pair PP_W3 PPG_W3

neutron flow-classifier-create --source-ip-prefix 10.1.0.0/24 --destination-ip-prefix 10.1.0.0/24 --logical-source-port p01 FC1
neutron port-chain-create --port-pair-group PPG_W1 --port-pair-group PPG_W2  --port-pair-group PPG_W3 --flow-classifier FC1 PC1
```

--chain-parameters correlation=NSH

### delete port chain

```
neutron port-chain-delete PC1
neutron flow-classifier-delete FC1
neutron port-pair-group-delete PPG_W11
neutron port-pair-group-delete PPG_FW1
neutron port-pair-group-delete PPG_W12
neutron port-pair-group-delete PPG_W21
neutron port-pair-group-delete PPG_FW2
neutron port-pair-group-delete PPG_W22
neutron port-pair-group-delete PPG_W31
neutron port-pair-group-delete PPG_FW3
neutron port-pair-group-delete PPG_W32
neutron port-pair-delete PP_W11
neutron port-pair-delete PP_FW1
neutron port-pair-delete PP_W12
neutron port-pair-delete PP_W21
neutron port-pair-delete PP_FW2
neutron port-pair-delete PP_W22
neutron port-pair-delete PP_W31
neutron port-pair-delete PP_FW3
neutron port-pair-delete PP_W32
```

## sfc wrapper and firewall

```
# -> w1 -> fw
neutron port-pair-create PP_W11 --ingress p02 --egress p03
neutron port-pair-group-create --port-pair PP_W11 PPG_W11
# fw1 to w1
neutron port-pair-create PP_FW1 --ingress p14 --egress p15
neutron port-pair-group-create --port-pair PP_FW1 PPG_FW1
# w1 to w2
neutron port-pair-create PP_W12 --ingress p04 --egress p05
neutron port-pair-group-create --port-pair PP_W12 PPG_W12

# w2 to fw
neutron port-pair-create PP_W21 --ingress p06 --egress p07
neutron port-pair-group-create --port-pair PP_W21 PPG_W21
# fw2 to w3
neutron port-pair-create PP_FW2 --ingress p16 --egress p17
neutron port-pair-group-create --port-pair PP_FW2 PPG_FW2
# w2 to w3
neutron port-pair-create PP_W22 --ingress p08 --egress p09
neutron port-pair-group-create --port-pair PP_W22 PPG_W22

# w3 to fw
neutron port-pair-create PP_W31 --ingress p10 --egress p11
neutron port-pair-group-create --port-pair PP_W31 PPG_W31
# fw3 to w3
neutron port-pair-create PP_FW3 --ingress p18 --egress p19
neutron port-pair-group-create --port-pair PP_FW3 PPG_FW3
# w3 to end
neutron port-pair-create PP_W32 --ingress p12 --egress p13
neutron port-pair-group-create --port-pair PP_W32 PPG_W32

neutron flow-classifier-create --source-ip-prefix 10.1.0.0/24 \
    --destination-ip-prefix 10.1.0.0/24 --logical-source-port p01 FC1

neutron port-chain-create --flow-classifier FC1 PC1 \
    --port-pair-group PPG_W11 --port-pair-group PPG_FW1  --port-pair-group PPG_W12 \
    --port-pair-group PPG_W21 --port-pair-group PPG_FW2  --port-pair-group PPG_W22 \
    --port-pair-group PPG_W31 --port-pair-group PPG_FW3  --port-pair-group PPG_W32
```
