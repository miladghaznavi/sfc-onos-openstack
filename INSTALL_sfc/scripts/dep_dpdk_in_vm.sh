# check CPU-Flags (ssse3 avx aes)

sudo apt-get update
sudo apt-get install -y build-essential linux-generic linux-headers-generic
sudo apt-get install -y git zip python libconfig-dev;\
wget http://fast.dpdk.org/rel/dpdk-16.04.tar.xz;\
tar xf dpdk-16.04.tar.xz;\
mv dpdk-16.04 dpdk;\
rm dpdk-16.04.tar.xz

# git clone https://github.com/weichweich/sfc-onos-openstack.git && source sfc-onos-openstack/INSTALL_sfc/scripts/setup_vm.sh
# source sfc-onos-openstack/INSTALL_sfc/scripts/setup_vm.sh
# sudo ./simple_bench/build/simple_bench -n 3 -b 0000:00:03.0 -- <config>
# sudo ./build/packet_gen -n 1 -b 0000:00:03.0 -- -s 10.1.0.3 -d 10.1.0.8 -m 02:00:00:00:00:00
# sudo ./build/logging -n 1 -b 0000:00:03.0
# top -b -p `5690` -n 100