# check CPU-Flags (ssse3 avx aes)
sudo apt-get update && sudo apt-get install -y git zip build-essential linux-generic linux-headers-generic python
wget http://fast.dpdk.org/rel/dpdk-16.04.tar.xz
tar xf dpdk-16.04.tar.xz
mv dpdk-16.04 dpdk

# sudo ./l2fwd_filter/build/l2fwd_filter -n 3 -b 0000:00:03.0 -- -p 3
# sudo ./simple_bench/build/simple_bench -n 3 -b 0000:00:03.0 -- -p 3 -m 02:00:00:00:00:00 -s 10.1.0.3 -d 10.1.0.9
# sudo ./packet_gen/build/packet_gen -n 1 -b 0000:00:03.0 -b 0000:00:05.0 -- -s 10.1.0.3 -d 10.1.0.8 -m 02:00:00:00:00:00
