#! /bin/bash

#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# Run with "source /path/to/setup.sh"
#

#
# Configuration
#

TARGET="x86_64-native-linuxapp-gcc"
NB_HUGEPAGES=64
NICS_TO_BIND=(0000:00:04.0 0000:00:05.0 0000:00:06.0 0000:00:07.0) # WRAPPER
#NICS_TO_BIND=(0000:00:04.0 0000:00:05.0) # FIREWALL

#
# Setup environment
#

sudo apt-get update
sudo apt-get install -y build-essential linux-4.4.0-47 linux-headers-4.4.0-47
sudo apt-get install -y git zip python gdb libconfig-dev libssl-dev
wget http://fast.dpdk.org/rel/dpdk-16.07.2.tar.xz
tar xf dpdk-16.07.2.tar.xz
mv dpdk-16.07.2 dpdk
rm dpdk-16.07.2.tar.xz

#
# Change to DPDK directory ( <this-script's-dir>/dpdk ), and export it as RTE_SDK
#
export RTE_SDK=$PWD/dpdk
cd $RTE_SDK
echo "------------------------------------------------------------------------------"
echo " RTE_SDK exported as $RTE_SDK"
echo "------------------------------------------------------------------------------"

HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`

#
# Application EAL parameters for setting memory options (amount/channels/ranks).
#
EAL_PARAMS='-n 4'

#
# Sets RTE_TARGET and does a "make install".
#
setup_target()
{
    export RTE_TARGET=$1

    compiler=${RTE_TARGET##*-}
    if [ "$compiler" == "icc" ] ; then
        platform=${RTE_TARGET%%-*}
        if [ "$platform" == "x86_64" ] ; then
            setup_icc intel64
        else
            setup_icc ia32
        fi
    fi
    make install T=${RTE_TARGET}
    echo "------------------------------------------------------------------------------"
    echo " RTE_TARGET exported as $RTE_TARGET"
    echo "------------------------------------------------------------------------------"
}

#
# Creates hugepage filesystem.
#
create_mnt_huge()
{
    echo "Creating /mnt/huge and mounting as hugetlbfs"
    sudo mkdir -p /mnt/huge

    grep -s '/mnt/huge' /proc/mounts > /dev/null
    if [ $? -ne 0 ] ; then
        sudo mount -t hugetlbfs nodev /mnt/huge
    fi
}

#
# Removes hugepage filesystem.
#
remove_mnt_huge()
{
    echo "Unmounting /mnt/huge and removing directory"
    grep -s '/mnt/huge' /proc/mounts > /dev/null
    if [ $? -eq 0 ] ; then
        sudo umount /mnt/huge
    fi

    if [ -d /mnt/huge ] ; then
        sudo rm -R /mnt/huge
    fi
}

#
# Unloads igb_uio.ko.
#
remove_igb_uio_module()
{
    echo "Unloading any existing DPDK UIO module"
    /sbin/lsmod | grep -s igb_uio > /dev/null
    if [ $? -eq 0 ] ; then
        sudo /sbin/rmmod igb_uio
    fi
}

#
# Loads new igb_uio.ko (and uio module if needed).
#
load_igb_uio_module()
{
    if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko ];then
        echo "## ERROR: Target does not have the DPDK UIO Kernel Module."
        echo "       To fix, please try to rebuild target."
        return
    fi

    remove_igb_uio_module

    /sbin/lsmod | grep -s uio > /dev/null
    if [ $? -ne 0 ] ; then
        modinfo uio > /dev/null
        if [ $? -eq 0 ]; then
            echo "Loading uio module"
            sudo /sbin/modprobe uio
        fi
    fi

    # UIO may be compiled into kernel, so it may not be an error if it can't
    # be loaded.

    echo "Loading DPDK UIO module"
    sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko
    if [ $? -ne 0 ] ; then
        echo "## ERROR: Could not load kmod/igb_uio.ko."
        quit
    fi
}

#
# Removes all reserved hugepages.
#
clear_huge_pages()
{
    echo > .echo_tmp
    for d in /sys/devices/system/node/node? ; do
        echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
    done
    echo "Removing currently reserved hugepages"
    sudo sh .echo_tmp
    rm -f .echo_tmp

    remove_mnt_huge
}

#
# Creates hugepages.
#
set_non_numa_pages()
{
    clear_huge_pages

    echo ""
    echo "  Input the number of ${HUGEPGSZ} hugepages"
    echo "  Example: to have 128MB of hugepages available in a 2MB huge page system,"
    echo "  enter '64' to reserve 64 * 2MB pages"
    echo -n "Number of pages: "

    echo "echo $1 > /sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" > .echo_tmp

    echo "Reserving hugepages"
    sudo sh .echo_tmp
    rm -f .echo_tmp

    create_mnt_huge
}

#
# Print hugepage information.
#
grep_meminfo()
{
    grep -i huge /proc/meminfo
}

#
# Calls dpdk_nic_bind.py --status to show the NIC and what they
# are all bound to, in terms of drivers.
#
show_nics()
{
    if [ -d /sys/module/vfio_pci -o -d /sys/module/igb_uio ]; then
        ${RTE_SDK}/tools/dpdk_nic_bind.py --status
    else
        echo "# Please load the 'igb_uio' or 'vfio-pci' kernel module before "
        echo "# querying or adjusting NIC device bindings"
    fi
}

#
# Uses dpdk_nic_bind.py to move devices to work with igb_uio
#
bind_nics_to_igb_uio()
{
    if [ -d /sys/module/igb_uio ]; then
        ${RTE_SDK}/tools/dpdk_nic_bind.py --status
        echo ""
        echo -n "Enter PCI address of device to bind to IGB UIO driver: "
        sudo ${RTE_SDK}/tools/dpdk_nic_bind.py -b igb_uio $1 && echo "OK"
    else
        echo "# Please load the 'igb_uio' kernel module before querying or "
        echo "# adjusting NIC device bindings"
    fi
}


setup_target $TARGET

set_non_numa_pages $NB_HUGEPAGES

load_igb_uio_module

for i in ${NICS_TO_BIND[@]}; do
    bind_nics_to_igb_uio $i
done

