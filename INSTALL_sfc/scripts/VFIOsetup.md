# VFIO setup

## setup memlock limit
# edit  /etc/security/limits.conf
# add these lines (set memlock to 64MB)

user            hard    memlock         65536
user            soft    memlock         65536
root            hard    memlock         65536
root            soft    memlock         65536

## iommu
# edit  /etc/default/grub
# append intel_iommu=on iommu=pt to GRUB_CMDLINE_LINUX

GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"

# update grup...
update-grup

# reboot...