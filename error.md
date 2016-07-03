# Solutions for common errors
## dpdk wont build
Check gcc version. Install 4.8.x manually. Update system. Check nova.conf (etc/nova/nova.conf).

```
[libvirt]
...
cpu_mode = None
```
replace `None` with `host-model`
