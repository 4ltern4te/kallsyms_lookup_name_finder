# kallsyms_lookup_name
As of Linux Kernel version 5.7.0 the function `kallsyms_lookup_name` is no longer exported to kernel modules. This was a convenient way to lookup the the `sys_call_table` when hacking on LKM rootkits and other such things. I came across a [few other hackers](https://github.com/xcellerator/linux_kernel_hacking/issues/3) looking for interesting ways to get around the problem too which inspired me to maintain a list of ways to work around the issue per kernel version.

## Building

### Dependencies
Install the packages required to build kernel modules on your system.

For Fedora where I did my testing:
```
sudo dnf install -y kernel-headers kernel-devel make gcc
```

### Make
Beside building the module the Makefile has some other admin tasks available.

```
# Build the module
$ make build
# insmod kallsyms_lookup_name_finder.ko
# insmod kallsyms_lookup_name_finder.ko my_kaddr=$(grep -ioP '\K[a-f0-9]+ (?=T kallsyms_lookup_name)' /proc/kallsyms)
```

## Contribution
If you have another way to find `kallsyms_lookup_name()` please:
- create a pull request
	- credit the author in the code comments
	- include checks for kernel version support
	- follow the output format
