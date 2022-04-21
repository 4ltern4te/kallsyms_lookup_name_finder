#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/parser.h>
#include <linux/version.h>	// for version macro
#include <linux/moduleparam.h>	// for params

#include <linux/ftrace.h>	// for kallsys
#include <linux/slab.h>		// for kmalloc
#include <linux/fs.h>		// for kernel_read
#include <asm/uaccess.h>	// for segment descriptors


MODULE_LICENSE("GPL");
MODULE_AUTHOR("alternate");
MODULE_DESCRIPTION("Locate kallsyms_lookup_name");
MODULE_VERSION("0.1");

static char *my_kaddr = NULL;
module_param(my_kaddr, charp, 0660);
MODULE_PARM_DESC(my_kaddr, "kallsyms_look_name address");


//https://elixir.bootlin.com/linux/latest/source/include/linux/kallsyms.h#L18
#define KSYM_NAME_LEN 128

//create function pointer type as we use this quite a bit
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);


/*
 * CREDIT:
 * - Author: xcellerator (alternate rewrote a few lines from the original)
 * - Link: https://xcellerator.github.io/posts/linux_rootkits_11/
 *
 * kaddr is an unsigned long which holds the memory address being looped over
 * fname_lookup is a kernel buffer which stores the name of the function at kaddr
 * fname is a kernel buffer storing the function we're searching for
 *
 * Trick to get the kernel base address
 * sprint_symbol() is less than 0x100000 bytes from the base address, so
 * we can just AND-out the last 3 bytes from it's address to obtain the address
 * of startup_64 (the kernel load address)
 */
kallsyms_lookup_name_t sprint_symbol_reverse_lookup(char *fname)
{
	int i;
	char fname_lookup[KSYM_NAME_LEN];
	char *fname_lookup_p = fname_lookup;
	char *fname_result;
	char *token;
	unsigned long kaddr = (unsigned long) &sprint_symbol;
	kaddr &= 0xffffffffff000000;

	/* During testing, all the interesting functions were found below this limit */
	for ( i = 0x0 ; i < 0x200000 ; i++ ) {

		sprint_symbol(fname_lookup, kaddr);

		//strnstr because symbols resolve to: addrconf_sysctl_addr_gen_mode+0x1c0/0x230
		fname_result = strnstr(fname_lookup, fname, sizeof(fname_lookup));

		if (fname_result != NULL) {

			//point to the kallsyms_lookup_name from kallsyms_lookup_name+0x0/0xe0
			if ((token = strsep(&fname_lookup_p, "+")) != NULL) {
				if (strncmp(fname, token, strlen(fname)) == 0) {
					return (kallsyms_lookup_name_t) kaddr;
				}
			}
			// reset the strsep() pointer for the next interation
			// otherwise we point to old data
			fname_lookup_p = fname_lookup;
		}
		/* Kernel function addresses are all aligned, so we skip 0x10 bytes */
		kaddr += 0x10;
	}

	return NULL;
}

#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

kallsyms_lookup_name_t kprobe_symbol_lookup(char *symbol_name)
{
	kallsyms_lookup_name_t kprobe_kallsyms_lookup_name = NULL;

	register_kprobe(&kp);
	kprobe_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	return kprobe_kallsyms_lookup_name;
}

/* CREDIT:
 * - Author: alternate (99% the code from xcellerator though)
 *
 * This function is very similar to sprint_symbol_reverse_lookup()
 * with the difference of using snprintf with format spec. "%ps"
 * instead of sprint_symbol().
 */
kallsyms_lookup_name_t sprintf_symbol_lookup(char *lookup_name)
{
	int i;
	char buf[KSYM_NAME_LEN];
	kallsyms_lookup_name_t sprintf_kallsyms_lookup_name;

	unsigned long kaddr = (unsigned long) &sprint_symbol;
	kaddr &= 0xffffffffff000000;

	for ( i = 0x0 ; i < 0x200000 ; i++ )
	{
		sprintf_kallsyms_lookup_name = (kallsyms_lookup_name_t) kaddr;
		snprintf(buf, sizeof(buf), "%ps", sprintf_kallsyms_lookup_name);

		if (strncmp(buf, lookup_name, strlen(lookup_name)) == 0) {
			return sprintf_kallsyms_lookup_name;
		}

		/* Kernel function addresses are all aligned, so we skip 0x10 bytes */
		kaddr += 0x10;
	}

	return NULL;
}

/* CREDIT:
 * - Author: alternate
 *
 * The least creative method of them all and I am sure someone else has done
 * this too.
 *
 * Open /proc/kallsyms from kernel space and search for kallsyms_lookup_name entry
 * The kallsyms_lookup_name is still globally available to the rest of the
 * kernel it is just not EXPORT_SYMBOL'd to kernel modules.
 */
kallsyms_lookup_name_t search_kallsyms_file(char *name, char *fname)
{
	ssize_t ccode;
	size_t count = 1;
	int lc = 0;
	loff_t pos = 0;
	int ret;

	struct file *f;

	char buffer[1];
	char *buf_p = buffer;
	char line[512];
	char *line_p = line;
	char *line_check;
	char *token;

	unsigned long kaddr;

	char first[17];
	char second[1];
	char third[KSYM_NAME_LEN];

	//init line buffer
	memset(line, 0x0, sizeof(line));

	//open /proc/kallsyms
	f = filp_open(name, O_RDONLY, 0);
	if (!f) {
		ccode = -EBADF;
		pr_info("Unable to open file: %s (%ld)", name, ccode);
		return NULL;
	}

	// read in a char to check for \n
	while((ccode = kernel_read(f, buf_p, count, &pos)) > 0 && lc < 512) {
		if (*buf_p != '\n') {
			line[lc++] = *buf_p;
		} else {
			//terminate line[]
			line[lc] = '\0';

			// check for kallsyms_lookup_name
			line_check = strnstr(line, fname, sizeof(line));
			if (line_check != NULL) {

				//get address from 'ffffffff81234c70 T kallsyms_lookup_name'
				if ((token = strsep(&line_p, " ")) != NULL) {
					strncpy(first, token, sizeof(first));
					first[sizeof(first)-1] = '\0';
				}
				if ((token = strsep(&line_p, " ")) != NULL) {
					strncpy(second, token, sizeof(second));
				}
				if ((token = strsep(&line_p, " ")) != NULL) {
					strncpy(third, token, sizeof(third));
					third[sizeof(third)-1] = '\0';
				}
				if (strncmp(third, fname, strlen(fname)) == 0) {
					if ((ret = kstrtoul(first, 16, &kaddr)) < 0) {
						return NULL;
					}
					filp_close(f, 0);
					return (kallsyms_lookup_name_t) kaddr;
				}


			}
			//reset variables
			memset(line, 0x0, sizeof(line));
			lc = 0;
			line_p = line;
		}
	}
	pr_info("[!] search_kallsyms_file(): no symbol: %s\n", fname);
	filp_close(f, 0);
	return NULL;
}

static int __init mod_init(void)
{
	kallsyms_lookup_name_t my_kallsyms_lookup_name;
	unsigned long kaddr;
	int ret;

	//kallsys_lookup_name added in 2.6 but exported to modules in 3.0.0
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(5,7,0))
	pr_info("kallsys_lookup_name():\n");
	pr_info("\t[+] kernel versions: >= 3.0.0 <= 5.7.0\n");
	pr_info("\t[+] sys_call_table: 0x%lx\n", kallsyms_lookup_name("sys_call_table"));
	#endif

	//kprobe
	//kallsys_lookup_name in 2.6 but kprobes added 2.6.9
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9))
	pr_info("kprobe_symbol_lookup():\n");
	pr_info("\t[+] kernel versions: >= 2.6.9\n");
	my_kallsyms_lookup_name = kprobe_symbol_lookup("kallsyms_lookup_name");
	if (my_kallsyms_lookup_name != NULL) {
		pr_info("\t[+] kprobe_symbol_lookup: sys_call_table: 0x%lx\n",
			my_kallsyms_lookup_name("sys_call_table"));
	}
	#endif

	//sprintf
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4))
	pr_info("sprintf_symbol_lookup():\n");
	pr_info("\t[+] kernel versions: >= 2.6.4\n");
	my_kallsyms_lookup_name = sprintf_symbol_lookup("kallsyms_lookup_name");
	if (my_kallsyms_lookup_name != NULL) {
		pr_info("\t[+] sprintf_symbol_lookup: sys_call_table: 0x%lx\n",
			my_kallsyms_lookup_name("sys_call_table"));
	}
	#endif

	//sprint_symbol
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
	pr_info("sprint_symbol():\n");
	pr_info("\t[+] kernel versions: >= 2.6.22\n");
	my_kallsyms_lookup_name = sprint_symbol_reverse_lookup("kallsyms_lookup_name");
	if (my_kallsyms_lookup_name != NULL) {
		pr_info("\t[+] sprint_symbol_reverse_lookup(): sys_call_table: 0x%lx\n",
			my_kallsyms_lookup_name("sys_call_table"));
	}
	#endif

	//search through /proc/kallsyms
	//looks cut off at 5.9.16 due to set_fs() changes. TODO: confirm and research way around
	//https://elixir.bootlin.com/linux/v5.10/source/fs/read_write.c#L448
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)) && (LINUX_VERSION_CODE <= KERNEL_VERSION(5,9,16))
	pr_info("search_kallsyms_file():\n");
	pr_info("\t[+] kernel versions: >= 2.6.4 <= 5.9.16(?)\n");
	my_kallsyms_lookup_name = search_kallsyms_file("/proc/kallsyms", "kallsyms_lookup_name");
	if (my_kallsyms_lookup_name != NULL) {
		pr_info("\t[+] search_kallsyms_file(): sys_call_table: 0x%lx\n",
			my_kallsyms_lookup_name("sys_call_table"));
	}
	#endif

	//Get symbol address from a parameter.
	//Manual version of search_kallsyms_file() for the hell of it
	//insmod module.ko my_kaddr=$(grep -ioP '\K[a-f0-9]+ (?=T kallsyms_lookup_name)' /proc/kallsyms)
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4))
	pr_info("kallsyms_lookup_name() from parameter:\n");
	pr_info("\t[+] kernel versions: >= 2.6.4\n");

	if ((my_kaddr != NULL) && (ret = kstrtoul(my_kaddr, 16, &kaddr)) >= 0) {
		my_kallsyms_lookup_name = (kallsyms_lookup_name_t) kaddr;
		if (my_kallsyms_lookup_name != NULL) {
			pr_info("\t[+] kallsyms_lookup_name() from param: sys_call_table: 0x%lx\n",
				my_kallsyms_lookup_name("sys_call_table"));
		}
	} else {
		pr_info("\t[-] no my_addr param supplied\n");
	}
	#endif

	return 0;
}

static void __exit mod_exit(void)
{
	pr_info("\t%s unload successful\n", THIS_MODULE->name);
}

module_init(mod_init);
module_exit(mod_exit);
