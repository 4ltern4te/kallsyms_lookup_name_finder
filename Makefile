obj-m += kallsyms_lookup_name_finder.o
CC = gcc -Wall -g -O0
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
MOD := kallsyms_lookup_name_finder.ko

default:
	@echo MAKE TARGETS:
	@echo build, system, deploy, ssh, clean

build:
	make -C $(KDIR) M=$(PWD) modules

system:                                                                                                                 
	# command to boot your testing VM goes here
	@echo Booting VM

deploy:
	# Deploy to VM
	scp -o StrictHostKeyChecking=no -P 2222 $(MOD) root@localhost:

ssh:
	# SSH to VM
	ssh -o StrictHostKeyChecking=no -p 2222 root@localhost

clean:
	make -C $(KDIR) M=$(PWD) clean
