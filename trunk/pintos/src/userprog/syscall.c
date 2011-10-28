#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"
static int syscall_write (int fd, const void *buffer, unsigned length);

void syscall_init (void) {

	printf("INITIALIZING THE SYSCALL HANDLER \n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

static void syscall_handler (struct intr_frame *f) {

  int *syscall;
  int retval;
  
  syscall = f->esp;
  
  if (*syscall == SYS_WRITE) {
    retval = syscall_write(*(syscall + 1), *(syscall + 2), *(syscall + 3));
  } else if (*syscall == SYS_EXIT) {
    retval = syscall_exit(*(syscall + 1));
  }

  if (retval != -1) {
    f->eax = retval;
  }

 
}

static int syscall_write (int fd, const void *buffer, unsigned length) {

  if (fd == 1) {
    putbuf (buffer, length);
  }
  return length;

}

int syscall_exit (int status) {

  thread_current()->return_code = status;
  thread_exit();
  return -1;

}
