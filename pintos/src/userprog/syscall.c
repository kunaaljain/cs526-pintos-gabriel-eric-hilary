#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/off_t.h"

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

static void syscall_handler (struct intr_frame *);
struct file * find_file_by_fd (int fd);
struct fd_elem * find_fd_elem_by_fd (int fd);
struct fd_elem * find_fd_elem_by_fd_in_process (int fd);
struct lock filelock;

static int fid = 2;

static int syscall_write (int fd, const void *buffer, unsigned length);
static int syscall_halt(void);
static int syscall_exec (const char *file);
static int syscall_wait (pid_t);
static int syscall_create (const char *file, unsigned initial_size);
static int syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned length);
static int syscall_seek (int fd, unsigned position);
static int syscall_tell (int fd);
static int syscall_close (int fd);
static bool bad_args(int *syscall, int numargs);

struct list filelist;

void syscall_init (void) {

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&filelist);
  lock_init (&filelock);

}

static void syscall_handler (struct intr_frame *f) {

  int *syscall;
  int retval = -1;
  
  syscall = f->esp;

  if (*syscall < SYS_HALT || *syscall > SYS_CLOSE) {
     printf("BAD\n");
     f->eax = -1;
  }
  
  if (*syscall == SYS_WRITE) {
        if (!bad_args(syscall, 3)) {
        	retval = syscall_write((int)*(syscall + 1), (void*)*(syscall + 2), (unsigned)*(syscall + 3));
        }
  } else if (*syscall == SYS_EXIT) {
        if (!bad_args(syscall, 1)) {
    		retval = syscall_exit((int)*(syscall + 1));
	}
  } else if (*syscall == SYS_HALT){
	retval = syscall_halt();
  } else if (*syscall == SYS_EXEC){
        if (!bad_args(syscall, 1)) {
		retval = syscall_exec((char*)*(syscall + 1));
	}
  } else if (*syscall == SYS_WAIT){
        if (!bad_args(syscall, 1)) {
		retval = syscall_wait((pid_t)*(syscall + 1));
	}
  } else if (*syscall == SYS_CREATE){
        if (!bad_args(syscall, 2)) {
		retval = syscall_create((char*)*(syscall + 1), (unsigned)*(syscall + 2));
	}
  } else if (*syscall == SYS_REMOVE){
        if (!bad_args(syscall, 1)) {
		retval = syscall_remove((char*)*(syscall + 1));
	}
  } else if (*syscall == SYS_OPEN){
        if (!bad_args(syscall, 1)) {
		retval = syscall_open((char*)*(syscall + 1));
	}
  } else if (*syscall == SYS_FILESIZE){
        if (!bad_args(syscall, 1)) {
		retval = syscall_filesize((int)*(syscall + 1));
	}
  } else if (*syscall == SYS_READ){
        if (!bad_args(syscall, 3)) {
		retval = syscall_read((int)*(syscall + 1), (void*)*(syscall + 2), (unsigned)*(syscall + 3));
	}
  } else if (*syscall == SYS_SEEK){
        if (!bad_args(syscall, 2)) {
		retval = syscall_seek((int)*(syscall + 1), (unsigned)*(syscall + 2));
	}
  } else if (*syscall == SYS_TELL){
        if (!bad_args(syscall, 1)) {
		retval = syscall_tell((int)*(syscall + 1));
	}
  } else if (*syscall == SYS_CLOSE){
        if (!bad_args(syscall, 1)) {
		retval = syscall_close((int)*(syscall + 1));
	}
  }


  if (retval != -1) {
    f->eax = retval;
  }

 
}

static bool bad_args(int *syscall, int numargs) {

   if (syscall + numargs >= PHYS_BASE) {
      thread_current()->return_code = -1;
      thread_exit();
      return true;
   }
   
   return false;

}

static int syscall_write (int fd, const void *buffer, unsigned length) {

  struct file *f;
  int ret = 0;

  if (length <= 0) {
    printf("(%s) end\n", thread_current()->name);
    syscall_exit(0);
  }

  lock_acquire(&filelock);
  if (fd == STDOUT_FILENO) {
    putbuf (buffer, length);
    ret = length;
  } else if (fd == STDIN_FILENO) {
    lock_release(&filelock);
    syscall_exit(-1);
  } else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length)) {
     lock_release(&filelock);
     syscall_exit(-1);
  } else {
     f = find_file_by_fd(fd);
     if (!f) {
        lock_release(&filelock);
        syscall_exit(-1);
     }
     ret = file_write (f, buffer, length);
  }

  lock_release(&filelock);
  return ret;

}

int syscall_exit (int status) {

   struct thread *t;
   struct list_elem *l;
  
   t = thread_current ();
   while (!list_empty (&t->files)){
     	l = list_begin (&t->files);
     	syscall_close (list_entry (l, struct fd_elem, thread_elem)->fd);
   }

  thread_current()->return_code = status;
  thread_exit();
  return status;

}

static int syscall_halt(void){
   power_off();
}

static int syscall_exec(const char *cmd_line){

   pid_t ret;

   if (!cmd_line || !is_user_vaddr (cmd_line)) {
      thread_current()->return_code = -1;
      thread_exit();
   }
   lock_acquire(&filelock);
   ret = process_execute (cmd_line);
   lock_release(&filelock);
   return ret;

}

static int syscall_wait (pid_t pid){
	
   return process_wait (pid);

}


static int syscall_create (const char *file, unsigned initial_size){

  if (!file) {
        thread_current()->return_code = -1;
    	return syscall_exit (-1);    
  } else {
	return filesys_create (file, initial_size);
  }

}


static int syscall_remove (const char *file){
	
  if (!file) {
     thread_current()->return_code = -1;
     return -1;
  } else if (!is_user_vaddr (file)) {
     thread_current()->return_code = -1;
     return syscall_exit (-1);	
  } else {
     return filesys_remove (file);
  }

}


static int syscall_open (const char *file){

  struct file *f;
  struct fd_elem *fde;
  int ret = -1;

  if (strlen(file)==0) {
    printf("(%s) end\n", thread_current()->name);
    syscall_exit(0);
  }
  
  ret = -1;
  if (!file || !is_user_vaddr (file)) {
    syscall_exit (-1);
  }

  f = filesys_open (file);
  if (!f) {
    printf("(%s) end\n", thread_current()->name);
    syscall_exit (0);
  }

  fde = (struct fd_elem *)malloc (sizeof (struct fd_elem));
  if (!fde) {
    file_close (f);
    syscall_exit (0);
  }
  
  int fd = fde->fd;
  if (fd == STDIN_FILENO) {
    syscall_exit(0);
  } else if (fd == STDOUT_FILENO) {
    syscall_exit(1);
  }

  fde->file = f; 
  fde->fd = fid++;
  list_push_back (&filelist, &fde->elem);
  list_push_back (&thread_current ()->files, &fde->thread_elem);
  ret = fde->fd;

  return ret;

}

static int syscall_filesize (int fd){

  struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f) {
    thread_current()->return_code = -1;
    return -1;
  }
  return file_length (f);

}


static int syscall_read (int fd, void *buffer, unsigned length){

  struct file * f;
  unsigned i;
  int ret;

  if (length <= 0) {
    printf("(%s) end\n", thread_current()->name);
    syscall_exit(0);
  }
  
  ret = -1;
  lock_acquire (&filelock);
  if (fd == STDIN_FILENO) {
      for (i = 0; i != length; ++i) {
        uint8_t ch = input_getc();
        if (ch == '\n') {
           break;
        } else {
           *(uint8_t *)(buffer + i) = ch;
        }
      }
      lock_release (&filelock);
      return length;
  } else if (fd == STDOUT_FILENO) {
      lock_release (&filelock);
      syscall_exit (-1);
  } else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length)) {
      lock_release (&filelock);
      syscall_exit(-1);
  } else {
      f = find_file_by_fd (fd);
      if (!f) {
         lock_release (&filelock);
	 syscall_exit (-1);
         return ret;
      }
      ret = file_read (f, buffer, length);
  }
    
  lock_release (&filelock);
  return ret;
}	


static int syscall_seek (int fd, unsigned position){

  struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f) {
    thread_current()->return_code = -1;
    return syscall_exit(-1);
  }
  file_seek (f, (off_t)position);

  return 0;

}


static int syscall_tell (int fd){

  struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f) {
    thread_current()->return_code = -1;
    return -1;
  }
  return file_tell (f);

}

		
static int syscall_close (int fd){

  struct fd_elem *f;
  
  f = find_fd_elem_by_fd_in_process (fd);
  
  if (!f) {
    return 0;
  }

  file_close (f->file);
  list_remove (&f->elem);
  list_remove (&f->thread_elem);
  free (f);
  return 0;

}

struct file * find_file_by_fd (int fd) {
  struct fd_elem *ret;
  
  ret = find_fd_elem_by_fd (fd);
  if (!ret) {
    return NULL;
  }
  return ret->file;
}

struct fd_elem * find_fd_elem_by_fd (int fd) {
  struct fd_elem *ret;
  struct list_elem *l;
  
  for (l = list_begin (&filelist); l != list_end (&filelist); l = list_next (l)) {
      ret = list_entry (l, struct fd_elem, elem);
      if (ret->fd == fd)
        return ret;
    }
    
  return NULL;
}

struct fd_elem * find_fd_elem_by_fd_in_process (int fd) {
  struct fd_elem *ret;
  struct list_elem *l;
  struct thread *t;
  
  t = thread_current ();
  
  for (l = list_begin (&t->files); l != list_end (&t->files); l = list_next (l)) {
      ret = list_entry (l, struct fd_elem, thread_elem);
      if (ret->fd == fd)
        return ret;
    }
    
  return NULL;
}
