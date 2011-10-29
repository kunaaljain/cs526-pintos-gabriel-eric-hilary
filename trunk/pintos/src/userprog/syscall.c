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
struct lock file_lock;
static int alloc_fid (void);


static int syscall_write (int fd, const void *buffer, unsigned length);
static int syscall_halt(void);
static int syscall_exec (const char *file);
static int syscall_wait (pid_t);
static int syscall_create (const char *file, unsigned initial_size);
static int syscall_remove (const char *file);
static int syscall_open (const char *file);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned length);
static int syscall_write (int fd, const void *buffer, unsigned length);
static int syscall_seek (int fd, unsigned position);
static int syscall_tell (int fd);
static int syscall_close (int fd);

struct list file_list;
struct fd_elem
{
  int fd;
  struct file *file;
  struct list_elem elem;
  struct list_elem thread_elem;
};

void syscall_init (void) {

	printf("INITIALIZING THE SYSCALL HANDLER \n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

static void syscall_handler (struct intr_frame *f) {

  int *syscall;
  int retval;
  
  syscall = f->esp;
  
  if (*syscall == SYS_WRITE) {
    retval = syscall_write((int)*(syscall + 1), (void*)*(syscall + 2), (unsigned)*(syscall + 3));
  } else if (*syscall == SYS_EXIT) {
    retval = syscall_exit((int)*(syscall + 1));
  }
	else if (*syscall == SYS_HALT){
	retval = syscall_halt();
  }
	else if (*syscall == SYS_EXEC){
	retval = syscall_exec((char*)*(syscall + 1));
  }
	else if (*syscall == SYS_WAIT){
	retval = syscall_wait((pid_t)*(syscall + 1));
  }
	else if (*syscall == SYS_CREATE){
	retval = syscall_create((char*)*(syscall + 1), (unsigned)*(syscall + 2));
  }
	else if (*syscall == SYS_REMOVE){
	retval = syscall_remove((char*)*(syscall + 1));
  }	
	else if (*syscall == SYS_OPEN){
	retval = syscall_open((char*)*(syscall + 1));
  }
	else if (*syscall == SYS_FILESIZE){
	retval = syscall_filesize((int)*(syscall + 1));
  }
	else if (*syscall == SYS_READ){
	retval = syscall_read((int)*(syscall + 1), (void*)*(syscall + 2), (unsigned)*(syscall + 3));
  }
	else if (*syscall == SYS_SEEK){
	retval = syscall_seek((int)*(syscall + 1), (unsigned)*(syscall + 2));
  }
	else if (*syscall == SYS_TELL){
	retval = syscall_tell((int)*(syscall + 1));
  }
	else if (*syscall == SYS_CLOSE){
	retval = syscall_close((int)*(syscall + 1));
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

	/* Close all the files */
 			struct thread *t;
  		struct list_elem *l;
  
 			t = thread_current ();
 		  while (!list_empty (&t->files))
      {
     	 	l = list_begin (&t->files);
     	 	syscall_close (list_entry (l, struct fd_elem, thread_elem)->fd);
   	  }

  thread_current()->return_code = status;
  thread_exit();
  return -1;

}

static int syscall_halt(void){
	
	power_off();
}

static int syscall_exec(const char *cmd_line){

	pid_t ret;
  
	if (!cmd_line || !is_user_vaddr (cmd_line)) /* bad ptr */
		return -1;
	ret = process_execute (cmd_line);
	return ret;
}

static int syscall_wait (pid_t pid){
	
	return process_wait (pid);
}


static int syscall_create (const char *file, unsigned initial_size){

	if (!file)
  {
    return syscall_exit (-1);    
  }

  else
 		return filesys_create (file, initial_size);
}


static int syscall_remove (const char *file){
	
	if (!file)
    return -1;
  else if (!is_user_vaddr (file))
  {
	printf("invalid user virtual address");
   return syscall_exit (-1);	
  }
	else
	  return filesys_remove (file);
}


static int syscall_open (const char *file){

	struct file *f;
  struct fd_elem *fde;
  int ret;
  
  ret = -1; /* Initialize to -1 ("can not open") */
  if (!file) /* file == NULL */
    return -1;
  if (!is_user_vaddr (file))
    return syscall_exit (-1);
  f = filesys_open (file);
  if (!f) /* Bad file name */
    goto done;
    
  fde = (struct fd_elem *)malloc (sizeof (struct fd_elem));
  if (!fde) /* Not enough memory */
    {
	  printf("Not enough memory to allocate memory syscall open()");
      file_close (f);
      goto done;
    }
    

  /* allocate fde an ID, put fde in file_list, put fde in the current thread's file_list */
  fde->file = f; 
  fde->fd = alloc_fid ();
  list_push_back (&file_list, &fde->elem);
  list_push_back (&thread_current ()->files, &fde->thread_elem);
  ret = fde->fd;
done:
  return ret;

}

static int syscall_filesize (int fd){

	struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f)
    return -1; /* mabye return exit() ?? */
  return file_length (f);
}


static int syscall_read (int fd, void *buffer, unsigned length){

	struct file * f;
  unsigned i;
  int ret;
  
  ret = -1; /* Initialize to zero */
  lock_acquire (&file_lock);
  if (fd == STDIN_FILENO) /* stdin */
    {
      for (i = 0; i != length; ++i)
        *(uint8_t *)(buffer + i) = input_getc ();
      ret = length;
      goto done;
    }
  else if (fd == STDOUT_FILENO) /* stdout */
      goto done;
  else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length)) /* bad ptr */
    {
      lock_release (&file_lock);
      syscall_exit(-1);
    }
  else
    {
      f = find_file_by_fd (fd);
      if (!f)
        goto done;
      ret = file_read (f, buffer, length);
    }
    
done:    
  lock_release (&file_lock);
  return ret;
}	


static int syscall_seek (int fd, unsigned position){

	struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f)
    return syscall_exit(-1);
  file_seek (f, (off_t)position);
	return 0; /* file_seek() has NULL return type */
}


static int syscall_tell (int fd){

	struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f)
    return -1;
  return file_tell (f);
}

		
static int syscall_close (int fd){

	struct fd_elem *f;
  
  f = find_fd_elem_by_fd_in_process (fd);
  
  if (!f) /* Bad fd */
    syscall_exit (-1);
 
  file_close (f->file);
  list_remove (&f->elem);
  list_remove (&f->thread_elem);
  free (f);
	return syscall_exit(1);
}	

	
static int alloc_fid (void)
{
   int fid = 2;
  return fid++;
}

struct file * find_file_by_fd (int fd)
{
  struct fd_elem *ret;
  
  ret = find_fd_elem_by_fd (fd);
  if (!ret)
    return NULL;
  return ret->file;
}

struct fd_elem * find_fd_elem_by_fd (int fd)
{
  struct fd_elem *ret;
  struct list_elem *l;
  
  for (l = list_begin (&file_list); l != list_end (&file_list); l = list_next (l))
    {
      ret = list_entry (l, struct fd_elem, elem);
      if (ret->fd == fd)
        return ret;
    }
    
  return NULL;
}

struct fd_elem * find_fd_elem_by_fd_in_process (int fd)
{
  struct fd_elem *ret;
  struct list_elem *l;
  struct thread *t;
  
  t = thread_current ();
  
  for (l = list_begin (&t->files); l != list_end (&t->files); l = list_next (l))
    {
      ret = list_entry (l, struct fd_elem, thread_elem);
      if (ret->fd == fd)
        return ret;
    }
    
  return NULL;
}
