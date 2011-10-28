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

 void syscall_handler (struct intr_frame *);


 struct file *find_file_by_fd (int fd);
 struct fd_elem *find_fd_elem_by_fd (int fd);
 int alloc_fid (void);
 struct fd_elem *find_fd_elem_by_fd_in_process (int fd);

 typedef int (*handler) (uint32_t, uint32_t, uint32_t);
 handler syscall_vec[128];
 struct lock file_lock;



struct fd_elem
  {
    int fd;
    struct file *file;
    struct list_elem elem;
    struct list_elem thread_elem;
  };
  
 struct list file_list;

void syscall_init (void) 
{
	printf("INITIALIZING THE SYSCALL HANDLER \n");
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  


  syscall_vec[SYS_EXIT] = (handler)exit;
  syscall_vec[SYS_HALT] = (handler)halt;
  syscall_vec[SYS_CREATE] = (handler)create;
  syscall_vec[SYS_OPEN] = (handler)open;
  syscall_vec[SYS_CLOSE] = (handler)close;
  syscall_vec[SYS_READ] = (handler)read;
  syscall_vec[SYS_WRITE] = (handler)write;
  syscall_vec[SYS_EXEC] = (handler)exec;
  syscall_vec[SYS_WAIT] = (handler)wait;
  syscall_vec[SYS_FILESIZE] = (handler)filesize;
  syscall_vec[SYS_SEEK] = (handler)seek;
  syscall_vec[SYS_TELL] = (handler)tell;
  syscall_vec[SYS_REMOVE] = (handler)remove;
  
  list_init (&file_list);
  lock_init (&file_lock);

}

 void syscall_handler (struct intr_frame *f /* UNUSED */) 
{
  
  printf ("system call!\n");
  

  handler h;
  int *p;
  int ret;
  
  p = f->esp;
  
  if (!is_user_vaddr (p))
    goto terminate;
  
  if (*p < SYS_HALT || *p > SYS_INUMBER)
    goto terminate;
  
  h = syscall_vec[*p];
  
    
  ret = h (*(p + 1), *(p + 2), *(p + 3));
  
  f->eax = ret;

  switch (*p)  
 	{
		case SYS_HALT :
		{
			printf("IN SYS_HALT CASE\n");
 		  power_off ();
			break;
		}	

		case SYS_EXIT : /******************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;
			
				int status = (int)*(p + 1);
			
			/* Close all the files */
 			struct thread *t;
  		struct list_elem *l;
  
 			t = thread_current ();
 		  while (!list_empty (&t->files))
      {
     	 	l = list_begin (&t->files);
     	 	close (list_entry (l, struct fd_elem, thread_elem)->fd);
   	  }
  
 		 t->ret_status = status;
  	 thread_exit ();	
		}

		case SYS_EXEC : /*****************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;

			
			char *cmd = (char*)*(p + 1);
			  
 		 /* if (!cmd || !is_user_vaddr (cmd)) // bad ptr 
    	return -1; */
 		 lock_acquire (&file_lock);
  	 f->eax = process_execute (cmd);
 	   lock_release (&file_lock);
		 break;  	 
		}

		case SYS_WAIT : /***************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;

				pid_t pid = (pid_t)*(p + 1);
				f->eax = process_wait(pid);
				break;
		}

		case SYS_CREATE : /*********************************/
		{	
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) && is_user_vaddr (p + 2) ))
		    goto terminate;

			unsigned initial_size = (unsigned)*(p + 2);
			char *file = (char*)*(p + 1);

			if (!file)
 		  {
   			 goto terminate;
	 		}

 			else
 			   f->eax = filesys_create (file, initial_size);
			
			break;
		}			


		case SYS_REMOVE : /*********************************/
	  {
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;

			char *file = (char*)*(p + 1);

			if (!is_user_vaddr (file))
 		  {
				printf("invalid user virtual address");
   		  goto terminate;
  		}

  		f->eax = filesys_remove (file);
			break;

		}
  
		case SYS_OPEN : /*********************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;

			char *file = (char*)*(p + 1);
			
			struct file *fi;
  		struct fd_elem *fde;
 		  int ret;
  
 		 ret = -1; /* Initialize to -1 ("can not open") */
 		 if (!file) /* file == NULL */
    		goto terminate;
  	 if (!is_user_vaddr (file))
    		goto terminate;
  			fi = filesys_open (file);
 		 if (!fi) /* Bad file name */
    		goto terminate;
    
 		 fde = (struct fd_elem *)malloc (sizeof (struct fd_elem));
		 if (!fde) /* Not enough memory */
     {
			  printf("Not enough memory to allocate memory syscall open()");
    		  file_close (fi);
	      goto terminate;
	    }    

		  /* allocate fde an ID, put fde in file_list, put fde in the current thread's file_list */
		  fde->file = fi; 
		  fde->fd = alloc_fid ();
		  list_push_back (&file_list, &fde->elem);
		  list_push_back (&thread_current ()->files, &fde->thread_elem);
		  f->eax = fde->fd;
			break;
		}

		case SYS_FILESIZE : /***************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;

			int fd = (int)*(p + 1);

			struct file *fi;
  
  			fi = find_file_by_fd (fd);
  			if (!fi)
  			  goto terminate; /* mabye return exit() ?? */
 			  f->eax = file_length (fi);
				break;	
		 }

		case SYS_READ : /*******************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) && is_user_vaddr (p + 2) && is_user_vaddr (p + 3) ))
		    goto terminate;

			int fd = (int)*(p + 1);
			void *buffer = (void*)*(p + 2);
			unsigned size = (unsigned)*(p + 3);
			
			struct file * fi;
 		 	unsigned i;
  		int ret;
  
  		ret = -1; /* Initialize to zero */
  		lock_acquire (&file_lock);
  		if (fd == STDIN_FILENO) /* stdin */
    	{
      	for (i = 0; i != size; ++i)
        	*(uint8_t *)(buffer + i) = input_getc ();
      		ret = size;
      		goto done;
    	}
  		else if (fd == STDOUT_FILENO) /* stdout */
     		 goto done;
  		else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size)) /* bad ptr */
    	{
      	lock_release (&file_lock);
      	goto terminate;
    	}
  		else
    	{
      	fi = find_file_by_fd (fd);
      	if (!fi)
        	goto done;
      	ret = file_read (fi, buffer, size);
					goto done;
    	}
		}

		case SYS_WRITE : /****************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) && is_user_vaddr (p + 2) && is_user_vaddr (p + 3) ))
		    goto terminate;

			int fd = (int)*(p + 1);
			void *buffer = (void*)*(p + 2);
			unsigned size = (unsigned)*(p + 3);

			struct file * fi;
  		int ret;
  
  		ret = -1;
  		lock_acquire (&file_lock);
  		if (fd == STDOUT_FILENO) /* stdout */
    		putbuf (buffer, size);
  		else if (fd == STDIN_FILENO) /* stdin */
    		goto done;
  		else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size))
    	{
	  		printf("Not a valid user virtual address syscall.c write()");
      	lock_release (&file_lock);
      	goto terminate;
    	}
 		  else
      {
      	fi = find_file_by_fd (fd);
      	if (!fi)
        	goto done;
        
      	ret = file_write (fi, buffer, size);
				goto done;
    	}
		}

		case SYS_SEEK : /*************************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) && is_user_vaddr (p + 2) ))
		    goto terminate;
			
			int fd = (int)*(p + 1);
			unsigned position = (unsigned)*(p + 2);

			struct file *fi;
  
 	 		fi = find_file_by_fd (fd);
  		if (!fi)
    		goto terminate;
  		file_seek (fi, position);
			break;
		}

		case SYS_TELL : /**********************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;
			
			int fd = (int)*(p + 1);
			struct file *fi;
  
  		fi = find_file_by_fd (fd);
  		if (!f)
   		 f->eax = -1;
 		  f->eax = file_tell (fi);
			break;
		}

		case SYS_CLOSE: /**************************/
		{
			if (!(is_user_vaddr (p) && is_user_vaddr (p + 1) ))
		    goto terminate;
			
			int fd = (int)*(p + 1);
			
			struct fd_elem *fi;
  		//int ret;
  
  		fi = find_fd_elem_by_fd_in_process (fd);
  
  		if (!fi) /* Bad fd */
   		 goto terminate;
 
  		file_close (fi->file);
  		list_remove (&fi->elem);
  		list_remove (&fi->thread_elem);
  		free (fi);
			break;
		}
	} /* end switch */

  
terminate:
  exit (-1); /* thread_current ()->exit_status = -1; thread_exit(); */

done:    
  lock_release (&file_lock);
  f->eax = ret;  
}

 int write (int fd, const void *buffer, unsigned length)
{
  struct file * f;
  int ret;
  
  ret = -1;
  lock_acquire (&file_lock);
  if (fd == STDOUT_FILENO) /* stdout */
    putbuf (buffer, length);
  else if (fd == STDIN_FILENO) /* stdin */
    goto done;
  else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length))
    {
	  printf("Not a valid user virtual address syscall.c write()");
      lock_release (&file_lock);
      exit (-1);
    }
  else
    {
      f = find_file_by_fd (fd);
      if (!f)
        goto done;
        
      ret = file_write (f, buffer, length);
    }
    
done:
  lock_release (&file_lock);
  return ret;
}

void exit (int status)
{
  /* Close all the files */
  struct thread *t;
  struct list_elem *l;
  
  t = thread_current ();
  while (!list_empty (&t->files))
    {
      l = list_begin (&t->files);
      close (list_entry (l, struct fd_elem, thread_elem)->fd);
    }
  
  t->ret_status = status;
  thread_exit ();
 
}

 void halt (void)
{
  power_off ();
}

 bool create (const char *file, unsigned initial_size)
{
  if (!file)
  {
    exit (-1);
    return false; /*  */
  }

  else
 	return filesys_create (file, initial_size);
}

 int open (const char *file)
{
  struct file *f;
  struct fd_elem *fde;
  int ret;
  
  ret = -1; /* Initialize to -1 ("can not open") */
  if (!file) /* file == NULL */
    return -1;
  if (!is_user_vaddr (file))
    exit (-1);
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

 void close(int fd)
{
  struct fd_elem *f;
  //int ret;
  
  f = find_fd_elem_by_fd_in_process (fd);
  
  if (!f) /* Bad fd */
    exit (-1);
 
  file_close (f->file);
  list_remove (&f->elem);
  list_remove (&f->thread_elem);
  free (f);
}

 int read (int fd, void *buffer, unsigned size)
{
  struct file * f;
  unsigned i;
  int ret;
  
  ret = -1; /* Initialize to zero */
  lock_acquire (&file_lock);
  if (fd == STDIN_FILENO) /* stdin */
    {
      for (i = 0; i != size; ++i)
        *(uint8_t *)(buffer + i) = input_getc ();
      ret = size;
      goto done;
    }
  else if (fd == STDOUT_FILENO) /* stdout */
      goto done;
  else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size)) /* bad ptr */
    {
      lock_release (&file_lock);
      exit(-1);
    }
  else
    {
      f = find_file_by_fd (fd);
      if (!f)
        goto done;
      ret = file_read (f, buffer, size);
    }
    
done:    
  lock_release (&file_lock);
  return ret;
}

/* ensure appropriate synchronization??? */
 pid_t exec (const char *cmd)
{
  pid_t ret;
  
  if (!cmd || !is_user_vaddr (cmd)) /* bad ptr */
    return -1;
  lock_acquire (&file_lock);
  ret = process_execute (cmd);
  lock_release (&file_lock);
  return ret;
}

 int wait (pid_t pid)
{
  return process_wait (pid);
}

 struct file *
find_file_by_fd (int fd)
{
  struct fd_elem *ret;
  
  ret = find_fd_elem_by_fd (fd);
  if (!ret)
    return NULL;
  return ret->file;
}

 struct fd_elem *
find_fd_elem_by_fd (int fd)
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

 int
alloc_fid (void)
{
   int fid = 2;
  return fid++;
}

 int filesize (int fd)
{
  struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f)
    return -1; /* mabye return exit() ?? */
  return file_length (f);
}

 unsigned tell (int fd)
{
  struct file *f;
  
  f = find_file_by_fd (fd);
  if (!f)
    return -1;
  return file_tell (f);
}

 void seek (int fd, unsigned pos)
{
  struct file *f;
  
  f = find_file_by_fd (fd);
  //if (!f)
    /* exit?? */
  file_seek (f, pos);
  
}

 bool remove (const char *file)
{
  if (!file)
    return false;
  if (!is_user_vaddr (file))
  {
	printf("invalid user virtual address");
    exit (-1);
  }

  return filesys_remove (file);
}

 struct fd_elem *
find_fd_elem_by_fd_in_process (int fd)
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

