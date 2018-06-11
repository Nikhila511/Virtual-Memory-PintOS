#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define USER_VADDR_BOTTOM ((void *) 0x08048000)

void syscall_init (void);
void syscall_exit (void);
// static struct lock fs_lock;
#endif /* userprog/syscall.h */
