#ifndef VM_PAGEANDFRAME_H
#define VM_PAGEANDFRAME_H

#include <stdint.h>
#include <stdbool.h>
#include "hash.h"
#include "threads/thread.h"
#include <list.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/file.h"

#define VALID_STACK_SIZE (8 *(1 << 20))

struct lock lock_frame;

struct frame_table_entry{

	struct thread *thread;
	struct list_elem frame_entry_elem;
	void *frame;
	struct suppl_page_table_entry *spte;
};

struct list frame_list;

struct suppl_page_table_entry{

	void *user_virtual_addr;
	struct hash_elem hash_table_elem;
	struct file *load_file;
	size_t page_offset;
	size_t zero_bytes;
	size_t read_bytes;
	bool is_writable;
	bool page_isloaded;
	bool page_accessed;
};

void *frame_allocate (enum palloc_flags page_flags);
void frame_deallocate (void *allocated_frame);

bool pagetable_addfile (struct file *file_page, uint32_t zero_bytes, uint32_t read_bytes, 
						bool is_writable, uint32_t page_offset,uint8_t *user_page, struct hash *spt);
void page_free(struct hash_elem *elem, void *aux UNUSED);
struct suppl_page_table_entry* spt_lookup(void *user_vaddr);
bool file_load(struct suppl_page_table_entry *spt_entry);
bool add_stack(void *user_vaddr);
uint32_t page_hashing (struct hash_elem *elem, void *aux UNUSED);
bool page_less (struct hash_elem *e1, struct hash_elem *e2,void *aux UNUSED);

#endif