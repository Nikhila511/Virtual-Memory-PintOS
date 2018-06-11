#include "pageandframe.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "hash.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

void *frame_allocate (enum palloc_flags page_flags) {
	if ((page_flags & PAL_USER) == 0){
		return NULL;
	}
	 void *frame = palloc_get_page(page_flags);
	 if(frame){
	 	struct frame_table_entry *ft_entry= malloc(sizeof(struct frame_table_entry));
	 	ft_entry->frame = frame;
	 	ft_entry->thread = thread_current();
	 	//ft_entry->spte = spt_entry;
	 	lock_acquire(&lock_frame);
	 	list_push_back(&frame_list, &ft_entry->frame_entry_elem);
	 	lock_release(&lock_frame);
	 }
	 else{
	 	PANIC("Ran out of frames");
	 }
	return frame;
}

void frame_deallocate (void *allocated_frame){
	struct list_elem *elem;
	lock_acquire(&lock_frame);
	for(elem = list_begin(&frame_list); elem != list_end(&frame_list); elem = list_next(elem)){
		struct frame_table_entry *ft_entry = list_entry(elem, struct frame_table_entry, frame_entry_elem);
		if(ft_entry->frame == allocated_frame){
			list_remove(elem);
			free(ft_entry);
			palloc_free_page(allocated_frame);
		}
	}
	lock_release(&lock_frame);
}

bool pagetable_addfile (struct file *file_page, uint32_t zero_bytes, uint32_t read_bytes, 
						bool is_writable, uint32_t ofs,uint8_t *user_page, struct hash *spt){
	struct suppl_page_table_entry *spt_entry = malloc(sizeof(struct suppl_page_table_entry));
	if(spt_entry){ 
		 spt_entry->load_file = file_page;
		 spt_entry->zero_bytes = zero_bytes;
		 spt_entry->read_bytes = read_bytes;
		 spt_entry->is_writable = is_writable;
		 spt_entry->page_offset = ofs;
		 spt_entry->user_virtual_addr = user_page;
		 spt_entry->page_isloaded = true;
		 spt_entry->page_accessed = false;
	 	 //struct hash_elem *page_elem = hash_insert(&thread_current()->suppl_page_table, 
	 	 	 										//&spt_entry->hash_table_elem);
	 	 struct hash_elem *page_elem = hash_insert(spt, &spt_entry->hash_table_elem);
	 	 										
	 	 if(page_elem == NULL){
	 	 	return true;
	 	 }
	 	 else{
	 	 	return false;
	 	 }
	}
	else{
		return false;
	}
}

void page_free(struct hash_elem *elem, void *aux UNUSED){
	struct suppl_page_table_entry *spt_entry = hash_entry(elem, struct suppl_page_table_entry,hash_table_elem);
	if(spt_entry->page_isloaded){
		void *page = pagedir_get_page(thread_current()->pagedir, spt_entry->user_virtual_addr);
		frame_deallocate(page);
		pagedir_clear_page(thread_current()->pagedir, spt_entry->user_virtual_addr);
	}
	free(spt_entry);
}

uint32_t page_hashing (struct hash_elem *elem, void *aux UNUSED){
	struct suppl_page_table_entry *spt_entry = hash_entry(elem, struct suppl_page_table_entry, hash_table_elem);
	return hash_int((uint32_t) spt_entry->user_virtual_addr);
}

bool page_less (struct hash_elem *e1, struct hash_elem *e2,void *aux UNUSED){
  struct suppl_page_table_entry *spt_entry1 = hash_entry(e1, struct suppl_page_table_entry,hash_table_elem);
  struct suppl_page_table_entry *spt_entry2 = hash_entry(e2, struct suppl_page_table_entry,hash_table_elem);
  if (spt_entry1->user_virtual_addr < spt_entry2->user_virtual_addr)
    {
      return true;
    }
  return false;
}
/* look up the supplemental hash table using uva as key*/
struct suppl_page_table_entry* spt_lookup(void *user_vaddr){
	struct suppl_page_table_entry spt_entry;
	spt_entry.user_virtual_addr = user_vaddr;  // rounds down to nearest page boundary
	//struct hash *ht = &thread_current()->suppl_page_table;
	//struct hash_elem *hash_table_entry = hash_find(ht,&spt_entry.hash_table_elem);
	struct hash_iterator i;

	hash_first (&i, &thread_current()->suppl_page_table);
	while (hash_next (&i))
	{
	    struct suppl_page_table_entry *f = hash_entry (hash_cur (&i), struct suppl_page_table_entry, hash_table_elem);
	    if(f->user_virtual_addr == spt_entry.user_virtual_addr){
	    	return f;
	    }
	}
												
	/*if(hash_table_entry){
		return hash_entry(hash_table_entry,struct suppl_page_table_entry, hash_table_elem);
	}
	else{
		printf("entry not found\n");
		return NULL;
	}*/
}

bool file_load(struct suppl_page_table_entry *spt_entry){
	enum palloc_flags page_flags = PAL_USER;

	if (spt_entry->read_bytes == 0)
		page_flags = page_flags | PAL_USER;

	uint8_t *kpage = frame_allocate(page_flags);
    if (!kpage)
        return false;
    if(spt_entry->read_bytes > 0){
       if (file_read_at(spt_entry->load_file, kpage, spt_entry->read_bytes, spt_entry->page_offset) != (int) spt_entry->read_bytes)
        {
         // palloc_free_page (kpage);
        	frame_deallocate (kpage);
        	return false; 
        }
      memset (kpage + spt_entry->read_bytes, 0, spt_entry->zero_bytes);
   }
   bool inst_result = install_page (spt_entry->user_virtual_addr, kpage, spt_entry->is_writable);
    /* Add the page to the process's address space. */
    if (!inst_result || inst_result == NULL) 
    {
          //palloc_free_page (kpage);
        frame_deallocate (kpage);
        return false; 
    }
 	spt_entry->page_isloaded = true;
 	return true;
}

bool add_stack(void *user_vaddr){
	size_t stack_addr = PHYS_BASE - pg_round_down(user_vaddr);
	if(stack_addr > VALID_STACK_SIZE)
		return false;
	struct suppl_page_table_entry *spt_entry = malloc(sizeof(struct suppl_page_table_entry));
	if(spt_entry){
		spt_entry->page_isloaded = true;
		spt_entry->user_virtual_addr = pg_round_down(user_vaddr);
		spt_entry->page_accessed = true;
		spt_entry->is_writable = true;
		uint8_t *stack_frame = frame_allocate(PAL_USER);
		if(stack_frame){
			bool result = install_page(spt_entry->user_virtual_addr,stack_frame, spt_entry->is_writable);
			if(!result){
				free(spt_entry);
				frame_deallocate(stack_frame);
				return false;
			}

			if(intr_context())
				spt_entry->page_accessed = false;
		}
		else{
			free(spt_entry);
			return false;
		}

	}
	else{
		return false;
	}
	struct hash_elem *success = hash_insert(&thread_current()->suppl_page_table, &spt_entry->hash_table_elem);
	
	if(success == NULL)
		return true;
	else
		return false;
}

