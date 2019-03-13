#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include "mem.h"



#define A_BIT_MASK		0x0001
#define P_BIT_MASK		0x0002
#define SIZE_MASK		(~(A_BIT_MASK | P_BIT_MASK))
#define BLK_HDR_SIZE(header)	(header->size_status & SIZE_MASK)
#define BLK_HDR_ALLOC(header)	(header->size_status & A_BIT_MASK)
#define BLK_HDR_PREV(header)	(header->size_status & P_BIT_MASK)
#define NEXT_HDR_DIST(header)	(BLK_HDR_SIZE(header) / sizeof(block_header))
#define NEXT_HEADER(header)	(header + NEXT_HDR_DIST(header))
#define IS_END_MARK(header)	(header->size_status == 1)

/*
 * This structure serves as the header for each allocated and free block.
 * It also serves as the footer for each free block but only containing size.
 */
typedef struct block_header {
        int size_status;
    /*
    * Size of the block is always a multiple of 8.
    * Size is stored in all block headers and free block footers.
    *
    * Status is stored only in headers using the two least significant bits.
    *   Bit0 => least significant bit, last bit
    *   Bit0 == 0 => free block
    *   Bit0 == 1 => allocated block
    *
    *   Bit1 => second last bit 
    *   Bit1 == 0 => previous block is free
    *   Bit1 == 1 => previous block is allocated
    * 
    * End Mark: 
    *  The end of the available memory is indicated using a size_status of 1.
    * 
    * Examples:
    * 
    * 1. Allocated block of size 24 bytes:
    *    Header:
    *      If the previous block is allocated, size_status should be 27
    *      If the previous block is free, size_status should be 25
    * 
    * 2. Free block of size 24 bytes:
    *    Header:
    *      If the previous block is allocated, size_status should be 26
    *      If the previous block is free, size_status should be 24
    *    Footer:
    *      size_status should be 24
    */
} block_header;         

/* Global variable - DO NOT CHANGE. It should always point to the first block,
 * i.e., the block at the lowest address.
 */

block_header *start_block = NULL;

/* 
 * Function for allocating 'size' bytes of heap memory.
 * Argument size: requested size for the payload
 * Returns address of allocated block on success.
 * Returns NULL on failure.
 * This function should:
 * - Check size - Return NULL if not positive or if larger than heap space.
 * - Determine block size rounding up to a multiple of 8 and possibly adding padding as a result.
 * - Use BEST-FIT PLACEMENT POLICY to find the block closest to the required block size
 * - Use SPLITTING to divide the chosen free block into two if it is too large.
 * - Update header(s) and footer as needed.
 * Tips: Be careful with pointer arithmetic.
 */
void* Alloc_Mem(int size) {
	  
	// declare some variables to be used later
	block_header *best = NULL;
	block_header *curr = start_block;
	block_header *next;
	int remainder; // this variable will be used to hold the size of the left over space for splitting into a new block

   	// if size is less than or equal to 0 then return null
	if (size <= 0 ) {return NULL;} 

	// round to the nearest multiple of 8
	size += 8 - (size % 8);

	// Loop through the entire heap to find the best fit location
	while(!IS_END_MARK(curr)){
		/* IF THE BLOCK IS NOT ALLOCATED ALREADY */
		if (!(BLK_HDR_ALLOC(curr))) {
			/* IF THE BLOCK IS PERFECT SIZE */
			if (BLK_HDR_SIZE(curr) == size){

				/* CONSIDER MAKING THIS A FUNCTION TO AVOID REDUNDANCY */
				block_header *next_header = NEXT_HEADER(curr);
				curr->size_status |= A_BIT_MASK;

				/** check the previous block **/
				if(!(IS_END_MARK(next_header))){
					next_header->size_status |= P_BIT_MASK;
				}

				/** if its the first block must also set p bit to 1 **/
				if(curr == start_block){
					curr->size_status |= P_BIT_MASK;
				}
				/* THIS ^^^^ COULD ALL BE A FUNCTION */

				/** return the current pointer plus 1 block_header which is a pointer to the start of the data **/
				return curr + 1;
			}

			/* IF THE BLOCK ISN'T PERFECT SIZE */
			/* IF THE CURRENT BLOCK SIZE IS GREATER THAN REQUESTED SIZE AND ITS LESS THAN THE BEST CANDIDATE */
			if(BLK_HDR_SIZE(curr) > size && (best == NULL || BLK_HDR_SIZE(curr) < BLK_HDR_SIZE(best))){
				best = curr; // set the best block to the current block
			}
			
		}
			/* GET THE NEXT BLOCK */
			curr = NEXT_HEADER(curr);	
	}
	/* IF WE GET HERE AND BEST IS STILL NULL THEN THERE ARE NO SUFFICIENT BLOCKS */
	if(best == NULL){
		return NULL;
	}		



	/* SINCE WE DID NOT FIND A PERFECT SIZE BLOCK THERE WILL BE A REMAINING BLOCK */
	remainder = BLK_HDR_SIZE(best) - size;
	next = best + (size / sizeof(block_header));
	next->size_status = ((remainder | P_BIT_MASK) & ~(A_BIT_MASK));
	(next + (remainder / sizeof(block_header)) - 1)->size_status = remainder & SIZE_MASK;

	/* NOW SET UP THE BLOCK WE JUST CHOSE TO BE ALLOCATED */
	 best->size_status = size | (best->size_status & (A_BIT_MASK | P_BIT_MASK));
	 best->size_status |= A_BIT_MASK;

	 if(!IS_END_MARK(NEXT_HEADER(best))){
	 	NEXT_HEADER(best)->size_status |= P_BIT_MASK;
	 }

	 if(best == start_block){
		best->size_status |= P_BIT_MASK;
	 }
		
	 return best + 1;
}

/* 
 * Function for freeing up a previously allocated block.
 * Argument ptr: address of the block to be freed up.
 * Returns 0 on success.
 * Returns -1 on failure.
 * This function should:
 * - Return -1 if ptr is NULL.
 * - Return -1 if ptr is not a multiple of 8.
 * - Return -1 if ptr is outside of the heap space.
 * - Return -1 if ptr block is already freed.
 * - USE IMMEDIATE COALESCING if one or both of the adjacent neighbors are free.
 * - Update header(s) and footer as needed.
 */                    
int Free_Mem(void *ptr) {         
    
	block_header *header, *adj_header;
	
	/* IF PTR IS NULL OR NOT A MULTIPLE OF */
	if(ptr == NULL) return -1;
	if((int)ptr % 8 != 0) return -1;
	
	/* PTR IS A POINTER TO THE START OF THE PAYLOAD, NEED TO SUBTRACT A BLOCK HEADER TO
	 * GET TO THE HEADER */
	header = ptr - sizeof(block_header);

	/* IF ITS NOT ALLOCATED RETURN -1 BECAUSE IT IS ALREADY FREE */
	if(BLK_HDR_ALLOC(header) != 1) return -1;

	/* PREPARE THE CURRENT BLOCK TO BE FREE */
	header->size_status &= ~A_BIT_MASK;

	/* SET THE PREVIOUS BIT OF THE NEXT BLOCK TO FREE */
	if(!IS_END_MARK(NEXT_HEADER(header))) {
		NEXT_HEADER(header)->size_status &= ~P_BIT_MASK;
	}
	
	/* SET OUR FOOTER BLOCK */
	(NEXT_HEADER(header) - 1)->size_status &= SIZE_MASK;

	/* ATTEMPT TO COALESCE WITH NEXT BLOCK */
	if(!IS_END_MARK(NEXT_HEADER(header)) && (BLK_HDR_ALLOC(NEXT_HEADER(header)) != 1)) {
		header->size_status += NEXT_HEADER(header)->size_status;
		(header + (header->size_status / sizeof(block_header) - 1))->size_status = BLK_HDR_SIZE(header);
	}

	/* ATTEMPT TO COALESCE WITH PREV BLOCK */
	if(BLK_HDR_PREV(header) != 2){
		adj_header = header - ((header - 1)->size_status / sizeof(block_header));
		adj_header->size_status += header->size_status;
		(header - 1)->size_status = BLK_HDR_SIZE(adj_header);
	}	
	return 0;
}

/*
 * Function used to initialize the memory allocator.
 * Intended to be called ONLY once by a program.
 * Argument sizeOfRegion: the size of the heap space to be allocated.
 * Returns 0 on success.
 * Returns -1 on failure.
 */                    
int Init_Mem(int sizeOfRegion) {         
    int pagesize;
    int padsize;
    int fd;
    int alloc_size;
    void* space_ptr;
    block_header* end_mark;
    static int allocated_once = 0;
  
    if (0 != allocated_once) {
        fprintf(stderr, 
        "Error:mem.c: Init_Mem has allocated space during a previous call\n");
        return -1;
    }
    if (sizeOfRegion <= 0) {
        fprintf(stderr, "Error:mem.c: Requested block size is not positive\n");
        return -1;
    }

    // Get the pagesize
    pagesize = getpagesize();

    // Calculate padsize as the padding required to round up sizeOfRegion 
    // to a multiple of pagesize
    padsize = sizeOfRegion % pagesize;
    padsize = (pagesize - padsize) % pagesize;

    alloc_size = sizeOfRegion + padsize;

    // Using mmap to allocate memory
    fd = open("/dev/zero", O_RDWR);
    if (-1 == fd) {
        fprintf(stderr, "Error:mem.c: Cannot open /dev/zero\n");
        return -1;
    }
    space_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, 
                    fd, 0);
    if (MAP_FAILED == space_ptr) {
        fprintf(stderr, "Error:mem.c: mmap cannot allocate space\n");
        allocated_once = 0;
        return -1;
    }
  
    allocated_once = 1;

    // for double word alignment and end mark
    alloc_size -= 8;

    // To begin with there is only one big free block
    // initialize heap so that start block meets 
    // double word alignement requirement
    start_block = (block_header*) space_ptr + 1;
    end_mark = (block_header*)((void*)start_block + alloc_size);
  
    // Setting up the header
    start_block->size_status = alloc_size;

    // Marking the previous block as used
    start_block->size_status += 2;

    // Setting up the end mark and marking it as used
    end_mark->size_status = 1;

    // Setting up the footer
    block_header *footer = (block_header*) ((char*)start_block + alloc_size - 4);
    footer->size_status = alloc_size;
  
    return 0;
}         
                 
/* 
 * Function to be used for DEBUGGING to help you visualize your heap structure.
 * Prints out a list of all the blocks including this information:
 * No.      : serial number of the block 
 * Status   : free/used (allocated)
 * Prev     : status of previous block free/used (allocated)
 * t_Begin  : address of the first byte in the block (where the header starts) 
 * t_End    : address of the last byte in the block 
 * t_Size   : size of the block as stored in the block header
 */                     
void Dump_Mem() {         
    int counter;
    char status[5];
    char p_status[5];
    char *t_begin = NULL;
    char *t_end = NULL;
    int t_size;

    block_header *current = start_block;
    counter = 1;

    int used_size = 0;
    int free_size = 0;
    int is_used = -1;

    fprintf(stdout, "************************************Block list***\
                    ********************************\n");
    fprintf(stdout, "No.\tStatus\tPrev\tt_Begin\t\tt_End\t\tt_Size\n");
    fprintf(stdout, "-------------------------------------------------\
                    --------------------------------\n");
  
    while (current->size_status != 1) {
        t_begin = (char*)current;
        t_size = current->size_status;
    
        if (t_size & 1) {
            // LSB = 1 => used block
            strcpy(status, "used");
            is_used = 1;
            t_size = t_size - 1;
        } else {
            strcpy(status, "Free");
            is_used = 0;
        }

        if (t_size & 2) {
            strcpy(p_status, "used");
            t_size = t_size - 2;
        } else {
            strcpy(p_status, "Free");
        }

        if (is_used) 
            used_size += t_size;
        else 
            free_size += t_size;

        t_end = t_begin + t_size - 1;
    
        fprintf(stdout, "%d\t%s\t%s\t0x%08lx\t0x%08lx\t%d\n", counter, status, 
        p_status, (unsigned long int)t_begin, (unsigned long int)t_end, t_size);
    
        current = (block_header*)((char*)current + t_size);
        counter = counter + 1;
    }

    fprintf(stdout, "---------------------------------------------------\
                    ------------------------------\n");
    fprintf(stdout, "***************************************************\
                    ******************************\n");
    fprintf(stdout, "Total used size = %d\n", used_size);
    fprintf(stdout, "Total free size = %d\n", free_size);
    fprintf(stdout, "Total size = %d\n", used_size + free_size);
    fprintf(stdout, "***************************************************\
                    ******************************\n");
    fflush(stdout);

    return;
}         
