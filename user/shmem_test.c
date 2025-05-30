#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(void)
{
  int parent_pid = getpid();
  char *shared_buffer;
  uint64 shared_addr;
  char *test_message = "Hello daddy";
  
  printf("shmem_test: starting shared memory test\n");
  
  // Allocate some memory in parent
  shared_buffer = sbrk(4096);  // Allocate one page
  if(shared_buffer == (char*)-1) {
    printf("shmem_test: failed to allocate memory\n");
    exit(1);
  }
  
  printf("Parent process %d allocated buffer at %p\n", parent_pid, shared_buffer);
  printf("Parent size before fork: %d\n", (char*)sbrk(0) - (char*)0);
  
  int child_pid = fork();
  if(child_pid < 0) {
    printf("shmem_test: fork failed\n");
    exit(1);
  }
  
  if(child_pid == 0) {
    // Child process
    printf("Child process %d started\n", getpid());
    printf("Child size before mapping: %d\n", (char*)sbrk(0) - (char*)0);
    
    // Map shared memory from parent
    shared_addr = map_shared_pages(parent_pid, getpid(), (uint64)shared_buffer, 4096);
    if(shared_addr == 0) {
      printf("shmem_test: failed to map shared memory in child\n");
      exit(1);
    }
    
    printf("Child mapped shared memory at address %p\n", (void*)shared_addr);
    printf("Child size after mapping: %d\n", (char*)sbrk(0) - (char*)0);
    
    // Write message to shared memory
    char *child_buffer = (char*)shared_addr;
    strcpy(child_buffer, test_message);
    printf("Child wrote: '%s' to shared memory\n", test_message);
    
    // Test malloc after mapping
    char *malloc_test = sbrk(1024);
    if(malloc_test != (char*)-1) {
      printf("Child: malloc after mapping works\n");
    }
    printf("Child size after malloc: %d\n", (char*)sbrk(0) - (char*)0);
    
    // Unmap shared memory
    if(unmap_shared_pages(shared_addr, 4096) == 0) {
      printf("Child: successfully unmapped shared memory\n");
    } else {
      printf("Child: failed to unmap shared memory\n");
    }
    printf("Child size after unmapping: %d\n", (char*)sbrk(0) - (char*)0);
    
    // Test malloc after unmapping
    char *malloc_test2 = sbrk(1024);
    if(malloc_test2 != (char*)-1) {
      printf("Child: malloc after unmapping works\n");
    }
    printf("Child size after second malloc: %d\n", (char*)sbrk(0) - (char*)0);
    
    exit(0);
  } else {
    // Parent process
    sleep(1); // Let child write to memory first
    
    printf("Parent reading from shared buffer: '%s'\n", shared_buffer);
    
    // Verify the message
    if(strcmp(shared_buffer, test_message) == 0) {
      printf("shmem_test: SUCCESS - message correctly shared between processes\n");
    } else {
      printf("shmem_test: FAILED - message not correctly shared\n");
    }
    
    wait(0); // Wait for child to finish
    
    printf("Parent final size: %d\n", (char*)sbrk(0) - (char*)0);
    printf("shmem_test: test completed\n");
  }
  
  exit(0);
}