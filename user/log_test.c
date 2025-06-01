#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define NUM_CHILDREN 4
#define BUFFER_SIZE 4096  // One page
#define MAX_MESSAGE_SIZE 100

// Header structure: child_index (16 bits) + message_length (16 bits)
struct log_header {
    uint16 child_index;
    uint16 message_length;
};

// Helper function to align address to 4-byte boundary
uint64 align_address(uint64 addr) {
    return (addr + 3) & ~3;
}

// Child process logging function
void child_logger(int child_index, char *shared_buffer, int parent_pid) {
    printf("Child %d: Starting logging\n", child_index);
    
    char message[MAX_MESSAGE_SIZE];
    int message_count = 0;
    
    // Generate multiple messages
    for (int i = 0; i < 5; i++) {
        // Create simple message for this child
        strcpy(message, "Hello from child ");
        int len = strlen(message);
        message[len] = '0' + child_index;
        message[len + 1] = ' ';
        message[len + 2] = 'm';
        message[len + 3] = 's';
        message[len + 4] = 'g';
        message[len + 5] = ' ';
        message[len + 6] = '0' + i;
        message[len + 7] = '\0';
        
        uint16 msg_len = strlen(message);
        uint64 current_pos = 0;
        int attempts = 0;
        int success = 0;
        
        // Try to find a spot in the buffer
        while (current_pos + sizeof(struct log_header) + msg_len < BUFFER_SIZE && attempts < 1000) {
            // Ensure we're at a 4-byte aligned position
            current_pos = align_address(current_pos);
            
            // Check if we're still within bounds
            if (current_pos + sizeof(struct log_header) + msg_len >= BUFFER_SIZE) {
                printf("Child %d: Buffer full, stopping\n", child_index);
                goto child_exit;
            }
            
            // Get pointer to header location
            struct log_header *header = (struct log_header *)(shared_buffer + current_pos);
            
            // Try to atomically claim this spot (compare 0 with our header)
            struct log_header new_header;
            new_header.child_index = child_index;
            new_header.message_length = msg_len;
            
            uint32 zero_header = 0;
            uint32 our_header = *(uint32*)&new_header;
            
            uint32 old_value = __sync_val_compare_and_swap((uint32*)header, zero_header, our_header);
            
            if (old_value == 0) {
                // Successfully claimed this spot! Write the message
                char *msg_ptr = shared_buffer + current_pos + sizeof(struct log_header);
                strcpy(msg_ptr, message);
                
                printf("Child %d: Wrote message %d at offset %d\n", child_index, i, (int)current_pos);
                message_count++;
                success = 1;
                break;
            } else {
                // Spot was taken, skip to next potential location
                struct log_header *existing = (struct log_header *)(shared_buffer + current_pos);
                if (existing->message_length > 0) {
                    current_pos += sizeof(struct log_header) + existing->message_length;
                    current_pos = align_address(current_pos);
                } else {
                    current_pos += sizeof(struct log_header);
                    current_pos = align_address(current_pos);
                }
            }
            attempts++;
        }
        
        if (!success) {
            printf("Child %d: Failed to write message %d after %d attempts\n", child_index, i, attempts);
        }
        
        // Small delay between messages  
        sleep(2);
    }
    
child_exit:
    printf("Child %d: Finished logging, wrote %d messages\n", child_index, message_count);
}

// Parent process reading function - FIXED VERSION
void parent_reader(char *shared_buffer) {
    printf("Parent: Starting to read all messages in buffer\n");
    
    uint64 read_pos = 0;
    int messages_read = 0;
    
    // Single pass through the buffer to read all messages
    while (read_pos + sizeof(struct log_header) < BUFFER_SIZE) {
        read_pos = align_address(read_pos);
        
        if (read_pos + sizeof(struct log_header) >= BUFFER_SIZE) {
            break;
        }
        
        struct log_header *header = (struct log_header *)(shared_buffer + read_pos);
        
        if (header->child_index != 0 && header->message_length > 0) {
            // Found a message
            if (read_pos + sizeof(struct log_header) + header->message_length < BUFFER_SIZE) {
                char *message = shared_buffer + read_pos + sizeof(struct log_header);
                printf("Parent read from child %d: %s\n", header->child_index, message);
                messages_read++;
            }
            
            read_pos += sizeof(struct log_header) + header->message_length;
        } else {
            read_pos += sizeof(struct log_header);
        }
        
        read_pos = align_address(read_pos);
    }
    
    printf("Parent: Finished reading, total messages found: %d\n", messages_read);
}

int main(void) {
    printf("log_test: Starting multi-process logging test\n");
    
    int parent_pid = getpid();
    char *shared_buffer;
    
    // Allocate shared buffer
    shared_buffer = sbrk(BUFFER_SIZE);
    if (shared_buffer == (char*)-1) {
        printf("log_test: Failed to allocate shared buffer\n");
        exit(1);
    }
    
    // Initialize buffer to zero
    memset(shared_buffer, 0, BUFFER_SIZE);
    
    printf("Parent: Allocated shared buffer at %p\n", shared_buffer);
    
    // Create child processes
    for (int i = 0; i < NUM_CHILDREN; i++) {
        int pid = fork();
        if (pid < 0) {
            printf("log_test: Fork failed for child %d\n", i);
            exit(1);
        }
        
        if (pid == 0) {
            // Child process
            printf("Child %d (PID %d): Starting\n", i + 1, getpid());
            
            // Map shared buffer from parent
            uint64 shared_addr = map_shared_pages(parent_pid, getpid(), (uint64)shared_buffer, BUFFER_SIZE);
            if (shared_addr == 0) {
                printf("Child %d: Failed to map shared buffer\n", i + 1);
                exit(1);
            }
            
            printf("Child %d: Mapped shared buffer at %p\n", i + 1, (void*)shared_addr);
            
            // Start logging
            child_logger(i + 1, (char*)shared_addr, parent_pid);
            
            exit(0);
        }
        // Parent continues to next iteration
    }
    
    // Wait for all children to finish writing first
    printf("Parent: Waiting for all children to finish writing...\n");
    for (int i = 0; i < NUM_CHILDREN; i++) {
        int status;
        wait(&status);
        printf("Parent: Child %d finished with status %d\n", i+1, status);
    }
    
    // Now read all the messages that were written
    printf("Parent: All children finished, now reading messages...\n");
    parent_reader(shared_buffer);
    
    printf("log_test: Multi-process logging test completed\n");
    return 0;
}