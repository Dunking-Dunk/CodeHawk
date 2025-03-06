/**
 * Sample C code for testing code analyzers
 * Contains intentional bugs and vulnerabilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global variable
int global_counter = 0;

// Function with potential buffer overflow
void unsafe_copy(char* input) {
    char buffer[10];
    // Buffer overflow vulnerability
    strcpy(buffer, input);
    printf("Buffer content: %s\n", buffer);
}

// Function with potential memory leak
void *memory_leak() {
    // Allocated but never freed in some paths
    int *data = (int*)malloc(sizeof(int) * 10);
    if (data == NULL) {
        return NULL;
    }
    
    // Initialize data
    for (int i = 0; i < 10; i++) {
        data[i] = i;
    }
    
    global_counter++;
    
    // Memory leak if early return
    if (global_counter % 2 == 0) {
        return data;
    }
    
    // This path frees memory correctly
    free(data);
    return NULL;
}

// Function with uninitialized variable
int use_uninitialized() {
    int x;
    // x is uninitialized
    return x + 5;
}

// Function with null pointer dereference
void null_pointer_deref(int *ptr) {
    // No null check before dereferencing
    *ptr = 10;
}

// Function with unreachable code
void unreachable_code() {
    printf("This will be printed\n");
    return;
    // Dead code
    printf("This will never be printed\n");
}

// Function with integer overflow
int integer_overflow(int a, int b) {
    // Can cause overflow
    return a + b;
}

// Format string vulnerability
void format_string_vuln(char *user_input) {
    // Format string vulnerability
    printf(user_input);
}

// Off-by-one error
void off_by_one() {
    int array[10];
    // Off-by-one error (array[10] is invalid)
    for (int i = 0; i <= 10; i++) {
        array[i] = i;
    }
}

// Double free error
void double_free() {
    int *data = (int*)malloc(sizeof(int));
    *data = 10;
    free(data);
    // Double free vulnerability
    free(data);
}

// Use after free
void use_after_free() {
    int *data = (int*)malloc(sizeof(int));
    *data = 10;
    free(data);
    // Use after free vulnerability
    *data = 20;
}

// Division by zero
int \
    // Leaked if not freed
    
    int uninit_result = use_uninitialized();
    printf("Uninitialized result: %d\n", uninit_result);
    
    int *valid_ptr = (int*)malloc(sizeof(int));
    null_pointer_deref(valid_ptr);
    free(valid_ptr);
    
    // Potential null pointer dereference
    null_pointer_deref(NULL);
    
    unreachable_code();
    
    int overflow_result = integer_overflow(2147483647, 1);
    printf("Overflow result: %d\n", overflow_result);
    
    format_string_vuln("%s%s%s%s%s%s");
    
    off_by_one();
    
    // Commenting out to prevent program crash
    // double_free();
    // use_after_free();
    
    int division_result = div_by_zero(10, 0);
    printf("Division result: %d\n", division_result);
    
    return 0;
} 