/**
 * Sample C++ code for testing code analyzers
 * Contains intentional bugs and vulnerabilities
 */

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <algorithm>

// Global variables
int g_counter = 0;
std::mutex g_mutex;

// Class with potential resource leaks
class ResourceManager {
private:
    int* data;
    FILE* file;
    
public:
    ResourceManager() {
        // Allocate resources
        data = new int[100];
        file = fopen("temp.txt", "w");
    }
    
    // Missing copy constructor - Rule of Three violation
    
    // Missing copy assignment operator - Rule of Three violation
    
    // Destructor doesn't clean up all resources - memory leak
    ~ResourceManager() {
        // Only frees one resource, forgetting 'data'
        if (file) {
            fclose(file);
        }
        // Missing delete[] data;
    }
    
    void write_data() {
        for (int i = 0; i < 100; i++) {
            data[i] = i;
            if (file) {
                fprintf(file, "%d\n", i);
            }
        }
    }
};

// Class with thread safety issues
class ThreadUnsafeCounter {
private:
    int counter;
    
public:
    ThreadUnsafeCounter() : counter(0) {}
    
    // Not thread-safe
    void increment() {
        counter++;
    }
    
    int get_value() {
        return counter;
    }
};

// Function with dangling reference
std::string& get_dangling_reference() {
    std::string local_str = "temporary string";
    // Returning reference to local variable
    return local_str;
}

// Function with potential null pointer dereference in C++
void cpp_null_pointer(std::shared_ptr<int> ptr) {
    // Using without checking if valid
    *ptr = 10;
}

// Function with move semantics issues
void move_semantics_issue() {
    std::vector<int> vec1 = {1, 2, 3, 4, 5};
    std::vector<int> vec2 = std::move(vec1);
    
    // Using vec1 after move - undefined behavior
    vec1.push_back(6);
}

// Function with improper exception handling
void exception_issues(int value) {
    try {
        std::vector<int> vec;
        // Might throw out_of_range exception
        std::cout << vec.at(value) << std::endl;
    } catch (std::exception& e) {
        // Proper exception handling
        std::cerr << "Exception caught: " << e.what() << std::endl;
        // But then re-throwing without information
        throw;
    }
}

// Race condition in multi-threaded code
void race_condition_function() {
    // No mutex protection
    g_counter++;
}

// Proper thread-safe function
void thread_safe_function() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_counter++;
}

// Integer sign conversion issues
void sign_conversion() {
    int negative = -1;
    unsigned int positive = negative;  // Signed to unsigned conversion
    
    std::cout << "Converted value: " << positive << std::endl;
}

// Memory leak with smart pointers
void smart_pointer_leak() {
    // Proper use of smart pointer
    auto smart_int = std::make_shared<int>(42);
    
    // Raw pointer leak
    int* raw_int = new int(10);
    
    // Improper use of raw pointer with smart pointer
    smart_int.reset(raw_int);  // Original smart_int value leaked
}

// Uninitialized member variable
class UninitializedMembers {
private:
    int x;
    double y;
    
public:
    // Missing initialization in constructor
    UninitializedMembers() {
        // x and y are uninitialized
    }
    
    int get_sum() {
        return x + static_cast<int>(y);
    }
};

int main() {
    std::cout << "Running C++ sample code with potential issues" << std::endl;
    
    // Resource leak
    {
        ResourceManager manager;
        manager.write_data();
        // ResourceManager destructor will be called here but won't delete 'data'
    }
    
    // Thread safety issues
    {
        ThreadUnsafeCounter counter;
        
        // Create threads that increment the counter
        std::thread t1([&counter]() {
            for (int i = 0; i < 1000; i++) {
                counter.increment();
            }
        });
        
        std::thread t2([&counter]() {
            for (int i = 0; i < 1000; i++) {
                counter.increment();
            }
        });
        
        t1.join();
        t2.join();
        
        // Due to race conditions, this may not be 2000
        std::cout << "Counter value: " << counter.get_value() << std::endl;
    }
    
    // Dangling reference
    {
        // Assigning to a dangling reference
        std::string& ref = get_dangling_reference();
        std::cout << "Dangling reference: " << ref << std::endl;  // Undefined behavior
    }
    
    // Null pointer dereference
    {
        std::shared_ptr<int> null_ptr;
        try {
            cpp_null_pointer(null_ptr);  // Will throw exception
        } catch (std::exception& e) {
            std::cerr << "Caught exception: " << e.what() << std::endl;
        }
    }
    
    // Move semantics issue
    move_semantics_issue();
    
    // Exception issues
    try {
        exception_issues(10);  // Out of range
    } catch (...) {
        std::cerr << "Caught re-thrown exception" << std::endl;
    }
    
    // Race condition
    {
        g_counter = 0;
        
        std::thread t1(race_condition_function);
        std::thread t2(race_condition_function);
        
        t1.join();
        t2.join();
        
        std::cout << "Race condition counter: " << g_counter << std::endl;
    }
    
    // Sign conversion
    sign_conversion();
    
    // Smart pointer leak
    smart_pointer_leak();
    
    // Uninitialized members
    {
        UninitializedMembers obj;
        std::cout << "Sum of uninitialized members: " << obj.get_sum() << std::endl;
    }
    
    return 0;
} 