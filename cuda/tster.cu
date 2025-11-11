#include "cuda_utils.cuh"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <algorithm>
#include <string>
#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

std::atomic<bool> key_found(false);
std::atomic<int> current_batch(0);
std::atomic<int> total_tested(0);
std::mutex key_mutex;
std::condition_variable key_cv;
std::string found_key_str;

struct KeyBatch {
    std::vector<const char*> keys;
    int key_length;
};

std::vector<const char*> generate_key_batch(const std::vector<std::string>& base_keys,
                                          const std::vector<std::string>& suffixes,
                                          const std::vector<std::string>& prefixes,
                                          int batch_size, int offset) {
    std::vector<const char*> keys;
    int count = 0;
    
    for (const auto& base : base_keys) {
        for (const auto& prefix : prefixes) {
            for (const auto& suffix : suffixes) {
                if (count < offset) {
                    count++;
                    continue;
                }
                
                if (count >= offset + batch_size) {
                    return keys;
                }
                
                std::string new_key_str = prefix + base + suffix;
                char* new_key = new char[new_key_str.length() + 1];
                strcpy(new_key, new_key_str.c_str());
                keys.push_back(new_key);
                count++;
            }
        }
    }
    
    return keys;
}

void free_keys(std::vector<const char*>& keys) {
    for (const char* key : keys) {
        delete[] key;
    }
    keys.clear();
}

void brute_force_worker(const char* encrypted_file, const char* output_dir,
                       const std::vector<std::string>& base_keys,
                       const std::vector<std::string>& suffixes,
                       const std::vector<std::string>& prefixes,
                       int batch_size) {
    char found_key[256] = {0};
    
    while (!key_found) {
        int current_offset;
        int batch_number;
        {
            std::lock_guard<std::mutex> lock(key_mutex);
            current_offset = current_batch * batch_size;
            batch_number = current_batch.load(); 
            current_batch++;
        }
        
        std::vector<const char*> keys = generate_key_batch(base_keys, suffixes, prefixes, batch_size, current_offset);
        
        if (keys.empty()) {
            break;
        }
        
        // Simple one-line output
        printf("\r🔍 Testing batch %d (%d keys)... Total tested: %d", 
               batch_number, (int)keys.size(), total_tested.load());
        fflush(stdout);
        
        int key_length = 0;
        for (const char* key : keys) {
            key_length = std::max(key_length, (int)strlen(key));
        }
        
        cudaError_t status = rc4_bruteforce_excel_file(encrypted_file, output_dir,
                                                      keys.data(), keys.size(),
                                                      key_length, found_key, sizeof(found_key));
        
        total_tested += keys.size();
        
        // Cleanup
        free_keys(keys);
        
        if (status == cudaSuccess) {
            {
                std::lock_guard<std::mutex> lock(key_mutex);
                if (!key_found) {
                    key_found = true;
                    found_key_str = found_key;
                    key_cv.notify_all();
                }
            }
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}


cudaError_t rc4_bruteforce_excel_file_quiet(const char* input_file, const char* output_dir, 
                                           const char** keys, int num_keys, int key_length, 
                                           char* found_key, int max_key_length) {
    uint8_t* d_data = nullptr;
    size_t file_size;
    
    cudaError_t cudaStatus = read_file_to_gpu(input_file, &d_data, &file_size);
    if (cudaStatus != cudaSuccess) {
        return cudaStatus;
    }
    
    char* d_keys = nullptr;
    size_t keys_size = num_keys * key_length;
    cudaStatus = cudaMalloc(&d_keys, keys_size);
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        return cudaStatus;
    }
    
    for (int i = 0; i < num_keys; i++) {
        cudaMemcpy(d_keys + i * key_length, keys[i], key_length, cudaMemcpyHostToDevice);
    }
    
    bool* d_found = nullptr;
    int* d_found_index = nullptr;
    bool h_found = false;
    int h_found_index = -1;
    
    cudaMalloc(&d_found, sizeof(bool));
    cudaMalloc(&d_found_index, sizeof(int));
    
    cudaMemset(d_found, 0, sizeof(bool));
    cudaMemset(d_found_index, -1, sizeof(int));
    
    int blockSize = 256;
    int numBlocks = (num_keys + blockSize - 1) / blockSize;
    
    rc4_bruteforce_kernel<<<numBlocks, blockSize>>>(d_data, file_size, d_keys, 
                                                   num_keys, key_length, d_found, d_found_index);
    
    cudaStatus = cudaGetLastError();
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_keys);
        cudaFree(d_found);
        cudaFree(d_found_index);
        return cudaStatus;
    }
    
    cudaStatus = cudaDeviceSynchronize();
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_keys);
        cudaFree(d_found);
        cudaFree(d_found_index);
        return cudaStatus;
    }
    
    cudaMemcpy(&h_found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
    cudaMemcpy(&h_found_index, d_found_index, sizeof(int), cudaMemcpyDeviceToHost);
    
    if (h_found && h_found_index >= 0 && h_found_index < num_keys) {
        char* successful_key = new char[key_length + 1];
        cudaMemcpy(successful_key, d_keys + h_found_index * key_length, key_length, cudaMemcpyDeviceToHost);
        successful_key[key_length] = '\0';
        
        strncpy(found_key, successful_key, max_key_length);
        
        char output_file[256];
        snprintf(output_file, sizeof(output_file), "%s/decrypted_with_%s.xls", output_dir, successful_key);
        
        cudaError_t decrypt_status = rc4_decrypt_excel_file(input_file, output_file, successful_key);
        
        delete[] successful_key;
        
        cudaFree(d_data);
        cudaFree(d_keys);
        cudaFree(d_found);
        cudaFree(d_found_index);
        
        return decrypt_status;
    }
    
    cudaFree(d_data);
    cudaFree(d_keys);
    cudaFree(d_found);
    cudaFree(d_found_index);
    
    return cudaErrorUnknown;
}

std::vector<std::string> generate_comprehensive_base_keys() {
    return {
        // Common passwords
        "password", "Password", "PASSWORD", "pass", "Pass", "PASS",
        "admin", "Admin", "ADMIN", "root", "Root", "ROOT",
        "test", "Test", "TEST", "demo", "Demo", "DEMO",
        "user", "User", "USER", "guest", "Guest", "GUEST",
        
        // Application specific
        "excel", "Excel", "EXCEL", "office", "Office", "OFFICE",
        "msoffice", "MSOffice", "MSOFFICE", "ms", "MS",
        "microsoft", "Microsoft", "MICROSOFT",
        
        // Trial related
        "trial", "Trial", "TRIAL", "try", "Try", "TRY",
        "eval", "Eval", "EVAL", "evaluation", "Evaluation", "EVALUATION",
        "demo", "Demo", "DEMO",
        
        "key", "Key", "KEY", "secret", "Secret", "SECRET",
        "pass", "Pass", "PASS", "code", "Code", "CODE",
        "cipher", "Cipher", "CIPHER",
        
        "company", "Company", "COMPANY", "corp", "Corp", "CORP",
        "business", "Business", "BUSINESS", "enterprise", "Enterprise", "ENTERPRISE",
        
        "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
        "111", "1111", "11111", "111111",
        "000", "0000", "00000", "000000",
        
        // Common words
        "hello", "Hello", "HELLO", "world", "World", "WORLD",
        "welcome", "Welcome", "WELCOME", "access", "Access", "ACCESS",
        "default", "Default", "DEFAULT", "temp", "Temp", "TEMP",
        "backup", "Backup", "BACKUP", "restore", "Restore", "RESTORE",
        
        // Original keys
        "MySecretKey", "mysecretkey", "MYSECRETKEY", "SecretKey", "secretkey",
        "Password", "password", "PASSWORD", "Key", "key", "KEY",
        "Admin", "admin", "ADMIN", "Test", "test", "TEST",
        "123456", "12345678", "123456789", "1234567890", "trial", "Trial", "TRIAL"
    };
}

std::vector<std::string> generate_comprehensive_suffixes() {
    return {
        "", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0",
        "01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
        "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
        "21", "22", "23", "24", "25", "26", "27", "28", "29", "30",
        "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
        
        "2020", "2021", "2022", "2023", "2024", "2025",
        "2019", "2018", "2017", "2016", "2015",
        
        "!", "!!", "!!!", "@", "#", "$", "%", "^", "&", "*", "()", "{}", "[]",
        
        "!1", "!12", "!123", "!1234",
        "@1", "@12", "@123", "@1234",
        "#1", "#12", "#123", "#1234"
    };
}

std::vector<std::string> generate_comprehensive_prefixes() {
    return {
        "", "my", "My", "MY", "the", "The", "THE",
        "a", "A", "an", "An", "AN",
        "new", "New", "NEW", "old", "Old", "OLD",
        "super", "Super", "SUPER", "mega", "Mega", "MEGA",
        "ultra", "Ultra", "ULTRA", "hyper", "Hyper", "HYPER",
        "ms", "MS", "ms_", "MS_", "_", "-"
    };
}

class SmartKeyGenerator {
private:
    std::vector<std::string> successful_patterns;
    std::vector<std::string> failed_patterns;
    
public:
    void add_successful_pattern(const std::string& pattern) {
        successful_patterns.push_back(pattern);
    }
    
    void add_failed_pattern(const std::string& pattern) {
        failed_patterns.push_back(pattern);
    }
    
    std::vector<std::string> generate_smart_keys(int count) {
        std::vector<std::string> keys;
        
        for (const auto& pattern : successful_patterns) {
            if (keys.size() >= count) break;
            
            for (int i = 0; i <= 9 && keys.size() < count; i++) {
                keys.push_back(pattern + std::to_string(i));
            }
            
            std::vector<std::string> specials = {"!", "@", "#", "$", "%"};
            for (const auto& spec : specials) {
                if (keys.size() >= count) break;
                keys.push_back(pattern + spec);
            }
        }
        
        auto base_keys = generate_comprehensive_base_keys();
        auto suffixes = generate_comprehensive_suffixes();
        
        for (const auto& base : base_keys) {
            if (keys.size() >= count) break;
            
            for (const auto& suffix : suffixes) {
                if (keys.size() >= count) break;
                
                std::string key = base + suffix;
                if (std::find(failed_patterns.begin(), failed_patterns.end(), key) == failed_patterns.end()) {
                    keys.push_back(key);
                }
            }
        }
        
        return keys;
    }
};

int main() {
    const char* encrypted_file = "trial.xls";
    const char* output_dir = ".";
    
    printf("🔓 CUDA RC4 PARALLEL BRUTE FORCE DECRYPTOR\n");
    printf("==========================================\n");
    
    auto base_keys = generate_comprehensive_base_keys();
    auto suffixes = generate_comprehensive_suffixes();
    auto prefixes = generate_comprehensive_prefixes();
    
    printf("📋 Base keys: %zu, Suffixes: %zu, Prefixes: %zu\n", 
           base_keys.size(), suffixes.size(), prefixes.size());
    
    size_t total_combinations = base_keys.size() * suffixes.size() * prefixes.size();
    printf("🎯 Total possible combinations: %zu\n", total_combinations);
    
    // Configuration
    const int NUM_WORKERS = 4;  
    const int BATCH_SIZE = 1000; 
    
    printf("🚀 Starting %d parallel workers (batch size: %d keys)\n", NUM_WORKERS, BATCH_SIZE);
    printf("⏳ Starting parallel brute force...\n\n");
    
    std::vector<std::thread> workers;
    
    for (int i = 0; i < NUM_WORKERS; i++) {
        workers.emplace_back([encrypted_file, output_dir, base_keys, suffixes, prefixes, batch_size = BATCH_SIZE]() {
            char found_key[256] = {0};
            
            while (!key_found) {
                int current_offset;
                int batch_number;
                {
                    std::lock_guard<std::mutex> lock(key_mutex);
                    current_offset = current_batch * batch_size;
                    batch_number = current_batch.load(); 
                    current_batch++;
                }
                
                std::vector<const char*> keys = generate_key_batch(base_keys, suffixes, prefixes, batch_size, current_offset);
                
                if (keys.empty()) {
                    break;
                }
                
                printf("\r🔍 Testing batch %d (%d keys)... Total tested: %d", 
                       batch_number, (int)keys.size(), total_tested.load());
                fflush(stdout);
                
                int key_length = 0;
                for (const char* key : keys) {
                    key_length = std::max(key_length, (int)strlen(key));
                }
                
                cudaError_t status = rc4_bruteforce_excel_file_quiet(encrypted_file, output_dir,
                                                                      keys.data(), keys.size(),
                                                                      key_length, found_key, sizeof(found_key));
                
                // Update total tested
                total_tested += keys.size();
                
                // Cleanup
                free_keys(keys);
                
                if (status == cudaSuccess) {
                    {
                        std::lock_guard<std::mutex> lock(key_mutex);
                        if (!key_found) {
                            key_found = true;
                            found_key_str = found_key;
                            key_cv.notify_all();
                        }
                    }
                    break;
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        });
    }
    
    {
        std::unique_lock<std::mutex> lock(key_mutex);
        key_cv.wait(lock, []{ return key_found.load(); });
    }
    
    key_found = true;
    
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
    // Clear the progress line
    printf("\r");
    
    if (!found_key_str.empty()) {
        printf("\n🎉 BRUTE FORCE SUCCESSFUL!\n");
        printf("✅ Key found: '%s'\n", found_key_str.c_str());
        printf("✅ File decrypted: ./decrypted_with_%s.xls\n", found_key_str.c_str());
        printf("📊 Total keys tested: %d\n", total_tested.load());
        
        return 0;
    } else {
        printf("\n❌ Key not found after testing %d keys\n", total_tested.load());
        printf("💡 Tips:\n");
        printf("   - Try adding more key patterns\n");
        printf("   - Check if file is actually RC4 encrypted\n");
        printf("   - Use dictionary attack with custom wordlist\n");
        
        return 1;
    }
}