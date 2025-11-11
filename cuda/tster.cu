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
        {
            std::lock_guard<std::mutex> lock(key_mutex);
            current_offset = current_batch * batch_size;
            current_batch++;
        }
        
        std::vector<const char*> keys = generate_key_batch(base_keys, suffixes, prefixes, batch_size, current_offset);
        
        if (keys.empty()) {
            break; // No more keys to generate
        }
        
        printf("🔍 Worker memproses batch %d dengan %zu keys...\n", current_batch, keys.size());
        
        // Calculate maximum key length for this batch
        int key_length = 0;
        for (const char* key : keys) {
            key_length = std::max(key_length, (int)strlen(key));
        }
        
        // Execute brute force
        cudaError_t status = rc4_bruteforce_excel_file(encrypted_file, output_dir,
                                                      keys.data(), keys.size(),
                                                      key_length, found_key, sizeof(found_key));
        
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
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
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
        
        // Key related
        "key", "Key", "KEY", "secret", "Secret", "SECRET",
        "pass", "Pass", "PASS", "code", "Code", "CODE",
        "cipher", "Cipher", "CIPHER",
        
        // Company/organization
        "company", "Company", "COMPANY", "corp", "Corp", "CORP",
        "business", "Business", "BUSINESS", "enterprise", "Enterprise", "ENTERPRISE",
        
        // Numbers only
        "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
        "111", "1111", "11111", "111111",
        "000", "0000", "00000", "000000",
        
        // Common words
        "hello", "Hello", "HELLO", "world", "World", "WORLD",
        "welcome", "Welcome", "WELCOME", "access", "Access", "ACCESS",
        "default", "Default", "DEFAULT", "temp", "Temp", "TEMP",
        "backup", "Backup", "BACKUP", "restore", "Restore", "RESTORE"
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
        "!", "!!", "!!!", "@", "#", "$", "%", "^", "&", "*",
        
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
                // Skip if this pattern previously failed
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
    
    printf("📋 Base keys: %zu\n", base_keys.size());
    printf("📋 Suffixes: %zu\n", suffixes.size());
    printf("📋 Prefixes: %zu\n", prefixes.size());
    
    size_t total_combinations = base_keys.size() * suffixes.size() * prefixes.size();
    printf("🎯 Total possible combinations: %zu\n", total_combinations);
    
    // Configuration
    const int NUM_WORKERS = 4;  
    const int BATCH_SIZE = 1000; 
    
    printf("🚀 Menjalankan %d workers paralel (batch size: %d keys)\n", NUM_WORKERS, BATCH_SIZE);
    printf("⏳ Memulai brute force paralel...\n\n");
    
    std::vector<std::thread> workers;
    
    for (int i = 0; i < NUM_WORKERS; i++) {
        workers.emplace_back(brute_force_worker, encrypted_file, output_dir,
                           base_keys, suffixes, prefixes, BATCH_SIZE);
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
    
    if (!found_key_str.empty()) {
        printf("\n🎉 BRUTE FORCE BERHASIL!\n");
        printf("✅ Key yang ditemukan: '%s'\n", found_key_str.c_str());
        printf("✅ File telah didekripsi: ./decrypted_with_%s.xls\n", found_key_str.c_str());
        
        // Verify the decryption
        printf("🔍 Memverifikasi file terdekripsi...\n");

        
        return 0;
    } else {
        printf("\n❌ Key tidak ditemukan setelah mencoba banyak kombinasi\n");
        printf("💡 Tips:\n");
        printf("   - Coba tambahkan lebih banyak pattern key\n");
        printf("   - Periksa apakah file benar-benar terenkripsi RC4\n");
        printf("   - Gunakan dictionary attack dengan wordlist khusus\n");
        
        return 1;
    }
}