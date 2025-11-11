#include "cuda_utils.cuh"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <algorithm>

std::vector<const char*> generate_keys(const std::vector<std::string>& base_keys, 
                                      const std::vector<std::string>& suffixes = {},
                                      const std::vector<std::string>& prefixes = {}) {
    std::vector<const char*> keys;
    
    if (suffixes.empty() && prefixes.empty()) {
        for (const auto& key : base_keys) {
            char* new_key = new char[key.length() + 1];
            strcpy(new_key, key.c_str());
            keys.push_back(new_key);
        }
    } else {
        for (const auto& base : base_keys) {
            if (suffixes.empty()) {
                for (const auto& prefix : prefixes) {
                    std::string new_key_str = prefix + base;
                    char* new_key = new char[new_key_str.length() + 1];
                    strcpy(new_key, new_key_str.c_str());
                    keys.push_back(new_key);
                }
            } else if (prefixes.empty()) {
                for (const auto& suffix : suffixes) {
                    std::string new_key_str = base + suffix;
                    char* new_key = new char[new_key_str.length() + 1];
                    strcpy(new_key, new_key_str.c_str());
                    keys.push_back(new_key);
                }
            } else {
                for (const auto& prefix : prefixes) {
                    for (const auto& suffix : suffixes) {
                        std::string new_key_str = prefix + base + suffix;
                        char* new_key = new char[new_key_str.length() + 1];
                        strcpy(new_key, new_key_str.c_str());
                        keys.push_back(new_key);
                    }
                }
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

int main() {
    const char* encrypted_file = "trial.xls";
    const char* output_dir = ".";
    
    printf("🔓 CUDA RC4 Brute Force Decryptor\n");
    printf("===================================\n");
    
    std::vector<std::string> base_keys = {
        "MySecretKey", "mysecretkey", "MYSECRETKEY", "SecretKey", "secretkey",
        "Password", "password", "PASSWORD", "Key", "key", "KEY",
        "Admin", "admin", "ADMIN", "Test", "test", "TEST",
        "123456", "12345678", "123456789", "1234567890", "trial", "Trial", "TRIAL"
    };
    
    std::vector<std::string> suffixes = {
        "", "123", "1234", "12345", "123456", "1", "12", "2023", "2024", "2025",
        "!", "@", "#", "$", "%", "&", "*", "!!", "!!!"
    };
    
    std::vector<std::string> prefixes = {
        "", "My", "my", "MY", "The", "the", "THE", "A", "a"
    };
    
    // Generate keys
    printf("⏳ Generating keys...\n");
    std::vector<const char*> keys = generate_keys(base_keys, suffixes, prefixes);
    
    printf("📋 Jumlah keys yang akan diuji: %zu\n", keys.size());
    printf("🔍 Memulai brute force...\n\n");
    
    printf("Contoh keys yang akan diuji:\n");
    for (int i = 0; i < std::min(10, (int)keys.size()); i++) {
        printf("  %d. '%s'\n", i + 1, keys[i]);
    }
    if (keys.size() > 10) {
        printf("  ... dan %zu keys lainnya\n", keys.size() - 10);
    }
    printf("\n");
    
    int key_length = 0;
    for (const char* key : keys) {
        key_length = std::max(key_length, (int)strlen(key));
    }
    
    printf("📏 Panjang key maksimum: %d\n", key_length);
    
    char found_key[256] = {0};
    
    cudaError_t status = rc4_bruteforce_excel_file(encrypted_file, output_dir, 
                                                  keys.data(), keys.size(), 
                                                  key_length, found_key, sizeof(found_key));
    
    if (status == cudaSuccess) {
        printf("\n🎉 BRUTE FORCE BERHASIL!\n");
        printf("✅ Key yang ditemukan: '%s'\n", found_key);
        printf("✅ File telah didekripsi: ./decrypted_with_%s.xls\n", found_key);
    } else {
        printf("\n❌ Brute force dengan pattern umum gagal\n");
        printf("🔍 Mencoba dengan keys yang lebih spesifik...\n");
        
        std::vector<std::string> specific_keys = {
            "MySecretKey123", "mysecretkey123", "MYSECRETKEY123",
            "SecretKey123", "secretkey123", "Password123", "password123",
            "Admin123", "admin123", "Test123", "test123", "trial123", "Trial123"
        };
        
        std::vector<const char*> specific_keys_ptr;
        for (const auto& key : specific_keys) {
            char* new_key = new char[key.length() + 1];
            strcpy(new_key, key.c_str());
            specific_keys_ptr.push_back(new_key);
        }
        
        key_length = 0;
        for (const char* key : specific_keys_ptr) {
            key_length = std::max(key_length, (int)strlen(key));
        }
        
        printf("\n🔑 Mencoba %zu keys spesifik...\n", specific_keys_ptr.size());
        status = rc4_bruteforce_excel_file(encrypted_file, output_dir, 
                                          specific_keys_ptr.data(), specific_keys_ptr.size(), 
                                          key_length, found_key, sizeof(found_key));
        
        if (status == cudaSuccess) {
            printf("\n🎉 BRUTE FORCE BERHASIL (Attempt 2)!\n");
            printf("✅ Key yang ditemukan: '%s'\n", found_key);
            printf("✅ File telah didekripsi: ./decrypted_with_%s.xls\n", found_key);
        } else {
            printf("❌ Key tidak ditemukan. Coba dengan daftar key yang lebih luas.\n");
            printf("💡 Tips:\n");
            printf("   - Periksa apakah file 'trial.xls' ada di directory yang benar\n");
            printf("   - Pastikan file memang terenkripsi dengan RC4\n");
            printf("   - Coba dengan key manual: ./tster\n");
        }
        
        free_keys(specific_keys_ptr);
    }
    
    // Cleanup
    free_keys(keys);
    
    return (status == cudaSuccess) ? 0 : 1;
}