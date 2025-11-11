#include "cuda_utils.cuh"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage() {
    printf("Usage: ./decrypt_excel <encrypted_file> <key>\n");
    printf("Example: ./decrypt_excel trial.xls MySecretKey123\n");
}

int main(int argc, char* argv[]) {
    const char* encrypted_file;
    const char* key;
    
    if (argc == 3) {
        encrypted_file = argv[1];
        key = argv[2];
    } else if (argc == 1) {
        // Default values
        encrypted_file = "trial.xls";
        key = "MySecretKey123";
    } else {
        print_usage();
        return 1;
    }
    
    char decrypted_file[256];
    const char* dot = strrchr(encrypted_file, '.');
    if (dot != NULL) {
        int name_length = dot - encrypted_file;
        strncpy(decrypted_file, encrypted_file, name_length);
        sprintf(decrypted_file + name_length, "_decrypted%s", dot);
    } else {
        sprintf(decrypted_file, "%s_decrypted", encrypted_file);
    }
    
    printf("🔐 CUDA Excel File Decryptor\n");
    printf("==============================\n");
    printf("Input file:  %s\n", encrypted_file);
    printf("Output file: %s\n", decrypted_file);
    printf("Key:         %s\n", key);
    printf("==============================\n");
    
    // Check CUDA device
    int device_count;
    cudaGetDeviceCount(&device_count);
    if (device_count == 0) {
        printf("❌ Tidak ada device CUDA yang ditemukan!\n");
        return 1;
    }
    
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    printf("Menggunakan GPU: %s\n", prop.name);
    
    printf("\n⏳ Memulai proses dekripsi...\n");
    
    cudaError_t status = rc4_decrypt_excel_file(encrypted_file, decrypted_file, key);
    
    if (status == cudaSuccess) {
        printf("✅ Dekripsi berhasil!\n");
        
        FILE* file = fopen(decrypted_file, "rb");
        if (file) {
            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            fclose(file);
            printf("📁 Ukuran file hasil: %ld bytes\n", size);
        }
        
        printf("\n🎉 File berhasil didekripsi: %s\n", decrypted_file);
    } else {
        printf("❌ Dekripsi gagal!\n");
        printf("Error: %s\n", cudaGetErrorString(status));
        
        // Detailed error information
        switch(status) {
            case cudaErrorFileNotFound:
                printf("• File '%s' tidak ditemukan\n", encrypted_file);
                printf("• Pastikan file berada di directory yang benar\n");
                break;
            case cudaErrorInvalidValue:
                printf("• File bukan format Excel yang valid\n");
                printf("• atau file tidak terenkripsi dengan RC4\n");
                printf("• atau key yang digunakan salah\n");
                break;
            case cudaErrorMemoryAllocation:
                printf("• Gagal mengalokasikan memory di GPU\n");
                break;
            default:
                printf("• Error code: %d\n", status);
        }
        return 1;
    }
    
    return 0;
}