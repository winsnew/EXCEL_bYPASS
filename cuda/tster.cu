#include "cuda_utils.cuh"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    const char* encrypted_file = "trial.xls";
    const char* decrypted_file = "trial_decrypted.xls";
    const char* key = "MySecretKey123"; 
    
    printf("Memulai dekripsi file: %s\n", encrypted_file);
    printf("Output file: %s\n", decrypted_file);
    printf("Menggunakan key: %s\n", key);
    
    cudaError_t status = rc4_decrypt_excel_file(encrypted_file, decrypted_file, key);
    
    if (status == cudaSuccess) {
        printf("✅ Dekripsi berhasil!\n");
        printf("File hasil dekripsi: %s\n", decrypted_file);
    } else {
        printf("❌ Dekripsi gagal: %s\n", cudaGetErrorString(status));
        return 1;
    }
    
    return 0;
}