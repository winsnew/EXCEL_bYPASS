#include <stdio.h>
#include <string.h>
#include <cuda_runtime.h>

__constant__ unsigned char target_hash[16] = {
    0xDA, 0xED, 0xEE, 0xE0, 0xA2, 0x13, 0xB1, 0x86, 
    0x1F, 0xFC, 0x4B, 0x82, 0x34, 0x6B, 0xB0, 0x6D
};

// RC4 
__device__ void rc4_encrypt(const unsigned char* key, int key_len, 
                           const unsigned char* plaintext, int plaintext_len,
                           unsigned char* ciphertext) {
    unsigned char S[256];
    int i, j = 0;
    
    // Initialize S-box
    for (i = 0; i < 256; i++)
        S[i] = i;
    
    // Key scheduling
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    
    // Encryption
    i = j = 0;
    for (int k = 0; k < plaintext_len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        
        int t = (S[i] + S[j]) % 256;
        ciphertext[k] = plaintext[k] ^ S[t];
    }
}

__device__ int compare_hash(const unsigned char* hash1, const unsigned char* hash2, int len) {
    for (int i = 0; i < len; i++) {
        if (hash1[i] != hash2[i])
            return 0;
    }
    return 1;
}

__device__ void generate_password(char* password, int max_len, unsigned int seed) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int charset_size = sizeof(charset) - 1;
    
    int len = 4 + (seed % 5);
    
    for (int i = 0; i < len && i < max_len - 1; i++) {
        password[i] = charset[(seed + i * 7919) % charset_size];
    }
    password[len < max_len ? len : max_len - 1] = '\0';
}

__device__ unsigned long long int attempt_count = 0;

// Kernel 
__global__ void brute_force_kernel(unsigned char* found, char* found_password, 
                                  int* password_len, unsigned long long int* attempts) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    char password[16];
    unsigned char encrypted[16];
    unsigned char plaintext[16] = {0}; 
    
    generate_password(password, 16, idx);
    
    atomicAdd(attempts, 1);
    
    rc4_encrypt((unsigned char*)password, strlen(password), 
                plaintext, 16, encrypted);
    
    if (compare_hash(encrypted, target_hash, 16)) {
        *found = 1;
        int len = strlen(password);
        *password_len = len;
        for (int i = 0; i < len; i++) {
            found_password[i] = password[i];
        }
        found_password[len] = '\0';
    }
}

int main() {
    printf("Starting CUDA Brute Force for Office 2003 Hash\n");
    printf("Target Hash: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X", target_hash[i]);
    }
    printf("\n");
    
    unsigned char* d_found;
    char* d_found_password;
    int* d_password_len;
    unsigned long long int* d_attempts;
    
    cudaMalloc(&d_found, sizeof(unsigned char));
    cudaMalloc(&d_found_password, 16 * sizeof(char));
    cudaMalloc(&d_password_len, sizeof(int));
    cudaMalloc(&d_attempts, sizeof(unsigned long long int));
    
    unsigned char h_found = 0;
    char h_found_password[16] = {0};
    int h_password_len = 0;
    unsigned long long int h_attempts = 0;
    
    cudaMemcpy(d_found, &h_found, sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_found_password, h_found_password, 16 * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_password_len, &h_password_len, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_attempts, &h_attempts, sizeof(unsigned long long int), cudaMemcpyHostToDevice);
    
    int blocks = 256;
    int threads_per_block = 256;
    int total_threads = blocks * threads_per_block;
    
    printf("Launching kernel with %d threads\n", total_threads);
    
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);
    
    brute_force_kernel<<<blocks, threads_per_block>>>(d_found, d_found_password, d_password_len, d_attempts);
    cudaDeviceSynchronize();
    
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);
    
    cudaMemcpy(&h_found, d_found, sizeof(unsigned char), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_found_password, d_found_password, 16 * sizeof(char), cudaMemcpyDeviceToHost);
    cudaMemcpy(&h_password_len, d_password_len, sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(&h_attempts, d_attempts, sizeof(unsigned long long int), cudaMemcpyDeviceToHost);
    
    float seconds = milliseconds / 1000.0f;
    float attempts_per_second = (seconds > 0) ? (h_attempts / seconds) : 0;
    
    printf("\n=== RESULTS ===\n");
    printf("Time elapsed: %.3f seconds\n", seconds);
    printf("Total attempts: %llu\n", h_attempts);
    printf("Speed: %.2f attempts/second\n", attempts_per_second);
    
    if (h_found) {
        printf("\n*** PASSWORD FOUND! ***\n");
        printf("Password: %s\n", h_found_password);
        printf("Length: %d\n", h_password_len);
    } else {
        printf("\nPassword not found in this attempt.\n");
        printf("Try increasing the number of threads.\n");
    }
    
    // Cleanup
    cudaFree(d_found);
    cudaFree(d_found_password);
    cudaFree(d_password_len);
    cudaFree(d_attempts);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    
    return 0;
}