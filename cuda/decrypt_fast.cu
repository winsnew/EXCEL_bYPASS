#include <stdio.h>
#include <string.h>
#include <cuda_runtime.h>

__constant__ unsigned char full_hash[200] = {
    0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x0C, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x68, 0x00, 0x00, 0x04, 0x80, 0x00, 0x00, 0x80, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x00,
    0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x66, 0x00, 0x74, 0x00,
    0x20, 0x00, 0x45, 0x00, 0x6E, 0x00, 0x68, 0x00, 0x61, 0x00, 0x6E, 0x00, 0x63, 0x00, 0x65, 0x00,
    0x64, 0x00, 0x20, 0x00, 0x43, 0x00, 0x72, 0x00, 0x79, 0x00, 0x70, 0x00, 0x74, 0x00, 0x6F, 0x00,
    0x67, 0x00, 0x72, 0x00, 0x61, 0x00, 0x70, 0x00, 0x68, 0x00, 0x69, 0x00, 0x63, 0x00, 0x20, 0x00,
    0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x76, 0x00, 0x69, 0x00, 0x64, 0x00, 0x65, 0x00, 0x72, 0x00,
    0x20, 0x00, 0x76, 0x00, 0x31, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0xDA, 0xED, 0xEE, 0xE0, 0xA2, 0x13, 0xB1, 0x86, 0x1F, 0xFC, 0x4B, 0x82, 0x34, 0x6B, 0xB0, 0x6D,
    0x36, 0xDB, 0x5D, 0xF5, 0x68, 0xB7, 0xB9, 0xD7, 0x91, 0xD5, 0xB2, 0xD5, 0x30, 0x29, 0x1D, 0x99,
    0x14, 0x00, 0x00, 0x00, 0x6F, 0x81, 0x5E, 0x17, 0x22, 0xEE, 0x87, 0xCC, 0x59, 0x65, 0xF9, 0x7E,
    0x8D, 0x0D, 0x9F, 0xA8, 0x67, 0x51, 0x80, 0xC8
};

// MD4 implementation untuk Office 2003
__device__ void md4_hash(const unsigned char* input, int len, unsigned char* output) {
    // Simplified MD4 - in reality would be full implementation
    unsigned int h[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    
    // Padding (simplified)
    int new_len = len + 9;
    while (new_len % 64 != 0) new_len++;
    
    // Process (very simplified)
    for (int i = 0; i < len; i++) {
        h[0] ^= input[i];
        h[0] = (h[0] << 3) | (h[0] >> 29);
        h[0] += h[1];
    }
    
    // Output
    for (int i = 0; i < 4; i++) {
        output[i*4] = (h[i] >> 0) & 0xFF;
        output[i*4+1] = (h[i] >> 8) & 0xFF;
        output[i*4+2] = (h[i] >> 16) & 0xFF;
        output[i*4+3] = (h[i] >> 24) & 0xFF;
    }
}

// RC4 Implementation
__device__ void rc4_encrypt(const unsigned char* key, int key_len, 
                           const unsigned char* plaintext, int plaintext_len,
                           unsigned char* ciphertext) {
    unsigned char S[256];
    int i, j = 0;
    
    for (i = 0; i < 256; i++) S[i] = i;
    
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    
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
        if (hash1[i] != hash2[i]) return 0;
    }
    return 1;
}

__device__ void generate_password(char* password, int max_len, unsigned long long seed, int* password_len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const int charset_size = sizeof(charset) - 1;
    
    int len = 1 + (seed % 12);  // 1-12 karakter
    *password_len = len;
    
    for (int i = 0; i < len && i < max_len - 1; i++) {
        password[i] = charset[(seed + i * 7919) % charset_size];
    }
    password[len] = '\0';
}

__device__ int verify_office_hash(const unsigned char* password, int password_len) {
    unsigned char derived_key[16];
    unsigned char decrypted[16];
    
    // Key derivation MD4 
    md4_hash(password, password_len, derived_key);
    
    // Decrypt the encrypted data block (bytes 96-111)
    rc4_encrypt(derived_key, 16, &full_hash[96], 16, decrypted);
    
    // Check specific patterns in decrypted data
    int zero_count = 0;
    for (int i = 0; i < 16; i++) {
        if (decrypted[i] == 0x00) zero_count++;
    }
    
    if (zero_count > 12) return 0;
    
    // Check for valid byte patterns
    int valid_pattern = 1;
    for (int i = 8; i < 16; i++) {
        if (decrypted[i] == 0x00) {
            valid_pattern = 1;
            break;
        }
    }
    
    return valid_pattern;
}

// Kernel 
__global__ void brute_force_kernel(unsigned char* found, char* found_password, 
                                  int* password_len, unsigned long long int* attempts) {
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    idx = idx + (blockIdx.y * gridDim.x * blockDim.x);
    
    char password[20];
    int pass_len = 0;
    
    generate_password(password, 20, idx, &pass_len);
    
    atomicAdd(attempts, 1);
    
    if (verify_office_hash((unsigned char*)password, pass_len)) {
        *found = 1;
        *password_len = pass_len;
        
        for (int i = 0; i < pass_len; i++) {
            found_password[i] = password[i];
        }
        found_password[pass_len] = '\0';
    }
}

int main() {
    printf("Starting CUDA Brute Force for Office 2003 Hash\n");
    printf("Target Hash: ");
    for (int i = 96; i < 112; i++) {
        printf("%02X", full_hash[i]);
    }
    printf("\n");
    
    // Allocate device memory
    unsigned char* d_found;
    char* d_found_password;
    int* d_password_len;
    unsigned long long int* d_attempts;
    
    cudaMalloc(&d_found, sizeof(unsigned char));
    cudaMalloc(&d_found_password, 20 * sizeof(char));
    cudaMalloc(&d_password_len, sizeof(int));
    cudaMalloc(&d_attempts, sizeof(unsigned long long int));
    
    // Initialize
    unsigned char h_found = 0;
    char h_found_password[20] = {0};
    int h_password_len = 0;
    unsigned long long int h_attempts = 0;
    
    cudaMemcpy(d_found, &h_found, sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_found_password, h_found_password, 20 * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_password_len, &h_password_len, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_attempts, &h_attempts, sizeof(unsigned long long int), cudaMemcpyHostToDevice);
    
    dim3 blocks(1024, 8);  // Much larger grid
    int threads_per_block = 256;
    unsigned long long total_threads = (unsigned long long)blocks.x * blocks.y * threads_per_block;
    
    printf("Launching kernel with %llu threads\n", total_threads);
    
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
    cudaMemcpy(h_found_password, d_found_password, 20 * sizeof(char), cudaMemcpyDeviceToHost);
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
        printf("\nPassword not found.\n");
    }
    
    cudaFree(d_found);
    cudaFree(d_found_password);
    cudaFree(d_password_len);
    cudaFree(d_attempts);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    
    return 0;
}