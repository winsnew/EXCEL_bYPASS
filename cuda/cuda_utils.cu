#include "cuda_utils.cuh"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <vector>

__global__ void rc4_init_kernel(RC4State* state, const char* key, size_t key_length) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    
    if (idx == 0) {
        // Inisialisasi state S
        for (int i = 0; i < 256; i++) {
            state->S[i] = i;
        }
        
        // Key-scheduling algorithm (KSA)
        uint8_t j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + state->S[i] + key[i % key_length]) % 256;
            // Swap S[i] dan S[j]
            uint8_t temp = state->S[i];
            state->S[i] = state->S[j];
            state->S[j] = temp;
        }
        
        state->i = 0;
        state->j = 0;
    }
}

__global__ void rc4_process_kernel(RC4State* state, uint8_t* data, size_t data_size) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    int stride = blockDim.x * gridDim.x;
    
    __shared__ RC4State local_state;
    if (threadIdx.x == 0) {
        local_state = *state;
    }
    __syncthreads();
    
    for (int pos = idx; pos < data_size; pos += stride) {
        local_state.i = (local_state.i + 1) % 256;
        local_state.j = (local_state.j + local_state.S[local_state.i]) % 256;
        
        uint8_t temp = local_state.S[local_state.i];
        local_state.S[local_state.i] = local_state.S[local_state.j];
        local_state.S[local_state.j] = temp;
        
        uint8_t k = local_state.S[(local_state.S[local_state.i] + local_state.S[local_state.j]) % 256];
        
        data[pos] ^= k;
    }
    
    __syncthreads();
    
    if (threadIdx.x == 0) {
        *state = local_state;
    }
}

__global__ void rc4_encrypt_kernel(uint8_t* data, size_t data_size, const char* key, size_t key_length) {
    RC4State state;
    
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        for (int i = 0; i < 256; i++) {
            state.S[i] = i;
        }
        
        uint8_t j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + state.S[i] + key[i % key_length]) % 256;
            uint8_t temp = state.S[i];
            state.S[i] = state.S[j];
            state.S[j] = temp;
        }
        state.i = 0;
        state.j = 0;
    }
    __syncthreads();
    
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    int stride = blockDim.x * gridDim.x;
    
    __shared__ RC4State local_state;
    if (threadIdx.x == 0) {
        local_state = state;
    }
    __syncthreads();
    
    for (int pos = idx; pos < data_size; pos += stride) {
        local_state.i = (local_state.i + 1) % 256;
        local_state.j = (local_state.j + local_state.S[local_state.i]) % 256;
        
        uint8_t temp = local_state.S[local_state.i];
        local_state.S[local_state.i] = local_state.S[local_state.j];
        local_state.S[local_state.j] = temp;
        
        uint8_t k = local_state.S[(local_state.S[local_state.i] + local_state.S[local_state.j]) % 256];
        data[pos] ^= k;
    }
}

__global__ void rc4_decrypt_kernel(uint8_t* data, size_t data_size, const char* key, size_t key_length) {
    RC4State state;
    
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        for (int i = 0; i < 256; i++) {
            state.S[i] = i;
        }
        
        uint8_t j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + state.S[i] + key[i % key_length]) % 256;
            uint8_t temp = state.S[i];
            state.S[i] = state.S[j];
            state.S[j] = temp;
        }
        state.i = 0;
        state.j = 0;
    }
    __syncthreads();
    
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    int stride = blockDim.x * gridDim.x;
    
    __shared__ RC4State local_state;
    if (threadIdx.x == 0) {
        local_state = state;
    }
    __syncthreads();
    
    for (int pos = idx; pos < data_size; pos += stride) {
        local_state.i = (local_state.i + 1) % 256;
        local_state.j = (local_state.j + local_state.S[local_state.i]) % 256;
        
        uint8_t temp = local_state.S[local_state.i];
        local_state.S[local_state.i] = local_state.S[local_state.j];
        local_state.S[local_state.j] = temp;
        
        uint8_t k = local_state.S[(local_state.S[local_state.i] + local_state.S[local_state.j]) % 256];
        data[pos] ^= k;
    }
}

cudaError_t read_file_to_gpu(const char* filename, uint8_t** d_data, size_t* file_size) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return cudaErrorFileNotFound;
    }
    
    *file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> host_data(*file_size);
    file.read(reinterpret_cast<char*>(host_data.data()), *file_size);
    file.close();
    
    cudaError_t cudaStatus = cudaMalloc(d_data, *file_size);
    if (cudaStatus != cudaSuccess) {
        return cudaStatus;
    }
    
    cudaStatus = cudaMemcpy(*d_data, host_data.data(), *file_size, cudaMemcpyHostToDevice);
    return cudaStatus;
}

cudaError_t write_file_from_gpu(const char* filename, const uint8_t* d_data, size_t file_size) {
    std::vector<uint8_t> host_data(file_size);
    
    cudaError_t cudaStatus = cudaMemcpy(host_data.data(), d_data, file_size, cudaMemcpyDeviceToHost);
    if (cudaStatus != cudaSuccess) {
        return cudaStatus;
    }
    
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return cudaErrorFileNotFound;
    }
    
    file.write(reinterpret_cast<const char*>(host_data.data()), file_size);
    file.close();
    
    return cudaSuccess;
}

bool is_excel_file(const uint8_t* data, size_t size) {
    if (size < 8) return false;
    
    uint8_t excel_signature[8] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    
    for (int i = 0; i < 8; i++) {
        if (data[i] != excel_signature[i]) {
            return false;
        }
    }
    return true;
}

cudaError_t rc4_encrypt_excel_file(const char* input_file, const char* output_file, const char* key) {
    uint8_t* d_data = nullptr;
    size_t file_size;
    
    cudaError_t cudaStatus = read_file_to_gpu(input_file, &d_data, &file_size);
    if (cudaStatus != cudaSuccess) {
        return cudaStatus;
    }
    
    std::vector<uint8_t> header(8);
    cudaMemcpy(header.data(), d_data, 8, cudaMemcpyDeviceToHost);
    
    size_t key_length = strlen(key);
    char* d_key = nullptr;
    
    cudaStatus = cudaMalloc(&d_key, key_length);
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        return cudaStatus;
    }
    cudaStatus = cudaMemcpy(d_key, key, key_length, cudaMemcpyHostToDevice);
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_key);
        return cudaStatus;
    }
    
    // CUDA kernel
    int blockSize = 256;
    int numBlocks = (file_size + blockSize - 1) / blockSize;
    
    rc4_encrypt_kernel<<<numBlocks, blockSize>>>(d_data, file_size, d_key, key_length);
    
    cudaStatus = cudaGetLastError();
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_key);
        return cudaStatus;
    }
    
    cudaStatus = cudaDeviceSynchronize();
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_key);
        return cudaStatus;
    }
    
    cudaStatus = write_file_from_gpu(output_file, d_data, file_size);
    
    // Cleanup
    cudaFree(d_data);
    cudaFree(d_key);
    
    return cudaStatus;
}

cudaError_t rc4_decrypt_excel_file(const char* input_file, const char* output_file, const char* key) {
    uint8_t* d_data = nullptr;
    size_t file_size;
    
    cudaError_t cudaStatus = read_file_to_gpu(input_file, &d_data, &file_size);
    if (cudaStatus != cudaSuccess) {
        return cudaStatus;
    }
    
    
    size_t key_length = strlen(key);
    char* d_key = nullptr;
    
    cudaStatus = cudaMalloc(&d_key, key_length);
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        return cudaStatus;
    }
    cudaStatus = cudaMemcpy(d_key, key, key_length, cudaMemcpyHostToDevice);
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_key);
        return cudaStatus;
    }
    
    int blockSize = 256;
    int numBlocks = (file_size + blockSize - 1) / blockSize;
    
    rc4_decrypt_kernel<<<numBlocks, blockSize>>>(d_data, file_size, d_key, key_length);
    
    cudaStatus = cudaGetLastError();
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_key);
        return cudaStatus;
    }
    
    cudaStatus = cudaDeviceSynchronize();
    if (cudaStatus != cudaSuccess) {
        cudaFree(d_data);
        cudaFree(d_key);
        return cudaStatus;
    }
    
    cudaStatus = write_file_from_gpu(output_file, d_data, file_size);
    
    // Cleanup
    cudaFree(d_data);
    cudaFree(d_key);
    
    return cudaStatus;
}

// testing
void test_excel_encryption() {
    const char* input_file = "test.xls";
    const char* encrypted_file = "test_encrypted.xls";
    const char* decrypted_file = "test_decrypted.xls";
    const char* key = "MySecretKey123";
    
    printf("Testing Excel RC4 Encryption...\n");
    
    cudaError_t status = rc4_encrypt_excel_file(input_file, encrypted_file, key);
    if (status == cudaSuccess) {
        printf("Encryption successful!\n");
    } else {
        printf("Encryption failed: %s\n", cudaGetErrorString(status));
        return;
    }
    
    status = rc4_decrypt_excel_file(encrypted_file, decrypted_file, key);
    if (status == cudaSuccess) {
        printf("Decryption successful!\n");
    } else {
        printf("Decryption failed: %s\n", cudaGetErrorString(status));
    }
}