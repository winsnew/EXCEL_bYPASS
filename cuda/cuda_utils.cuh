#ifndef CUDA_UTILS_CUH
#define CUDA_UTILS_CUH

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct {
    uint8_t signature[8];        
    uint16_t unused[12];
    uint16_t sector_size;
    uint16_t mini_sector_size;
    uint8_t unused2[10];
    uint32_t total_sectors;
    uint32_t directory_sector_start;
    uint8_t unused3[4];
    uint32_t standard_stream_min_size;
    uint32_t directory_sector;
    uint8_t unused4[76];
} XlsHeader;
#pragma pack(pop)

// RC4 state
typedef struct {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} RC4State;

__global__ void rc4_encrypt_kernel(uint8_t* data, size_t data_size, const char* key, size_t key_length);
__global__ void rc4_decrypt_kernel(uint8_t* data, size_t data_size, const char* key, size_t key_length);
__global__ void rc4_init_kernel(RC4State* state, const char* key, size_t key_length);
__global__ void rc4_process_kernel(RC4State* state, uint8_t* data, size_t data_size);

cudaError_t rc4_encrypt_excel_file(const char* input_file, const char* output_file, const char* key);
cudaError_t rc4_decrypt_excel_file(const char* input_file, const char* output_file, const char* key);

// Utility functions
cudaError_t read_file_to_gpu(const char* filename, uint8_t** d_data, size_t* file_size);
cudaError_t write_file_from_gpu(const char* filename, const uint8_t* d_data, size_t file_size);
bool is_excel_file(const uint8_t* data, size_t size);

#endif // CUDA_UTILS_CUH