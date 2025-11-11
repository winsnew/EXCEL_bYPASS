#include "hash_extractor.h"

XLSFile* read_xls_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    XLSFile *xls_file = malloc(sizeof(XLSFile));
    xls_file->data = malloc(size);
    xls_file->size = size;
    xls_file->is_encrypted = 0;
    xls_file->hash_length = 0;
    memset(xls_file->salt, 0, sizeof(xls_file->salt));
    memset(xls_file->encrypted_verifier, 0, sizeof(xls_file->encrypted_verifier));
    memset(xls_file->encrypted_verifier_hash, 0, sizeof(xls_file->encrypted_verifier_hash));
    memset(xls_file->hash_data, 0, sizeof(xls_file->hash_data));
    
    size_t bytes_read = fread(xls_file->data, 1, size, file);
    fclose(file);
    
    if (bytes_read != size) {
        printf("Error reading file\n");
        free_xls_file(xls_file);
        return NULL;
    }
    
    return xls_file;
}

void free_xls_file(XLSFile *file) {
    if (file) {
        free(file->data);
        free(file);
    }
}

int find_encryption_header(XLSFile *file) {
    const uint8_t encryption_signature[] = {0xFE, 0xFF, 0xFF, 0xFF};
    const uint8_t encryption_header[] = "EncryptionInfo";
    
    for (size_t i = 0; i < file->size - 100; i++) {
        if (memcmp(file->data + i, encryption_header, 14) == 0) {
            printf("Found EncryptionInfo at offset: 0x%08lX\n", i);
            return i;
        }
        
        if (memcmp(file->data + i, encryption_signature, 4) == 0) {
            printf("Found encryption signature at offset: 0x%08lX\n", i);
            return i;
        }
    }
    
    return -1;
}

int extract_office_2003_hash(XLSFile *file) {
    printf("Trying Office 97-2003 format...\n");
    
    for (size_t i = 0; i < file->size - 50; i++) {
        if (file->data[i] == 0x2F && file->data[i+1] == 0x00) {
            printf("Found encryption record at offset: 0x%08lX\n", i);
            
            uint16_t rec_len = *(uint16_t*)(file->data + i + 2);
            if (rec_len > 0 && rec_len < 1000) {
                printf("Encryption record length: %d bytes\n", rec_len);
                
                size_t copy_len = (rec_len < MAX_HASH_LENGTH) ? rec_len : MAX_HASH_LENGTH - 1;
                
                file->hash_length = copy_len;
                memcpy(file->hash_data, file->data + i + 4, copy_len);
                file->is_encrypted = 1;
                return 1;
            }
        }
    }
    
    return 0;
}

int extract_office_2007plus_hash(XLSFile *file) {
    printf("Trying Office 2007+ format...\n");
    const uint8_t encryption_info[] = {0x04, 0x00, 0x04, 0x00};
    const uint8_t verifier_prefix[] = "Microsoft Enhanced Cryptographic Provider";
    
    for (size_t i = 0; i < file->size - 200; i++) {
        if (memcmp(file->data + i, encryption_info, 4) == 0) {
            printf("Found encryption info at offset: 0x%08lX\n", i);
            
            if (i + 20 < file->size) {
                memcpy(file->salt, file->data + i + 8, 16);
                printf("Salt extracted: ");
                for (int j = 0; j < 16; j++) {
                    printf("%02X", file->salt[j]);
                }
                printf("\n");
            }
            
            if (i + 100 < file->size) {
                memcpy(file->encrypted_verifier, file->data + i + 40, 16);
                memcpy(file->encrypted_verifier_hash, file->data + i + 56, 16);
                
                printf("Encrypted verifier: ");
                for (int j = 0; j < 16; j++) {
                    printf("%02X", file->encrypted_verifier[j]);
                }
                printf("\n");
                
                printf("Encrypted verifier hash: ");
                for (int j = 0; j < 16; j++) {
                    printf("%02X", file->encrypted_verifier_hash[j]);
                }
                printf("\n");
                
                file->is_encrypted = 1;
                
                snprintf((char*)file->hash_data, MAX_HASH_LENGTH,
                    "$office$*2007*20*%d*%d*",
                    file->encryption_type, 16);
                
                char *hash_ptr = (char*)file->hash_data + strlen((char*)file->hash_data);
                for (int j = 0; j < 16; j++) {
                    sprintf(hash_ptr, "%02X", file->salt[j]);
                    hash_ptr += 2;
                }
                sprintf(hash_ptr, "*");
                hash_ptr++;
                
                for (int j = 0; j < 16; j++) {
                    sprintf(hash_ptr, "%02X", file->encrypted_verifier[j]);
                    hash_ptr += 2;
                }
                sprintf(hash_ptr, "*");
                hash_ptr++;
                
                for (int j = 0; j < 16; j++) {
                    sprintf(hash_ptr, "%02X", file->encrypted_verifier_hash[j]);
                    hash_ptr += 2;
                }
                
                file->hash_length = strlen((char*)file->hash_data);
                return 1;
            }
        }
        
        if (memcmp(file->data + i, verifier_prefix, 44) == 0) {
            printf("Found crypto provider at offset: 0x%08lX\n", i);
            file->is_encrypted = 1;
        }
    }
    
    return 0;
}

int extract_xls_hash(XLSFile *file) {
    printf("\n=== EXTRACTING EXCEL HASH ===\n");
    
    uint32_t signature = *(uint32_t*)file->data;
    if (signature != XLS_SIGNATURE) {
        printf("Error: Not a valid Excel file\n");
        return 0;
    }
    printf("✓ Valid Excel file signature\n");
    
    if (extract_office_2007plus_hash(file)) {
        printf("✓ Office 2007+ hash extracted successfully\n");
        return 1;
    }
    
    if (extract_office_2003_hash(file)) {
        printf("✓ Office 2003 hash extracted successfully\n");
        return 1;
    }
    
    int enc_offset = find_encryption_header(file);
    if (enc_offset != -1) {
        printf("✓ Encryption header found\n");
        file->is_encrypted = 1;
        
        // Ekstrak lebih banyak data untuk format lengkap
        size_t extract_size = (file->size - enc_offset > MAX_HASH_LENGTH) ? 
                             MAX_HASH_LENGTH : file->size - enc_offset;
        memcpy(file->hash_data, file->data + enc_offset, extract_size);
        file->hash_length = extract_size;
        return 1;
    }
    
    printf("✗ No encryption hash found\n");
    return 0;
}

void print_complete_hash(XLSFile *file) {
    if (!file->is_encrypted || file->hash_length == 0) {
        printf("No hash data available\n");
        return;
    }
    
    printf("\n=== COMPLETE HASH DATA ===\n");
    printf("Encryption detected: YES\n");
    printf("Hash length: %zu bytes\n", file->hash_length);
    
    printf("Hash data (hex): ");
    for (size_t i = 0; i < file->hash_length; i++) {
        printf("%02X", file->hash_data[i]);
    }
    printf("\n");
    
    printf("Hash data (ASCII): ");
    for (size_t i = 0; i < file->hash_length; i++) {
        if (file->hash_data[i] >= 32 && file->hash_data[i] <= 126) {
            printf("%c", file->hash_data[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

void print_hash_info(XLSFile *file) {
    if (!file->is_encrypted) {
        printf("File is not encrypted or hash not found\n");
        return;
    }
    
    printf("\n=== HASH INFORMATION ===\n");
    printf("Encryption detected: %s\n", file->is_encrypted ? "YES" : "NO");
    printf("Hash length: %zu bytes\n", file->hash_length);
    
    // Tampilkan preview singkat
    if (file->hash_length > 0) {
        printf("Hash data preview (hex): ");
        for (size_t i = 0; i < file->hash_length && i < 64; i++) {
            printf("%02X", file->hash_data[i]);
        }
        if (file->hash_length > 64) {
            printf("...");
        }
        printf("\n");
        
        printf("Hash data preview (ASCII): ");
        for (size_t i = 0; i < file->hash_length && i < 64; i++) {
            if (file->hash_data[i] >= 32 && file->hash_data[i] <= 126) {
                printf("%c", file->hash_data[i]);
            } else {
                printf(".");
            }
        }
        if (file->hash_length > 64) {
            printf("...");
        }
        printf("\n");
    }
    
    print_complete_hash(file);
    
    printf("\n=== FOR CRACKING TOOLS ===\n");
    if (file->hash_length < MAX_HASH_LENGTH && file->hash_length > 0) {
        printf("John/Hashcat format:\n");
        printf("%s\n", file->hash_data);
    }
}

void save_hash_to_file(XLSFile *file, const char *output_file) {
    if (!file->is_encrypted || file->hash_length == 0) {
        printf("No hash to save\n");
        return;
    }
    
    FILE *f = fopen(output_file, "w");
    if (!f) {
        printf("Error creating output file\n");
        return;
    }
    
    fprintf(f, "Encryption detected: YES\n");
    fprintf(f, "Hash length: %zu bytes\n", file->hash_length);
    
    fprintf(f, "Hash data (hex): ");
    for (size_t i = 0; i < file->hash_length; i++) {
        fprintf(f, "%02X", file->hash_data[i]);
    }
    fprintf(f, "\n");
    
    fprintf(f, "Hash data (ASCII): ");
    for (size_t i = 0; i < file->hash_length; i++) {
        if (file->hash_data[i] >= 32 && file->hash_data[i] <= 126) {
            fprintf(f, "%c", file->hash_data[i]);
        } else {
            fprintf(f, ".");
        }
    }
    fprintf(f, "\n");
    
    if (file->hash_length < MAX_HASH_LENGTH && strlen((char*)file->hash_data) > 0) {
        fprintf(f, "\nJohn/Hashcat format:\n");
        fprintf(f, "%s\n", file->hash_data);
    }
    
    fclose(f);
    
    printf("Complete hash data saved to: %s\n", output_file);
}