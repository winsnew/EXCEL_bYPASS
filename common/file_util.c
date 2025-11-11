#include "excel_hash.h"

ExcelFile* read_excel_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    ExcelFile *excel_file = malloc(sizeof(ExcelFile));
    excel_file->data = malloc(size);
    excel_file->size = size;
    excel_file->is_encrypted = 0;
    excel_file->encryption_type = 0;
    memset(excel_file->encryption_provider, 0, sizeof(excel_file->encryption_provider));
    
    fread(excel_file->data, 1, size, file);
    fclose(file);
    
    return excel_file;
}

void analyze_encryption(ExcelFile *file) {
    printf("\n=== EXCEL FILE ANALYSIS ===\n");
    printf("File size: %zu bytes\n", file->size);
    
    if (file->size >= 8 && 
        file->data[0] == 0xD0 && file->data[1] == 0xCF &&
        file->data[2] == 0x11 && file->data[3] == 0xE0) {
        printf("✓ Valid Excel file signature\n");
    } else {
        printf("✗ Invalid Excel file\n");
        return;
    }
    
    file->is_encrypted = detect_encryption_type(file);
    
    if (file->is_encrypted) {
        printf("ENCRYPTION DETECTED: %s\n", file->encryption_provider);
        printf("Encryption type: %d\n", file->encryption_type);
    } else {
        printf("No strong encryption detected\n");
    }
    
    const char *markers[] = {
        "Encrypted",
        "Encryption",
        "Password", 
        "StrongEncryption",
        "Microsoft Enhanced Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider",
        "EncryptedPackage",
        NULL
    };
    
    printf("\n--- Encryption Markers Found ---\n");
    int found_markers = 0;
    for (int i = 0; markers[i] != NULL; i++) {
        size_t marker_len = strlen(markers[i]);
        for (size_t pos = 0; pos < file->size - marker_len; pos++) {
            if (memcmp(file->data + pos, markers[i], marker_len) == 0) {
                printf("📍 %s at offset: 0x%08lX\n", markers[i], pos);
                found_markers++;
                break;
            }
        }
    }
    
    if (!found_markers) {
        printf("No explicit encryption markers found\n");
    }
}

int detect_encryption_type(ExcelFile *file) {
    const char *enhanced_crypto = "Microsoft Enhanced Cryptographic Provider";
    const char *strong_crypto = "Microsoft Strong Cryptographic Provider";
    const char *encrypted_package = "EncryptedPackage";
    
    
    for (size_t i = 0; i < file->size - 50; i++) {
        if (memcmp(file->data + i, enhanced_crypto, strlen(enhanced_crypto)) == 0) {
            strcpy(file->encryption_provider, enhanced_crypto);
            file->encryption_type = 2; 
            return 1;
        }
        if (memcmp(file->data + i, strong_crypto, strlen(strong_crypto)) == 0) {
            strcpy(file->encryption_provider, strong_crypto);
            file->encryption_type = 1; 
            return 1;
        }
        if (memcmp(file->data + i, encrypted_package, strlen(encrypted_package)) == 0) {
            strcpy(file->encryption_provider, "Encrypted Package");
            file->encryption_type = 3; 
            return 1;
        }
    }
    
    return 0;
}