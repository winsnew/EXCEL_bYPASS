#include "common/hash_extractor.h"

void print_banner() {
    printf("=========================================\n");
    printf("     EXCEL HASH EXTRACTOR TOOL\n");
    printf("     For Password Protected .XLS Files\n");
    printf("=========================================\n");
}

void print_usage(const char *program_name) {
    printf("Usage: %s <excel_file.xls> [options]\n", program_name);
    printf("Options:\n");
    printf("  -o <output>   Save hash to file\n");
    printf("  -v            Verbose mode\n");
    printf("  -h            Show this help\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    const char *output_file = NULL;
    int verbose = 0;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    print_banner();
    printf("Processing: %s\n", filename);
    
    XLSFile *xls_file = read_xls_file(filename);
    if (!xls_file) {
        return 1;
    }
    
    printf("File size: %zu bytes\n", xls_file->size);
    
    if (extract_xls_hash(xls_file)) {
        printf("\n=== COMPLETE HASH OUTPUT ===\n");
        printf("Encryption detected: YES\n");
        printf("Hash length: %zu bytes\n", xls_file->hash_length);
        
        printf("Hash data (hex): ");
        for (size_t i = 0; i < xls_file->hash_length; i++) {
            printf("%02X", xls_file->hash_data[i]);
        }
        printf("\n");
        
        printf("Hash data (ASCII): ");
        for (size_t i = 0; i < xls_file->hash_length; i++) {
            if (xls_file->hash_data[i] >= 32 && xls_file->hash_data[i] <= 126) {
                printf("%c", xls_file->hash_data[i]);
            } else {
                printf(".");
            }
        }
        printf("\n");
        
        print_hash_info(xls_file);
        
        if (output_file) {
            save_hash_to_file(xls_file, output_file);
        }
        
        printf("\nHash extraction successful!\n");
        printf("You can now use cracking tools like:\n");
        printf("  john --format=office hash.txt\n");
        printf("  hashcat -m 9400 hash.txt wordlist.txt\n");
    } else {
        printf("\nFailed to extract hash\n");
        printf("Possible reasons:\n");
        printf("  - File not password protected\n");
        printf("  - Unsupported Excel version\n");
        printf("  - File corrupted\n");
    }
    
    free_xls_file(xls_file);
    return 0;
}