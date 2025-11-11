#include "common/excel_hash.h"

void print_banner() {
    printf("=============================================\n");
    printf("       EXCEL PASSWORD RECOVERY TOOL\n");
    printf("       Modern Encryption Support\n");
    printf("=============================================\n");
}

void print_usage(const char *program_name) {
    printf("Usage: %s <excel_file> [options]\n", program_name);
    printf("Options:\n");
    printf("  -w <wordlist>    Use custom wordlist file\n");
    printf("  -d <dictionary>  Use dictionary attack\n");
    printf("  -a               Analyze file only\n");
    printf("  -h               Show this help\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *filename = argv[1];
    const char *wordlist = "wordlist.txt";  
    int analyze_only = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            wordlist = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0) {
            analyze_only = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    print_banner();
    printf("File: %s\n", filename);
    
    ExcelFile *excel_file = read_excel_file(filename);
    if (!excel_file) {
        return 1;
    }
    
    analyze_encryption(excel_file);
    
    if (analyze_only) {
        free_excel_file(excel_file);
        return 0;
    }
    
    if (excel_file->is_encrypted) {
        dictionary_attack(excel_file, wordlist);
    } else {
        printf("\nFile is not encrypted. No password recovery needed.\n");
    }
    
    free_excel_file(excel_file);
    return 0;
}

void free_excel_file(ExcelFile *file) {
    if (file) {
        free(file->data);
        free(file);
    }
}