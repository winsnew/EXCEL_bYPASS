#ifndef EXCEL_HASH_H
#define EXCEL_HASH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define MAX_PASSWORD_LEN 256
#define BUFFER_SIZE 1048576  // 1MB

typedef struct {
    uint8_t *data;
    size_t size;
    int is_encrypted;
    int encryption_type;
    char encryption_provider[128];
} ExcelFile;

// Structure untuk brute force context
typedef struct {
    char **passwords;
    size_t count;
    size_t current_index;
    int found;
    char password[MAX_PASSWORD_LEN];
    clock_t start_time;
} BruteForceContext;

// Function prototypes
ExcelFile* read_excel_file(const char *filename);
void analyze_encryption(ExcelFile *file);
int detect_encryption_type(ExcelFile *file);
void brute_force_excel(ExcelFile *file, const char *wordlist_file);
void dictionary_attack(ExcelFile *file, const char *dict_file);
void mask_attack(ExcelFile *file, const char *mask);
void free_excel_file(ExcelFile *file);

// Modern Excel encryption functions
int try_decrypt_modern(ExcelFile *file, const char *password);
int extract_encryption_info(ExcelFile *file);
void generate_wordlist_combinations();

#endif