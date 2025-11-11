#ifndef HASH_EXTRACTOR_H
#define HASH_EXTRACTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define XLS_SIGNATURE 0xE011CFD0  // D0 CF 11 E0
#define MAX_HASH_LENGTH 2048  

typedef struct {
    uint8_t *data;
    size_t size;
    int is_encrypted;
    uint16_t encryption_type;
    uint8_t salt[16];
    uint8_t encrypted_verifier[16];
    uint8_t encrypted_verifier_hash[16];
    uint8_t hash_data[MAX_HASH_LENGTH];
    size_t hash_length;
    char encryption_format[50];  
} XLSFile;

// Function prototypes
XLSFile* read_xls_file(const char *filename);
void free_xls_file(XLSFile *file);
int extract_xls_hash(XLSFile *file);
void print_hash_info(XLSFile *file);
int find_encryption_header(XLSFile *file);
int extract_office_2003_hash(XLSFile *file);
int extract_office_2007plus_hash(XLSFile *file);
void save_hash_to_file(XLSFile *file, const char *output_file);
void print_complete_hash(XLSFile *file); 
const char* get_encryption_type_name(XLSFile *file);  

#endif