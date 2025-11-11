#include "excel_hash.h"

void brute_force_excel(ExcelFile *file, const char *wordlist_file) {
    printf("\n=== BRUTE FORCE ATTACK ===\n");
    
    if (!file->is_encrypted) {
        printf("File is not encrypted. No need for brute force.\n");
        return;
    }
    
    FILE *wordlist = fopen(wordlist_file, "r");
    if (!wordlist) {
        printf("Error: Cannot open wordlist file %s\n", wordlist_file);
        return;
    }
    
    char password[MAX_PASSWORD_LEN];
    int attempts = 0;
    clock_t start_time = clock();
    
    printf("Starting brute force attack...\n");
    
    while (fgets(password, sizeof(password), wordlist)) {
        password[strcspn(password, "\n")] = 0;
        attempts++;
        
        if (attempts % 1000 == 0) {
            printf("Attempts: %d, Current: '%s'\n", attempts, password);
        }
        
        if (try_decrypt_modern(file, password)) {
            clock_t end_time = clock();
            double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
            
            printf("\nPASSWORD FOUND!\n");
            printf("Password: '%s'\n", password);
            printf("Attempts: %d\n", attempts);
            printf("Time: %.2f seconds\n", elapsed);
            
            fclose(wordlist);
            return;
        }
    }
    
    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    printf("\nPassword not found\n");
    printf("Total attempts: %d\n", attempts);
    printf("Time: %.2f seconds\n", elapsed);
    
    fclose(wordlist);
}

void dictionary_attack(ExcelFile *file, const char *dict_file) {
    printf("\n=== DICTIONARY ATTACK ===\n");
    
    const char *common_passwords[] = {
        "", "password", "123456", "12345678", "1234", "12345", 
        "excel", "microsoft", "office", "admin", "user", "secret",
        "pass", "0000", "1111", "9999", "temp", "test", "demo",
        "1234567890", "qwerty", "abc123", "letmein", "welcome",
        NULL
    };
    
    printf("Trying common passwords...\n");
    
    for (int i = 0; common_passwords[i] != NULL; i++) {
        printf("Trying: '%s'\n", common_passwords[i]);
        
        if (try_decrypt_modern(file, common_passwords[i])) {
            printf("\n PASSWORD FOUND: '%s'\n", common_passwords[i]);
            return;
        }
    }
    
    brute_force_excel(file, dict_file);
}

int try_decrypt_modern(ExcelFile *file, const char *password) {
    // decrypt placeholder
    // Implementasi with library 
    
    printf("  [DEBUG] Trying password: '%s'\n", password);
    
    // if (strcmp(password, "password123") == 0) {
    //     return 1;
    // }
    
    return 0;
}