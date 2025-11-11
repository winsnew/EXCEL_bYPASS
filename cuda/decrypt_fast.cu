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

// MD4 implementation
__device__ void md4_hash(const unsigned char* input, int len, unsigned char* output) {
    unsigned int h[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    
    for (int i = 0; i < len; i++) {
        h[0] ^= input[i];
        h[0] = (h[0] << 3) | (h[0] >> 29);
        h[0] += h[1];
    }
    
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

__device__ const char* common_words[] = {
    "password", "admin", "123456", "qwerty", "letmein", "welcome", "monkey", "password1",
    "12345678", "123456789", "12345", "1234", "111111", "1234567", "dragon", "master",
    "hello", "freedom", "whatever", "computer", "internet", "sunshine", "princess", "starwars",
    "superman", "iloveyou", "trustno1", "batman", "passw0rd", "charley", "888888", "hello123",
    "secret", "abc123", "123123", "football", "baseball", "qwerty123", "admin123", "login",
    "pass", "access", "shadow", "demo", "test", "guest", "default", "user", "info", "root",
    "love", "money", "hello", "angel", "jordan", "letmein", "password123", "welcome123",
    "adminadmin", "pass123", "password12", "qwe123", "asdf", "zxcv", "qazwsx", "password2",
    "123qwe", "1qaz2wsx", "qwerty1", "password01", "p@ssw0rd", "P@ssw0rd", "P@SSW0RD",
    "hello1", "test123", "temp", "tmp", "backup", "123abc", "pass1", "changeme", "secret123",
    "mypassword", "mysecret", "private", "admin1", "admin1234", "administrator", "sa", "oracle",
    "mysql", "database", "web", "website", "server", "client", "network", "security", "access123",
    "winter", "spring", "summer", "autumn", "season", "weather", "nature", "flower", "animal",
    "tiger", "lion", "elephant", "bird", "fish", "dolphin", "whale", "shark", "eagle", "hawk",
    "apple", "banana", "orange", "grape", "strawberry", "pineapple", "watermelon", "chocolate",
    "coffee", "tea", "juice", "water", "milk", "bread", "butter", "cheese", "pizza", "hamburger",
    "pasta", "rice", "chicken", "beef", "pork", "fish", "salad", "soup", "cake", "cookie",
    "chocolate", "vanilla", "strawberry", "blueberry", "raspberry", "blackberry", "lemon", "lime",
    "car", "bike", "motor", "train", "plane", "boat", "ship", "bus", "taxi", "truck", "vehicle",
    "house", "home", "apartment", "room", "door", "window", "floor", "wall", "roof", "garden",
    "school", "college", "university", "student", "teacher", "professor", "class", "course",
    "work", "job", "office", "company", "business", "market", "store", "shop", "mall", "bank",
    "money", "cash", "credit", "debit", "card", "account", "payment", "price", "cost", "value",
    "friend", "family", "parent", "child", "brother", "sister", "mother", "father", "son", "daughter",
    "people", "person", "human", "man", "woman", "boy", "girl", "baby", "kid", "adult",
    "country", "city", "town", "village", "street", "road", "avenue", "park", "forest", "mountain",
    "river", "lake", "ocean", "sea", "island", "beach", "sand", "rock", "stone", "tree",
    "flower", "plant", "grass", "leaf", "wood", "forest", "jungle", "desert", "snow", "ice",
    "fire", "water", "earth", "air", "wind", "rain", "snow", "storm", "cloud", "sky",
    "sun", "moon", "star", "planet", "space", "universe", "galaxy", "light", "dark", "color",
    "red", "green", "blue", "yellow", "orange", "purple", "pink", "brown", "black", "white",
    "gray", "silver", "gold", "bronze", "metal", "iron", "steel", "copper", "gold", "silver",
    "time", "day", "night", "week", "month", "year", "hour", "minute", "second", "clock",
    "watch", "calendar", "date", "today", "tomorrow", "yesterday", "future", "past", "present",
    "life", "death", "health", "sickness", "medicine", "doctor", "hospital", "patient", "care",
    "love", "hate", "happy", "sad", "angry", "calm", "peace", "war", "fight", "victory",
    "game", "play", "sport", "ball", "team", "player", "coach", "win", "lose", "score",
    "music", "song", "dance", "art", "picture", "photo", "movie", "film", "video", "tv",
    "book", "page", "story", "novel", "poem", "letter", "word", "sentence", "language", "english",
    "number", "count", "math", "add", "subtract", "multiply", "divide", "equal", "plus", "minus",
    "size", "big", "small", "large", "little", "tall", "short", "long", "wide", "narrow",
    "weight", "heavy", "light", "strong", "weak", "hard", "soft", "smooth", "rough", "sharp",
    "temperature", "hot", "cold", "warm", "cool", "freeze", "melt", "boil", "steam", "ice",
    "electric", "power", "energy", "battery", "wire", "circuit", "switch", "button", "light", "bulb",
    "machine", "engine", "motor", "tool", "device", "gadget", "system", "program", "code", "data",
    "information", "knowledge", "wisdom", "idea", "thought", "mind", "brain", "memory", "learn", "study"
};

__device__ const int num_common_words = sizeof(common_words) / sizeof(common_words[0]);

__device__ void generate_password_bruteforce(char* password, int max_len, unsigned long long seed, int* password_len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    const int charset_size = sizeof(charset) - 1;
    
    int len = 1 + (seed % 12);
    *password_len = len;
    
    for (int i = 0; i < len && i < max_len - 1; i++) {
        password[i] = charset[(seed + i * 7919) % charset_size];
    }
    password[len] = '\0';
}

__device__ void generate_password_common_words(char* password, int max_len, unsigned long long seed, int* password_len) {
    int word_index = seed % num_common_words;
    const char* base_word = common_words[word_index];
    int base_len = 0;
    
    // Hitung panjang kata dasar
    while (base_word[base_len] != '\0' && base_len < max_len - 1) {
        base_len++;
    }
    
    for (int i = 0; i < base_len; i++) {
        password[i] = base_word[i];
    }
    
    int mutation_type = (seed >> 16) % 16; 
    
    int current_len = base_len;
    
    switch (mutation_type) {
        case 0: // Original word
            break;
        case 1: // Uppercase first letter
            if (current_len > 0 && password[0] >= 'a' && password[0] <= 'z') {
                password[0] = password[0] - 32;
            }
            break;
        case 2: // Uppercase all
            for (int i = 0; i < current_len; i++) {
                if (password[i] >= 'a' && password[i] <= 'z') {
                    password[i] = password[i] - 32;
                }
            }
            break;
        case 3: // Add number suffix (0-99)
            if (current_len + 2 < max_len) {
                int num = (seed >> 8) % 100;
                if (num < 10) {
                    password[current_len] = '0' + num;
                    current_len++;
                } else {
                    password[current_len] = '0' + (num / 10);
                    password[current_len + 1] = '0' + (num % 10);
                    current_len += 2;
                }
            }
            break;
        case 4: // Add number suffix (0-999)
            if (current_len + 3 < max_len) {
                int num = (seed >> 8) % 1000;
                if (num < 10) {
                    password[current_len] = '0' + num;
                    current_len++;
                } else if (num < 100) {
                    password[current_len] = '0' + (num / 10);
                    password[current_len + 1] = '0' + (num % 10);
                    current_len += 2;
                } else {
                    password[current_len] = '0' + (num / 100);
                    password[current_len + 1] = '0' + ((num / 10) % 10);
                    password[current_len + 2] = '0' + (num % 10);
                    current_len += 3;
                }
            }
            break;
        case 5: // Add special character prefix
            if (current_len + 1 < max_len) {
                const char specials[] = "!@#$%^&*";
                // Shift existing characters
                for (int i = current_len; i > 0; i--) {
                    password[i] = password[i - 1];
                }
                password[0] = specials[(seed >> 4) % 8];
                current_len++;
            }
            break;
        case 6: // Add special character suffix
            if (current_len + 1 < max_len) {
                const char specials[] = "!@#$%^&*";
                password[current_len] = specials[(seed >> 4) % 8];
                current_len++;
            }
            break;
        case 7: // Leet speak substitution
            for (int i = 0; i < current_len; i++) {
                switch (password[i]) {
                    case 'a': case 'A': password[i] = '4'; break;
                    case 'e': case 'E': password[i] = '3'; break;
                    case 'i': case 'I': password[i] = '1'; break;
                    case 'o': case 'O': password[i] = '0'; break;
                    case 's': case 'S': password[i] = '5'; break;
                    case 't': case 'T': password[i] = '7'; break;
                }
            }
            break;
        case 8: // Reverse word
            for (int i = 0; i < current_len / 2; i++) {
                char temp = password[i];
                password[i] = password[current_len - 1 - i];
                password[current_len - 1 - i] = temp;
            }
            break;
        case 9: // Duplicate word
            if (current_len * 2 < max_len) {
                for (int i = 0; i < current_len; i++) {
                    password[current_len + i] = password[i];
                }
                current_len *= 2;
            }
            break;
        case 10: // Capitalize each word (for multi-word)
            password[0] = (password[0] >= 'a' && password[0] <= 'z') ? password[0] - 32 : password[0];
            for (int i = 1; i < current_len; i++) {
                if (password[i - 1] == ' ' && password[i] >= 'a' && password[i] <= 'z') {
                    password[i] = password[i] - 32;
                }
            }
            break;
        case 11: // Add year (1990-2025)
            if (current_len + 4 < max_len) {
                int year = 1990 + ((seed >> 12) % 36);
                password[current_len] = '0' + (year / 1000);
                password[current_len + 1] = '0' + ((year / 100) % 10);
                password[current_len + 2] = '0' + ((year / 10) % 10);
                password[current_len + 3] = '0' + (year % 10);
                current_len += 4;
            }
            break;
        case 12: // Combine two words
            if (current_len < max_len / 2) {
                int second_index = (seed >> 20) % num_common_words;
                const char* second_word = common_words[second_index];
                int second_len = 0;
                while (second_word[second_len] != '\0' && current_len + second_len < max_len - 1) {
                    password[current_len] = second_word[second_len];
                    current_len++;
                    second_len++;
                }
            }
            break;
        case 13: // Replace vowels with numbers
            for (int i = 0; i < current_len; i++) {
                switch (password[i]) {
                    case 'a': case 'A': password[i] = '4'; break;
                    case 'e': case 'E': password[i] = '3'; break;
                    case 'i': case 'I': password[i] = '1'; break;
                    case 'o': case 'O': password[i] = '0'; break;
                    case 'u': case 'U': password[i] = '9'; break;
                }
            }
            break;
        case 14: // Add common suffix
            if (current_len + 3 < max_len) {
                const char* suffixes[] = {"123", "!@#", "000", "111", "abc", "xyz", "007", "2024"};
                int suffix_index = (seed >> 24) % 8;
                const char* suffix = suffixes[suffix_index];
                int suffix_len = 0;
                while (suffix[suffix_len] != '\0' && current_len < max_len - 1) {
                    password[current_len] = suffix[suffix_len];
                    current_len++;
                    suffix_len++;
                }
            }
            break;
        case 15: // Random case
            for (int i = 0; i < current_len; i++) {
                if (password[i] >= 'a' && password[i] <= 'z') {
                    if ((seed >> i) & 1) {
                        password[i] = password[i] - 32;
                    }
                } else if (password[i] >= 'A' && password[i] <= 'Z') {
                    if ((seed >> i) & 1) {
                        password[i] = password[i] + 32;
                    }
                }
            }
            break;
    }
    
    password[current_len] = '\0';
    *password_len = current_len;
}

__device__ int verify_office_hash(const unsigned char* password, int password_len) {
    unsigned char derived_key[16];
    unsigned char decrypted[16];
    
    md4_hash(password, password_len, derived_key);
    rc4_encrypt(derived_key, 16, &full_hash[96], 16, decrypted);
    
    int zero_count = 0;
    for (int i = 0; i < 16; i++) {
        if (decrypted[i] == 0x00) zero_count++;
    }
    
    if (zero_count > 12) return 0;
    
    int valid_pattern = 1;
    for (int i = 8; i < 16; i++) {
        if (decrypted[i] == 0x00) {
            valid_pattern = 1;
            break;
        }
    }
    
    return valid_pattern;
}

// Kernel dengan dual mode
__global__ void brute_force_kernel(unsigned char* found, char* found_password, 
                                  int* password_len, unsigned long long int* attempts,
                                  int use_common_words) {
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    idx = idx + (blockIdx.y * gridDim.x * blockDim.x);
    
    char password[32];
    int pass_len = 0;
    
    atomicAdd(attempts, 1);
    
    if (use_common_words) {
        generate_password_common_words(password, 32, idx, &pass_len);
    } else {
        generate_password_bruteforce(password, 32, idx, &pass_len);
    }
    
    if (verify_office_hash((unsigned char*)password, pass_len)) {
        *found = 1;
        *password_len = pass_len;
        
        for (int i = 0; i < pass_len; i++) {
            found_password[i] = password[i];
        }
        found_password[pass_len] = '\0';
    }
}

int main(int argc, char* argv[]) {
    printf("Starting CUDA Brute Force for Office 2003 Hash\n");
    printf("Target Hash: ");
    for (int i = 96; i < 112; i++) {
        printf("%02X", full_hash[i]);
    }
    printf("\n");
    
    // Mode selection
    int use_common_words = 1; // Default: use common words mode
    if (argc > 1) {
        if (strcmp(argv[1], "bruteforce") == 0) {
            use_common_words = 0;
            printf("Using BRUTE FORCE mode\n");
        } else {
            printf("Using COMMON WORDS mode (default)\n");
            printf("Usage: %s [bruteforce]  (default: common words)\n", argv[0]);
        }
    } else {
        printf("Using COMMON WORDS mode (default)\n");
        printf("Common words database: %d words\n", 150); // approx number of common words
    }
    
    // Allocate device memory
    unsigned char* d_found;
    char* d_found_password;
    int* d_password_len;
    unsigned long long int* d_attempts;
    
    cudaMalloc(&d_found, sizeof(unsigned char));
    cudaMalloc(&d_found_password, 32 * sizeof(char));
    cudaMalloc(&d_password_len, sizeof(int));
    cudaMalloc(&d_attempts, sizeof(unsigned long long int));
    
    // Initialize
    unsigned char h_found = 0;
    char h_found_password[32] = {0};
    int h_password_len = 0;
    unsigned long long int h_attempts = 0;
    
    cudaMemcpy(d_found, &h_found, sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_found_password, h_found_password, 32 * sizeof(char), cudaMemcpyHostToDevice);
    cudaMemcpy(d_password_len, &h_password_len, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_attempts, &h_attempts, sizeof(unsigned long long int), cudaMemcpyHostToDevice);
    
    // Configure grid size - lebih besar untuk coverage lebih baik
    dim3 blocks(1024, 16);
    int threads_per_block = 256;
    unsigned long long total_threads = (unsigned long long)blocks.x * blocks.y * threads_per_block;
    
    printf("Launching kernel with %llu threads\n", total_threads);
    printf("Mode: %s\n", use_common_words ? "COMMON WORDS + MUTATIONS" : "BRUTE FORCE");
    
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);
    
    // Launch kernel
    brute_force_kernel<<<blocks, threads_per_block>>>(d_found, d_found_password, d_password_len, 
                                                     d_attempts, use_common_words);
    cudaDeviceSynchronize();
    
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);
    
    cudaMemcpy(&h_found, d_found, sizeof(unsigned char), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_found_password, d_found_password, 32 * sizeof(char), cudaMemcpyDeviceToHost);
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
        printf("\nCoba buka file Excel dengan password ini!\n");
    } else {
        printf("\nPassword not found dalam percobaan ini.\n");
        printf("Rekomendasi:\n");
        printf("1. Coba mode berbeda: %s bruteforce\n", argv[0]);
        printf("2. Tingkatkan jumlah thread\n");
        printf("3. Coba dengan wordlist external\n");
    }
    
    // Cleanup
    cudaFree(d_found);
    cudaFree(d_found_password);
    cudaFree(d_password_len);
    cudaFree(d_attempts);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    
    return 0;
}