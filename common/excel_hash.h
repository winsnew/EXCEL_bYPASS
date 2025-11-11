#ifndef EXCEL_HASH_H
#define EXCEL_HASH_H

#include <cstdint>
#include <string>
#include <vector>

class ExcelHash {
public:
    static uint16_t computeExcelHash(const std::string& password) {
        uint16_t hash = 0;
        for (char c : password) {
            hash = ((hash >> 14) & 0x01) | ((hash << 1) & 0x7FFF);
            hash ^= c;
        }
        hash = ((hash >> 14) & 0x01) | ((hash << 1) & 0x7FFF);
        hash ^= password.length();
        hash ^= 0xCE4B;
        return hash;
    }

    static void simpleDecrypt(std::vector<char>& buffer, const std::string& password) {
        if (password.empty()) return;
        
        size_t passLen = password.length();
        for (size_t i = 0; i < buffer.size(); i++) {
            buffer[i] ^= password[i % passLen];
        }
    }

    static bool hasExcelSignature(const std::vector<char>& buffer) {
        if (buffer.size() < 8) return false;
        return (buffer[0] == 0xD0 && buffer[1] == 0xCF &&
                buffer[2] == 0x11 && buffer[3] == 0xE0 &&
                buffer[4] == 0xA1 && buffer[5] == 0xB1 &&
                buffer[6] == 0x1A && buffer[7] == 0xE1);
    }
};

#endif