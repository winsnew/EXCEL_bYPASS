#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <cstdint>

class FileUtils {
public:
    static std::vector<char> readFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + filename);
        }

        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<char> buffer(size);
        file.read(buffer.data(), size);
        return buffer;
    }

    static bool writeFile(const std::string& filename, const std::vector<char>& data) {
        std::ofstream file(filename, std::ios::binary);
        if (!file) return false;
        
        file.write(data.data(), data.size());
        return true;
    }

    static bool isExcelFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) return false;
        
        uint8_t signature[8];
        file.read(reinterpret_cast<char*>(signature), 8);
        
        return (signature[0] == 0xD0 && signature[1] == 0xCF &&
                signature[2] == 0x11 && signature[3] == 0xE0 &&
                signature[4] == 0xA1 && signature[5] == 0xB1 &&
                signature[6] == 0x1A && signature[7] == 0xE1);
    }

    static size_t findPattern(const std::vector<char>& buffer, const std::string& pattern) {
        if (buffer.size() < pattern.length()) return std::string::npos;
        
        for (size_t i = 0; i <= buffer.size() - pattern.length(); i++) {
            bool match = true;
            for (size_t j = 0; j < pattern.length(); j++) {
                if (buffer[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return std::string::npos;
    }
};

#endif