#ifndef ENCRYPTION_DETECT_H
#define ENCRYPTION_DETECT_H

#include <vector>
#include <string>
#include <iostream>
#include "file_util.h"

class EncryptionDetect {
public:
    static void analyzeEncryption(const std::vector<char>& buffer) {
        std::cout << "\n--- ENCRYPTION ANALYSIS ---" << std::endl;
        
        std::vector<std::string> encryptionMarkers = {
            "Encrypted", "Encryption", "Password", "StrongEncryption",
            "EncryptedPackage", "E.n.c.r.y.p.t.e.d.P.a.c.k.a.g.e",
            "Microsoft Strong Cryptographic Provider"
        };

        bool found = false;
        for (const auto& marker : encryptionMarkers) {
            size_t pos = FileUtils::findPattern(buffer, marker);
            if (pos != std::string::npos) {
                std::cout << "🔒 " << marker << " at offset: 0x" 
                          << std::hex << pos << std::dec << std::endl;
                found = true;
            }
        }

        if (!found) {
            std::cout << "No strong encryption indicators found." << std::endl;
        }
    }

    static void extractReadableContent(const std::vector<char>& buffer) {
        std::cout << "\n--- READABLE CONTENT ---" << std::endl;
        
        std::string currentString;
        int count = 0;

        for (size_t i = 0; i < buffer.size(); i++) {
            char c = buffer[i];
            if (c >= 32 && c <= 126) {
                currentString += c;
            } else {
                if (currentString.length() >= 8 && isMeaningfulContent(currentString)) {
                    std::cout << "[" << ++count << "] " 
                              << currentString.substr(0, 50) 
                              << (currentString.length() > 50 ? "..." : "") 
                              << std::endl;
                }
                currentString.clear();
            }
        }
    }

private:
    static bool isMeaningfulContent(const std::string& str) {
        std::vector<std::string> keywords = {
            "Sheet", "Workbook", "Worksheet", "Excel", "Microsoft",
            "Table", "Chart", "Data", "Cell", "Row", "Column",
            "Style", "Format", "Font", "Border", "NumberFormat"
        };

        for (const auto& keyword : keywords) {
            if (str.find(keyword) != std::string::npos) {
                return true;
            }
        }

        return false;
    }
};

#endif