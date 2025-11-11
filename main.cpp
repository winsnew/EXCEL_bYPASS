#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>

#include "common/pass_common.h"
#include "common/excel_hash.h"
#include "common/file_util.h"
#include "common/encrypt_detect.h"

class ExcelPasswordBypass {
private:
    std::vector<std::string> commonPasswords;
    std::vector<std::string> advancedPasswords;

public:
    ExcelPasswordBypass() {
        commonPasswords = PasswordCommon::getCommonPasswords();
        advancedPasswords = PasswordCommon::getAdvancedPasswords();
    }

    bool verifyExcelPassword(const std::string& filename, const std::string& password) {
        try {
            std::vector<char> buffer = FileUtils::readFile(filename);
            uint16_t passwordHash = ExcelHash::computeExcelHash(password);
            return checkPasswordInBuffer(buffer, passwordHash);
        } catch (const std::exception& e) {
            std::cout << "Error reading file: " << e.what() << std::endl;
            return false;
        }
    }

private:
    bool checkPasswordInBuffer(const std::vector<char>& buffer, uint16_t passwordHash) {
        std::vector<size_t> checkOffsets = {0x208, 0x214, 0x21C, 0x6E00, 0x6E04};
        
        for (size_t offset : checkOffsets) {
            if (offset + 2 < buffer.size()) {
                uint16_t storedHash = *reinterpret_cast<const uint16_t*>(buffer.data() + offset);
                if (storedHash == passwordHash) {
                    std::cout << "Password verified at offset: 0x" << std::hex << offset << std::dec << std::endl;
                    return true;
                }
            }
        }
        
        for (size_t i = 0; i < buffer.size() - 2; i++) {
            uint16_t fileHash = *reinterpret_cast<const uint16_t*>(buffer.data() + i);
            if (fileHash == passwordHash) {
                std::cout << "Password hash found at offset: " << i << std::endl;
                return true;
            }
        }
        
        return false;
    }

public:
    std::string bruteForcePassword(const std::string& filename) {
        std::cout << "\n=== BRUTE FORCE ATTEMPT ===" << std::endl;
        
        if (!FileUtils::isExcelFile(filename)) {
            std::cout << "Invalid Excel file!" << std::endl;
            return "";
        }

        auto startTime = std::chrono::high_resolution_clock::now();
        std::cout << "Trying common passwords..." << std::endl;
        for (const auto& password : commonPasswords) {
            if (tryPassword(filename, password)) {
                return logSuccess(password, startTime);
            }
        }

        std::cout << "Trying numeric patterns (0-9999)..." << std::endl;
        for (int i = 0; i <= 9999; i++) {
            std::string password = std::to_string(i);
            while (password.length() < 4) password = "0" + password;
            
            if (i % 1000 == 0) {
                std::cout << "Progress: " << i << "/9999" << std::endl;
            }
            
            if (tryPassword(filename, password)) {
                return logSuccess(password, startTime);
            }
        }

        std::cout << "Trying advanced patterns..." << std::endl;
        for (const auto& password : advancedPasswords) {
            if (tryPassword(filename, password)) {
                return logSuccess(password, startTime);
            }
        }

        logFailure(startTime);
        return "";
    }

    bool createDecryptedCopy(const std::string& filename, const std::string& password, 
                           const std::string& outputFilename) {
        try {
            std::vector<char> buffer = FileUtils::readFile(filename);
            ExcelHash::simpleDecrypt(buffer, password);
            return FileUtils::writeFile(outputFilename, buffer);
        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << std::endl;
            return false;
        }
    }

    void analyzeFile(const std::string& filename) {
        std::cout << "\n=== FILE ANALYSIS ===" << std::endl;
        
        try {
            std::vector<char> buffer = FileUtils::readFile(filename);
            std::cout << "File size: " << buffer.size() << " bytes" << std::endl;
            
            EncryptionDetect::analyzeEncryption(buffer);
            EncryptionDetect::extractReadableContent(buffer);
        } catch (const std::exception& e) {
            std::cout << "Analysis error: " << e.what() << std::endl;
        }
    }

private:
    bool tryPassword(const std::string& filename, const std::string& password) {
        std::cout << "Trying: '" << password << "'" << std::endl;
        return verifyExcelPassword(filename, password);
    }

    std::string logSuccess(const std::string& password, 
                          std::chrono::high_resolution_clock::time_point startTime) {
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        std::cout << "\nPASSWORD FOUND: '" << password << "'" << std::endl;
        std::cout << "Time: " << duration.count() << " ms" << std::endl;
        return password;
    }

    void logFailure(std::chrono::high_resolution_clock::time_point startTime) {
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        std::cout << "\nPassword not found." << std::endl;
        std::cout << "Total time: " << duration.count() << " ms" << std::endl;
    }
};

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <file.xls>" << std::endl;
    std::cout << "Example: " << programName << " protected_file.xls" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string filename = argv[1];
    
    ExcelPasswordBypass bypass;
    
    std::cout << "EXCEL PASSWORD BYPASS" << std::endl;
    std::cout << "File: " << filename << std::endl;
    std::cout << "=====================================" << std::endl;

    if (!FileUtils::isExcelFile(filename)) {
        std::cout << "Invalid Excel file!" << std::endl;
        return 1;
    }

    bypass.analyzeFile(filename);
    
    std::string foundPassword = bypass.bruteForcePassword(filename);
    
    if (!foundPassword.empty()) {
        std::cout << "\nSUCCESS! Password: " << foundPassword << std::endl;
        std::string outputFile = filename + ".decrypted.xls";
        if (bypass.createDecryptedCopy(filename, foundPassword, outputFile)) {
            std::cout << "Decrypted: " << outputFile << std::endl;
        }
    } else {
        std::cout << "\nTry professional tools for more comprehensive attack." << std::endl;
    }

    return 0;
}