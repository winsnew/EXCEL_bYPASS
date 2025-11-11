#ifndef PASSWORD_COMMON_H
#define PASSWORD_COMMON_H

#include <vector>
#include <string>

class PasswordCommon {
public:
    static std::vector<std::string> getCommonPasswords() {
        return {
            "", "password", "123456", "12345678", "1234", "12345", "123",
            "excel", "microsoft", "office", "admin", "user", "secret",
            "pass", "0000", "1111", "9999", "temp", "test", "demo",
            "1234567890", "qwerty", "abc123", "letmein", "welcome",
            "monkey", "password1", "123123", "admin123", "user123"
        };
    }

    static std::vector<std::string> getAdvancedPasswords() {
        return {
            "000000", "111111", "222222", "333333", "444444", "555555",
            "666666", "777777", "888888", "999999", "012345", "1234567",
            "123456789", "987654321", "00000000", "11111111", "22222222"
        };
    }

    static std::vector<std::string> generateNumericPasswords(int maxValue) {
        std::vector<std::string> passwords;
        for (int i = 0; i <= maxValue; i++) {
            std::string pass = std::to_string(i);
            while (pass.length() < 4) pass = "0" + pass;
            passwords.push_back(pass);
        }
        return passwords;
    }
};

#endif