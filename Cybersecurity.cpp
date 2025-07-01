#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <random>
#include <cctype>

using namespace std;

string generateSecurePassword(int length = 12) {
    const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const string digits = "0123456789";
    const string special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    string allChars = uppercase + lowercase + digits + special;
    random_device rd;
    mt19937 generator(rd());
    shuffle(allChars.begin(), allChars.end(), generator);
    
    string password;
    for (int i = 0; i < length; ++i) {
        password += allChars[rand() % allChars.size()];
    }
    
    password[0] = uppercase[rand() % uppercase.size()];
    password[1] = lowercase[rand() % lowercase.size()];
    password[2] = digits[rand() % digits.size()];
    password[3] = special[rand() % special.size()];
    
    shuffle(password.begin(), password.end(), generator);
    return password;
}

int passwordStrength(const string& password) {
    int strength = 0;
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    
    if (password.length() >= 8) strength += 1;
    if (password.length() >= 12) strength += 1;
    
    for (char c : password) {
        if (isupper(c)) hasUpper = true;
        else if (islower(c)) hasLower = true;
        else if (isdigit(c)) hasDigit = true;
        else hasSpecial = true;
    }
    
    if (hasUpper) strength += 1;
    if (hasLower) strength += 1;
    if (hasDigit) strength += 1;
    if (hasSpecial) strength += 1;
    
    return min(strength, 5);
}

string xorEncryptDecrypt(const string& input, char key) {
    string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key;
    }
    return output;
}

void displayMenu() {
    cout << "\n=== Кибербезопасность - Меню ===" << endl;
    cout << "1. Сгенерировать безопасный пароль" << endl;
    cout << "2. Проверить сложность пароля" << endl;
    cout << "3. Зашифровать текст (XOR)" << endl;
    cout << "4. Расшифровать текст (XOR)" << endl;
    cout << "5. Выход" << endl;
    cout << "Выберите опцию: ";
}

int main() {
    srand(time(nullptr));
    
    int choice;
    string input;
    char key;
    
    do {
        displayMenu();
        cin >> choice;
        cin.ignore();
        
        switch (choice) {
            case 1: {
                int length;
                cout << "Введите длину пароля (рекомендуется 12+): ";
                cin >> length;
                if (length < 8) {
                    cout << "Пароль слишком короткий. Установлена минимальная длина 8." << endl;
                    length = 8;
                }
                string password = generateSecurePassword(length);
                cout << "Сгенерированный пароль: " << password << endl;
                break;
            }
            case 2: {
                cout << "Введите пароль для проверки: ";
                getline(cin, input);
                int strength = passwordStrength(input);
                cout << "Оценка сложности пароля: " << strength << "/5" << endl;
                cout << "Рекомендации: ";
                if (strength < 3) {
                    cout << "Пароль очень слабый. Используйте больше символов разных типов.";
                } else if (strength < 5) {
                    cout << "Пароль можно улучшить. Попробуйте добавить специальные символы или увеличить длину.";
                } else {
                    cout << "Отличный пароль!";
                }
                cout << endl;
                break;
            }
            case 3: {
                cout << "Введите текст для шифрования: ";
                getline(cin, input);
                cout << "Введите ключ шифрования (один символ): ";
                cin >> key;
                cin.ignore();
                string encrypted = xorEncryptDecrypt(input, key);
                cout << "Зашифрованный текст: " << encrypted << endl;
                break;
            }
            case 4: {
                cout << "Введите текст для расшифровки: ";
                getline(cin, input);
                cout << "Введите ключ шифрования (один символ): ";
                cin >> key;
                cin.ignore();
                string decrypted = xorEncryptDecrypt(input, key);
                cout << "Расшифрованный текст: " << decrypted << endl;
                break;
            }
            case 5:
                cout << "Выход из программы..." << endl;
                break;
            default:
                cout << "Неверный выбор. Попробуйте снова." << endl;
        }
    } while (choice != 5);
    
    return 0;
}
