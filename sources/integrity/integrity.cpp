#include "integrity.h"
#include <cstdlib>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <errno.h>
#include <memory>

#ifdef _WIN32
#include <direct.h> // Windows mkdir
#define MKDIR(path, mode) _mkdir(path)
#else
#include <unistd.h> // POSIX mkdir
#define MKDIR(path, mode) mkdir(path, mode)
#endif

namespace integrity {

Integrity& Integrity::getInstance() {
    static Integrity instance;
    return instance;
}

std::unordered_map<key_type, value_type>& Integrity::getHashMap() {
    return hashmap;
}

void Integrity::createDirectoryIfNotExists(const std::string &path) const {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
#ifdef _WIN32
        if (MKDIR(path.c_str()) != 0 && errno != EEXIST) {
            throw std::runtime_error("Failed to create directory: " + path);
        }
#else
        if (MKDIR(path.c_str(), 0755) != 0 && errno != EEXIST) {
            throw std::runtime_error("Failed to create directory: " + path);
        }
#endif
    } else if (!(info.st_mode & S_IFDIR)) {
        throw std::runtime_error(path + " exists but is not a directory.");
    }
}

std::string Integrity::getFilePath() const {
    const char *home = std::getenv("HOME");
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (!appdata) {
        throw std::runtime_error("Environment variable APPDATA is not set.");
    }
    std::string dir = std::string(appdata) + "\\securefs";
#else
    if (!home) {
        throw std::runtime_error("Environment variable HOME is not set.");
    }
#ifdef __APPLE__
    std::string dir = std::string(home) + "/Library/Application Support/securefs";
#elif __linux__
    std::string dir = std::string(home) + "/.config/securefs";
#else
    throw std::runtime_error("Unsupported operating system.");
#endif
#endif
    createDirectoryIfNotExists(dir);
    return dir + "/integrity";
}

void Integrity::serializeBinary(const std::string &filePath) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to create or open file for writing: " + filePath);
    }

    for (const auto &entry : hashmap) {
        const key_type &key = entry.first;
        const value_type &value = entry.second;

        // 写入 Key 的大小
        size_t key_size = key.size();
        file.write(reinterpret_cast<const char *>(&key_size), sizeof(key_size));
        if (!file.good()) {
            throw std::runtime_error("Failed to write Key size to file: " + filePath);
        }

        // 写入 Key 的数据
        file.write(reinterpret_cast<const char *>(key.getData()), key_size);
        if (!file.good()) {
            throw std::runtime_error("Failed to write Key data to file: " + filePath);
        }

        // 写入 Value 的数据
        file.write(reinterpret_cast<const char *>(value.getData()), value.size());
        if (!file.good()) {
            throw std::runtime_error("Failed to write Value data to file: " + filePath);
        }
    }

    file.close();
    std::cout << "Data serialized to binary file: " << filePath << ", entries = " << hashmap.size() << std::endl;
}

void Integrity::deserializeBinary(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::ofstream createFile(filePath, std::ios::binary);
        if (!createFile.is_open()) {
            throw std::runtime_error("Failed to create file: " + filePath);
        }
        createFile.close();
        hashmap.clear();
        return;
    }

    hashmap.clear();

    size_t key_size;
    while (file.read(reinterpret_cast<char *>(&key_size), sizeof(key_size))) {
        // 使用 std::unique_ptr 替代 std::vector
        std::unique_ptr<byte[]> key_data(new byte[key_size]);
        if (!file.read(reinterpret_cast<char *>(key_data.get()), key_size)) {
            throw std::runtime_error("Failed to read Key data from file");
        }
        key_type key(key_data.get(), key_size);

        // 读取 Value 的数据
        byte value_data[16];
        if (!file.read(reinterpret_cast<char *>(value_data), sizeof(value_data))) {
            throw std::runtime_error("Failed to read Value data from file");
        }
        value_type value(value_data);

        // 插入到 hashmap
        hashmap[key] = value;
    }

    file.close();
    std::cout << "Data deserialized from: " << filePath << ", entries = " << hashmap.size() << std::endl;
}

void Integrity::loadData() {
    try {
        deserializeBinary(getFilePath());
    } catch (const std::exception &e) {
        std::cerr << "Failed to load data: " << e.what() << std::endl;
    }
}

void Integrity::saveData() {
    try {
        serializeBinary(getFilePath());
    } catch (const std::exception &e) {
        std::cerr << "Failed to save data: " << e.what() << std::endl;
    }
}

} // namespace integrity
