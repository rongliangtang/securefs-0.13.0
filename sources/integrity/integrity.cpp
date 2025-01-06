#include "integrity.h"

#include <cstdlib>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <errno.h>

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
        // 目录不存在时，创建之
#ifdef _WIN32
        // Windows mkdir 不使用 mode 参数
        if (MKDIR(path.c_str()) != 0 && errno != EEXIST) {
            throw std::runtime_error("Failed to create directory: " + path + ", error: " + std::to_string(errno));
        }
#else
        // POSIX mkdir
        if (MKDIR(path.c_str(), 0755) != 0 && errno != EEXIST) {
            throw std::runtime_error("Failed to create directory: " + path + ", error: " + std::to_string(errno));
        }
#endif
    } else if (!(info.st_mode & S_IFDIR)) {
        throw std::runtime_error(path + " exists but is not a directory.");
    }
}

std::string Integrity::getFilePath() const {
    const char *home = std::getenv("HOME");
#ifdef _WIN32
    // 在 Windows 系统上优先使用 APPDATA
    const char* appdata = std::getenv("APPDATA");
    if (!appdata) {
        throw std::runtime_error("Environment variable APPDATA is not set.");
    }
    std::string dir = std::string(appdata) + "\\securefs";
    createDirectoryIfNotExists(dir);
    return dir + "\\integrity";
#else
    if (!home) {
        throw std::runtime_error("Environment variable HOME is not set.");
    }
#ifdef __APPLE__
    std::string dir = std::string(home) + "/Library/Application Support/securefs";
    createDirectoryIfNotExists(dir);
    return dir + "/integrity";
#elif __linux__
    std::string dir = std::string(home) + "/.config/securefs";
    createDirectoryIfNotExists(dir);
    return dir + "/integrity";
#else
    throw std::runtime_error("Unsupported operating system.");
#endif
#endif
}

void Integrity::serializeBinary(const std::string &filePath) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to create or open file for writing: " + filePath);
    }

    // 写入所有 kv
    for (const auto &entry : hashmap) {
        const key_type &key = entry.first;
        value_type value = entry.second;

        // Key: 36 字节
        file.write(reinterpret_cast<const char *>(key.getData()), key.size());
        if (!file.good()) {
            throw std::runtime_error("Failed to write Key to file: " + filePath);
        }

        // Value: 8 字节
        file.write(reinterpret_cast<const char *>(&value), sizeof(value));
        if (!file.good()) {
            throw std::runtime_error("Failed to write Value to file: " + filePath);
        }
    }
    file.close();
    std::cout << "Data serialized to binary file: " << filePath << ", entries = " << hashmap.size() << std::endl;
}

void Integrity::deserializeBinary(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        // 文件不存在时创建空文件并清空 map
        std::ofstream createFile(filePath, std::ios::binary);
        if (!createFile.is_open()) {
            throw std::runtime_error("Failed to create file: " + filePath);
        }
        createFile.close();
        hashmap.clear();
        return;
    }

    // 获取文件大小
    file.seekg(0, std::ios::end);
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Key 大小 = 36 字节, Value 大小 = 8 字节, 每个 KV = 44 字节
    const std::streamsize kvSize = 40 + 8;
    if (fileSize % kvSize != 0) {
        throw std::runtime_error("Corrupted binary file: file size is not a multiple of 44 bytes.");
    }

    size_t numEntries = static_cast<size_t>(fileSize / kvSize);

    hashmap.clear();
    // 预留空间，减少 rehash
    hashmap.reserve(static_cast<size_t>(1.2 * numEntries));

    key_type key;
    value_type value;

    // 逐个读取
    while (file.read(reinterpret_cast<char *>(key.getData()), key.size())) {
        if (!file.read(reinterpret_cast<char *>(&value), sizeof(value))) {
            throw std::runtime_error("Corrupted binary file: " + filePath);
        }
        hashmap[key] = value;
    }

    file.close();
    std::cout << "Data deserialized from: " << filePath << ", entries = " << numEntries << std::endl;
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
