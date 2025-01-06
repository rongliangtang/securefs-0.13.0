#pragma once

#include "Key.h"
#include <unordered_map>
#include <string>
#include <cstdint>

namespace integrity {

using key_type = Key;       // Key 类型为自定义的 Key 类
using value_type = uint64_t; // Value 类型为 uint64_t

class Integrity {
public:
    static Integrity& getInstance();

    void loadData();
    void saveData();

    std::unordered_map<key_type, value_type>& getHashMap();

private:
    Integrity() {}
    ~Integrity() {}

    std::unordered_map<key_type, value_type> hashmap;

    std::string getFilePath() const;

    void serializeBinary(const std::string& filePath);
    void deserializeBinary(const std::string& filePath);
    void createDirectoryIfNotExists(const std::string& path) const;
};

} // namespace integrity
