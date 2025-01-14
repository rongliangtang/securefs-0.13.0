#pragma once

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <memory>

typedef unsigned char byte;

/**
 * @brief Key 类，用于高效存储和操作字节数据。
 */
class Key {
private:
    std::shared_ptr<byte> data;  // 使用 shared_ptr 管理内存
    size_t data_size;            // 数据大小

public:
    /**
   * @brief 从原始字节数组构造 Key。
   * @param input 输入字节数组。
   * @param size 字节数组大小。
     */
    Key(const byte* input, size_t size)
        : data(new byte[size], std::default_delete<byte[]>()), data_size(size) {
        if (!input) {
            throw std::invalid_argument("Input pointer cannot be null.");
        }
        std::memcpy(data.get(), input, size);
    }

    /**
   * @brief 获取大小。
   * @return 数据大小。
     */
    size_t size() const { return data_size; }

    /**
   * @brief 获取底层数据的只读指针。
   * @return 数据指针。
     */
    const byte* getData() const { return data.get(); }

    /**
   * @brief 获取底层数据的可写指针。
   * @return 数据指针。
     */
    byte* getData() { return data.get(); }

    /**
   * @brief 支持数组下标访问。
     */
    byte& operator[](size_t index) {
        if (index >= data_size) {
            throw std::out_of_range("Index out of bounds");
        }
        return *(data.get() + index);
    }

    const byte& operator[](size_t index) const {
        if (index >= data_size) {
            throw std::out_of_range("Index out of bounds");
        }
        return *(data.get() + index);
    }

    /**
   * @brief 计算哈希值（前后 8 字节异或）。
   * @return 哈希值。
     */
    uint64_t getHash() const {
        if (data_size < 8) {
            throw std::runtime_error("Key size is too small for hash calculation");
        }
        uint64_t result;
        std::memcpy(&result, data.get() + data_size - sizeof(uint64_t), sizeof(uint64_t));
        return result;
    }

    /**
   * @brief 比较两个 Key 是否相等。
     */
    bool operator==(const Key& other) const {
        return data_size == other.data_size &&
            std::memcmp(data.get(), other.data.get(), data_size) == 0;
    }

    /**
   * @brief 输出调试信息。
     */
    friend std::ostream& operator<<(std::ostream& os, const Key& key) {
        os << "[";
        for (size_t i = 0; i < key.data_size; ++i) {
            if (i > 0) os << " ";
            os << static_cast<int>(key.data.get()[i]);
        }
        os << "]";
        return os;
    }
};

// 自定义 Key 的哈希函数
namespace std {
template <>
struct hash<Key> {
    size_t operator()(const Key& key) const { return static_cast<size_t>(key.getHash()); }
};
}  // namespace std
