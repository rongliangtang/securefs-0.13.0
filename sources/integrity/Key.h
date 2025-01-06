#pragma once

#include <cstring>
#include <iostream>
#include <functional>
#include <stdexcept>
#ifdef NDEBUG
#define KEY_ASSERT(condition) ((void)0)
#else
#include <cassert>
#define KEY_ASSERT(condition) assert(condition)
#endif

#include "myutils.h"

typedef unsigned char byte;

class Key {
private:
    byte data[40]; // 固定大小的 40 字节数组

public:
    /**
     * @brief 默认构造函数，将 data 初始化为全 0
     */
    Key() {
        std::memset(data, 0, sizeof(data));
    }

    /**
     * @brief 从文件 ID 和块号构造 Key
     * @param fileId 文件 ID，长度应为 32 字节
     * @param blockNumber 块号
     */
    Key(const byte* fileId, securefs::offset_type blockNumber) {
        std::memcpy(data, fileId, 32);
        std::memcpy(data + 32, &blockNumber, sizeof(blockNumber));
    }

    /**
     * @brief 支持数组下标访问，可读可写
     * @param index 访问位置，应在 [0, 39] 范围内
     * @return 可写的字节引用
     */
    byte& operator[](size_t index) {
        KEY_ASSERT(index < 40 && "Index out of bounds in Key::operator[]");
        return data[index];
    }

    /**
     * @brief 支持数组下标只读访问
     */
    const byte& operator[](size_t index) const {
        KEY_ASSERT(index < 40 && "Index out of bounds in Key::operator[]");
        return data[index];
    }

    /**
     * @brief 获取底层字节数组的指针（只读）
     */
    const byte* getData() const {
        return data;
    }

    /**
     * @brief 获取底层字节数组的指针（可写）
     */
    byte* getData() {
        return data;
    }

    /**
     * @brief 返回 Key 的大小（40 字节）
     */
    size_t size() const {
        return sizeof(data);
    }

    /**
     * @brief 使用最后 8 字节和前 8 字节异或作为哈希值
     *
     * @return 以 8 字节解释的 uint64_t
     */
    uint64_t getHash() const {
        uint64_t last_bytes;
        uint64_t first_bytes;
        // 提取最后 8 字节
        std::memcpy(&last_bytes, data + 32, sizeof(last_bytes));
        // 提取前 8 字节
        std::memcpy(&first_bytes, data, sizeof(first_bytes));
        return last_bytes ^ first_bytes;
    }

    /**
     * @brief 比较两个 Key 是否相等（字节级比较）
     */
    bool operator==(const Key& other) const {
        return std::memcmp(data, other.data, sizeof(data)) == 0;
    }

    /**
     * @brief 输出流重载，用于调试
     *
     * 以十六进制形式输出每个字节
     */
    friend std::ostream& operator<<(std::ostream& os, const Key& key) {
        // 恢复默认格式
        std::ios_base::fmtflags f(os.flags());
        os << std::hex;
        for (size_t i = 0; i < sizeof(key.data); ++i) {
            // 每字节占两位宽，前面补零
            os.width(2);
            os.fill('0');
            os << static_cast<int>(key.data[i]);
            // 可加空格或不加
            if (i + 1 < sizeof(key.data)) {
                os << ' ';
            }
        }
        os.flags(f); // 恢复原先的流格式
        return os;
    }
};

// 为 Key 特化 std::hash
namespace std {
template <>
struct hash<Key> {
    size_t operator()(const Key& key) const {
        // 使用 Key::getHash() 返回的最后 8 字节和前 8 字节异或值
        return static_cast<size_t>(key.getHash());
    }
};
} // namespace std
