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

typedef unsigned char byte;

/**
 * @brief 固定大小为 36 字节的 Key，用于表示某种唯一标识。
 *
 * 特点：
 * - 最后 8 字节被用作哈希值 (getHash())。
 * - operator== 进行字节级比较。
 */
class Key {
private:
    byte data[36]; // 固定大小的 36 字节数组

public:
    /**
   * @brief 默认构造函数，将 data 初始化为全 0
     */
    Key() {
        std::memset(data, 0, sizeof(data));
    }

    /**
   * @brief 从原始字节数组构造 Key
   * @param input 需要至少 36 字节的数据
     */
    explicit Key(const byte* input) {
        std::memcpy(data, input, sizeof(data));
    }

    /**
   * @brief 支持数组下标访问，可读可写
   * @param index 访问位置，应在 [0, 35] 范围内
   * @return 可写的字节引用
     */
    byte& operator[](size_t index) {
        KEY_ASSERT(index < 36 && "Index out of bounds in Key::operator[]");
        return data[index];
    }

    /**
   * @brief 支持数组下标只读访问
     */
    const byte& operator[](size_t index) const {
        KEY_ASSERT(index < 36 && "Index out of bounds in Key::operator[]");
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
   * @brief 返回 Key 的大小（36 字节）
     */
    size_t size() const {
        return sizeof(data);
    }

    /**
   * @brief 使用末尾 8 字节作为哈希值
   *
   * @return 以 8 字节解释的 uint64_t
     */
    uint64_t getHash() const {
        uint64_t hash_value;
        // 将 data[28..35] 视为 uint64_t
        std::memcpy(&hash_value, data + (size() - sizeof(hash_value)), sizeof(hash_value));
        return hash_value;
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
        // 仍然使用 Key::getHash() 返回的最后 8 字节
        return static_cast<size_t>(key.getHash());
    }
};
} // namespace std
