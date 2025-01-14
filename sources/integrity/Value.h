#pragma once

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <memory>

typedef unsigned char byte;

/**
 * @brief Value 类，表示 16 字节的数据。
 */
class Value {
private:
    std::shared_ptr<byte> data;  // 使用 shared_ptr 管理内存

public:
    /**
   * @brief 默认构造函数，初始化为全零。
     */
    Value() : data(new byte[16](), std::default_delete<byte[]>()) {}

    /**
   * @brief 从原始字节数组构造 Value。
   * @param input 输入的字节数组。
     */
    Value(const byte* input)
        : data(new byte[16], std::default_delete<byte[]>()) {
        if (!input) {
            throw std::invalid_argument("Input pointer cannot be null.");
        }
        std::memcpy(data.get(), input, 16);
    }

    /**
   * @brief 支持下标访问。
     */
    byte& operator[](size_t index) {
        if (index >= 16) {
            throw std::out_of_range("Index out of bounds");
        }
        return *(data.get() + index);
    }

    const byte& operator[](size_t index) const {
        if (index >= 16) {
            throw std::out_of_range("Index out of bounds");
        }
        return *(data.get() + index);
    }

    /**
   * @brief 获取底层数据的只读指针。
     */
    const byte* getData() const { return data.get(); }

    /**
   * @brief 比较两个 Value 是否相等。
     */
    bool operator==(const Value& other) const {
        return std::memcmp(data.get(), other.data.get(), 16) == 0;
    }

    int size() const {
        return 16;
    }

    /**
   * @brief 输出调试信息。
     */
    friend std::ostream& operator<<(std::ostream& os, const Value& value) {
        os << "[";
        for (size_t i = 0; i < 16; ++i) {
            if (i > 0) os << " ";
            os << static_cast<int>(value.data.get()[i]);
        }
        os << "]";
        return os;
    }
};
