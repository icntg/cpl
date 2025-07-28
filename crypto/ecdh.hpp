#ifndef BIGNUM_H
#define BIGNUM_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstdbool>

using namespace std;

class ECC {
protected:
    // 以大端序在内存中保存数据
    vector<uint8_t> stream{};
    bool positive{true};
public:
    ECC() {

    }

    explicit ECC(uint64_t val) {

    }

    explicit ECC(int64_t val) {

    }

    explicit ECC(string val) {

    }

    ~ECC() = default;

    int32_t Plus(const ECC& other) {

    }

    int32_t Minus(const ECC& other) {

    }

    int32_t Multiply(const ECC& other) {

    }

    int32_t Divide(const ECC& other) {

    }

    int32_t Mod(const ECC& other) {

    }
};

#endif //BIGNUM_H
