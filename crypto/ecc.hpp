#ifndef ECC_H
#define ECC_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstdbool>
#include "bigint.hpp"

using namespace std;

namespace cpl {
    namespace crypto {
        class ECC {
        protected:
            // 以大端序在内存中保存数据
            BigInt d{}; // 私钥
            BigInt px{};
            BigInt py{};
            BigInt qx{};
            BigInt qy{};
        public:
            ECC() {

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
    }
}


#endif //ECC_H
