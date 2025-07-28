#ifndef BIGINT_H
#define BIGINT_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstdbool>

#include "../utility/strings.hpp"

using namespace std;


namespace cpl {
    namespace crypto {
        class BigInt10 {
        protected:
            // 以字符串方式在内存中保存数据
            string stream{};
        };

        class BigInt {
        protected:
            // 以大端序在内存中保存数据
            vector<uint8_t> stream{};
            bool positive{true};

        public:
            BigInt() {
            }

            explicit BigInt(const uint64_t val) {
                this->stream.clear();
                this->positive = true;
                const auto bytes = reinterpret_cast<const uint8_t *>(&val);
                for (size_t i = 0; i < sizeof(uint64_t); ++i) {
                    const size_t j = sizeof(uint64_t) - 1 - i;
                    this->stream.push_back(bytes[j]);
                }
            }

            explicit BigInt(const int64_t val) {
                this->stream.clear();
                this->positive = val >= 0;
                const auto abs = this->positive ? val : -val;
                const auto uv = static_cast<uint64_t>(abs);
                const auto bytes = reinterpret_cast<const uint8_t *>(&uv);
                for (size_t i = 0; i < sizeof(uint64_t); ++i) {
                    const size_t j = sizeof(uint64_t) - 1 - i;
                    this->stream.push_back(bytes[j]);
                }
            }

            explicit BigInt(string val, const int base = 10) {
                try {
                    //
                    if (base == 10) {
                    }
                    if (base == 16) {
                    }
                    throw exception(strings::Format("[x] base [%d] is not support", base));
                } catch (exception &err) {
                }
            }

            explicit BigInt(const BigInt &other) {
                this->stream = other.stream;
                this->positive = other.positive;
            }

            ~BigInt() = default;

            int32_t CmpAbs(const BigInt &other) const {
                if (this->stream.size() > other.stream.size()) {
                    return 1;
                }
                if (this->stream.size() < other.stream.size()) {
                    return -1;
                }
                for (auto i = 0; i < this->stream.size(); i++) {
                    const auto a = static_cast<int>(this->stream[i]);
                    const auto b = static_cast<int>(other.stream[i]);
                    if (a < b) {
                        return -1;
                    }
                    if (a > b) {
                        return 1;
                    }
                }
                return 0;
            }

            int32_t Compare(const BigInt &other) const {
                if (this->positive && !other.positive) {
                    return 1;
                }
                if (!this->positive && other.positive) {
                    return -1;
                }
                if (this->positive) {
                    return this->CmpAbs(other);
                }
                return -this->CmpAbs(other);
            }

            int32_t Plus(const BigInt &other) {
                const auto n0 = this->stream.size() > other.stream.size() ? other.stream.size() : this->stream.size();
                const auto n1 = this->stream.size() < other.stream.size() ? other.stream.size() : this->stream.size();
                for (auto i = 0; i < n0; i++) {
                }
                for (auto i = n0; i < n1; i++) {
                }
            }

            int32_t Minus(const BigInt &other) {
            }

            int32_t Multiply(const BigInt &other) {
            }

            int32_t Divide(const BigInt &other) {
            }

            int32_t Mod(const BigInt &other) {
            }

            int32_t Output(string &out, const int base = 10) {
            }
        };
    }
}


#endif //BIGINT_H
