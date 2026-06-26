#ifndef TIME_HPP_LAPTOP_TABLET_PHONE_CARPET_WINDOW_CHAIR_SOFA_BOOKSHELF
#define TIME_HPP_LAPTOP_TABLET_PHONE_CARPET_WINDOW_CHAIR_SOFA_BOOKSHELF

#include <ctime>
#include <string>

using namespace std;

namespace cpl {
    namespace time {
        inline string CurrentDateTimeForFilename() {
            const auto timestamp = _time64(nullptr);
            tm now{};
            const auto r00 = localtime_s(&now, &timestamp);
            if (0 != r00) {
                fprintf(stderr, "[x] localtime_s failed %ld", r00);
                return "";
            }
            string buffer{};
            buffer.reserve(128);
            buffer.resize(128);
            const auto r01 = strftime(
                &buffer[0], 128, "%Y%m%d-%H%M%S", &now
            );
            buffer.resize(r01);
            return buffer;
        }
    }
}

#endif //TIME_HPP_LAPTOP_TABLET_PHONE_CARPET_WINDOW_CHAIR_SOFA_BOOKSHELF
