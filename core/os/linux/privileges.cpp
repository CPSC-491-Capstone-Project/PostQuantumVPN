#include "privileges.hpp"

#include <unistd.h>

namespace core::os {

    bool HasElevatedPrivileges() {
        return ::geteuid() == 0;
    }

} // namespace core::os
