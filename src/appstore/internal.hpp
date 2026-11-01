#pragma once

#include "archive/internal.hpp"
#include <apple_auth/appstore.hpp>

namespace apple_auth::appstoredetail {
using netdetail::Path;
AppStoreMacPackageInfo inspect_mac_package(const Path& source);
} // namespace apple_auth::appstoredetail
