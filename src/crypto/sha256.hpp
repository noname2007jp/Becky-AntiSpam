#pragma once

#include <string>
#include <string_view>

namespace beckyas {

// Returns a lowercase 64-character SHA-256 hex digest of the exact input bytes.
std::string sha256_hex(std::string_view data);

} // namespace beckyas
