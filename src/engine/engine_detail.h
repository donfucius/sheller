// Internal name behind sheller::unicorn_version_string. The public name is
// defined only by the shared interface library, so the static core carries
// this one and a direct-link consumer reaches the implementation here.

#ifndef SHELLER_ENGINE_DETAIL_H
#define SHELLER_ENGINE_DETAIL_H

#include <string_view>

namespace sheller::engine::detail {

std::string_view unicorn_version_impl();

} // namespace sheller::engine::detail

#endif // SHELLER_ENGINE_DETAIL_H
