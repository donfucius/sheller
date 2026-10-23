// Loader import resolution unit tests: export lookup with bounded
// forwarder chains and IAT walk/fixup, exercised against the host's real
// system DLLs (the loader route needs a Windows host when imports exist).

#include "imports.h"

#include <windows.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

using namespace sheller::loader;
namespace loader = sheller::loader;

#ifdef _WIN32

std::filesystem::path system_dll(const char* name)
{
    char root[MAX_PATH] = {};
    const auto len = GetSystemDirectoryA(root, sizeof root);
    return len == 0 ? std::filesystem::path(name) : std::filesystem::path(root) / name;
}

loader::LoadedModule load_system_module(const char* file_name, const char* folded_name,
                                        const std::uint64_t base)
{
    std::ifstream in(system_dll(file_name), std::ios::binary);
    std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                    std::istreambuf_iterator<char>()};
    loader::LoadedModule module;
    module.base = base;
    module.image = bytes;
    std::memcpy(module.name.data(), folded_name, std::strlen(folded_name));
    static_cast<void>(index_exports(module));
    return module;
}

std::vector<loader::LoadedModule> make_modules()
{
    std::vector<loader::LoadedModule> modules;
    modules.push_back(load_system_module("kernel32.dll", "kernel32.dll", 0x7FFA00000000ULL));
    modules.push_back(load_system_module("kernelbase.dll", "kernelbase.dll", 0x7FF900000000ULL));
    modules.push_back(load_system_module("ntdll.dll", "ntdll.dll", 0x7FF800000000ULL));
    modules.push_back(load_system_module("ucrtbase.dll", "ucrtbase.dll", 0x7FF700000000ULL));
    return modules;
}

TEST(LoaderImports, DirectExportResolves)
{
    auto modules = make_modules();
    const auto resolved = resolve_export(modules, "kernel32.dll", "VirtualAlloc");
    std::size_t total = 0;
    for (const auto& m : modules) {
        std::printf("module %s exports=%zu", m.name.data(), m.exports.size());
        total += m.exports.size();
    }
    std::printf("total=%zu", total);
    EXPECT_TRUE(resolved.ok);
    EXPECT_FALSE(resolved.forwarded);
    EXPECT_NE(resolved.va, 0U); // resolved into a mapped module
}

TEST(LoaderImports, ForwarderChainResolvesAcrossModules)
{
    // HeapAlloc is a classic kernel32 -> ntdll.RtlAllocateHeap forwarder
    auto modules = make_modules();

    const auto resolved = resolve_export(modules, "kernel32.dll", "HeapAlloc");
    ASSERT_TRUE(resolved.ok);
    EXPECT_TRUE(resolved.forwarded);           // the chain was followed
    EXPECT_GE(resolved.va, 0x7FF800000000ULL); // landed in ntdll
    EXPECT_EQ(resolved.module, &modules[2]);   // ntdll
}

TEST(LoaderImports, UnresolvableNameIsNotOk)
{
    auto modules = make_modules();
    const auto resolved = resolve_export(modules, "kernel32.dll", "NoSuchApiZzz");
    EXPECT_FALSE(resolved.ok);
}

TEST(LoaderImports, ApiSetStaticImportResolvesViaHost)
{
    // a static import names the api-ms-win-crt set directly (every /MD
    // binary does): the set reduces to its host module, ucrtbase
    auto modules = make_modules();
    const auto resolved = resolve_export(modules, "api-ms-win-crt-heap-l1-1-0.dll", "free");
    ASSERT_TRUE(resolved.ok);
    EXPECT_FALSE(resolved.forwarded);
    EXPECT_GE(resolved.va, 0x7FF700000000ULL); // landed in ucrtbase
    EXPECT_EQ(resolved.module, &modules[3]);
}

TEST(LoaderImports, ApiSetForwarderChainResolves)
{
    // kernel32!AddDllDirectory is a real forwarder to
    // api-ms-win-core-libraryloader-l1-1-0.AddDllDirectory: the chain
    // reduces the set name to its host (kernelbase) and terminates - the
    // pre-reduction "scan every module" fallback recursed infinitely here
    auto modules = make_modules();
    const auto resolved = resolve_export(modules, "kernel32.dll", "AddDllDirectory");
    ASSERT_TRUE(resolved.ok);
    EXPECT_TRUE(resolved.forwarded);
    EXPECT_GE(resolved.va, 0x7FF900000000ULL); // landed in kernelbase
    EXPECT_LT(resolved.va, 0x7FFA00000000ULL);
    EXPECT_EQ(resolved.module, &modules[1]);
}

#endif // _WIN32

// Synthetic PE32 (x86) import walk: a 32-bit "system module" with one
// exported function, and a 32-bit sample image whose IAT resolves against
// it. Self-contained - no host DLLs, runs on any platform.
TEST(LoaderImports32, FourByteThunkWalkResolves)
{
    // -- module image: minimal PE32 header + export directory --
    // layout: header block 0x200, export dir at 0x200, names at 0x240,
    // name "FakeAlloc" hint/name at 0x260
    std::vector<std::uint8_t> module(0x400, 0);
    auto p32 = [&module](std::size_t offset, std::uint32_t value) {
        std::memcpy(&module[offset], &value, sizeof value);
    };
    auto p16 = [&module](std::size_t offset, std::uint16_t value) {
        std::memcpy(&module[offset], &value, sizeof value);
    };
    const std::uint32_t module_base = 0x77000000;
    module[0] = 'M';
    module[1] = 'Z';
    p32(0x3C, 0x40);
    p32(0x40, 0x00004550);
    p16(0x44, 0x014C);      // i386
    p16(0x58, 0x010B);      // PE32
    p32(0x74, module_base); // ImageBase
    // DataDirectory[0] (export) at 0x58 + 0x60 = 0xB8
    p32(0xB8, 0x200); // export dir RVA
    p32(0xBC, 0x40);  // export dir size
    // export directory at 0x200; its size dword (dir+4) gates index_exports
    p32(0x204, 0x40);
    p32(0x200 + 0x18, 1);     // NumberOfNames
    p32(0x200 + 0x1C, 0x228); // AddressOfFunctions
    p32(0x200 + 0x20, 0x22C); // AddressOfNames
    p32(0x200 + 0x24, 0x230); // AddressOfNameOrdinals
    p32(0x228, 0x280);        // function RVA -> ret stub below
    p32(0x22C, 0x260);        // name RVA -> "FakeAlloc"
    p16(0x230, 0);            // ordinal 0
    std::memcpy(&module[0x260], "FakeAlloc", 10);
    module[0x280] = 0xC3; // a ret instruction as the export target

    loader::LoadedModule loaded;
    loaded.base = module_base;
    loaded.image = module;
    std::memcpy(loaded.name.data(), "fake32.dll", 10);
    ASSERT_TRUE(loader::index_exports(loaded).has_value());
    ASSERT_EQ(loaded.exports.size(), 1U);

    // -- sample image: minimal PE32 header + one import descriptor --
    std::vector<std::uint8_t> sample(0x400, 0);
    auto s32 = [&sample](std::size_t offset, std::uint32_t value) {
        std::memcpy(&sample[offset], &value, sizeof value);
    };
    sample[0] = 'M';
    sample[1] = 'Z';
    s32(0x3C, 0x40);
    s32(0x40, 0x00004550);
    const std::uint16_t pe32_magic = 0x010B;
    std::memcpy(&sample[0x58], &pe32_magic, sizeof pe32_magic);
    // DataDirectory[1] (import) at 0x58 + 0x60 + 8 = 0xC0
    s32(0xC0, 0x300); // import descriptors RVA
    // descriptor at 0x300: OriginalFirstThunk 0x320, Name 0x340, FirstThunk 0x330
    s32(0x300, 0x320);
    s32(0x30C, 0x340);
    s32(0x310, 0x330);
    std::memcpy(&sample[0x340], "FAKE32.dll", 11);
    // OFT entry: hint/name RVA 0x360 ("FakeAlloc" name at 0x362)
    s32(0x320, 0x360);
    s32(0x324, 0); // terminator
    std::memcpy(&sample[0x362], "FakeAlloc", 10);
    // IAT pre-resolution value = hint/name RVA
    s32(0x330, 0x360);
    s32(0x334, 0);

    std::vector<loader::UnresolvedImport> unresolved;
    const auto fixups =
        resolve_imports(sample, std::vector<loader::LoadedModule>{loaded}, &unresolved);
    ASSERT_TRUE(fixups.has_value());
    EXPECT_EQ(fixups->size(), 1U);
    EXPECT_TRUE(unresolved.empty());
    EXPECT_EQ(fixups->at(0).iat_rva, 0x330U);
    EXPECT_EQ(fixups->at(0).resolved, module_base + 0x280U);

    // the IAT slot (4 bytes) now holds the absolute VA
    std::uint32_t slot = 0;
    std::memcpy(&slot, &sample[0x330], sizeof slot);
    EXPECT_EQ(slot, module_base + 0x280U);
}

} // namespace
