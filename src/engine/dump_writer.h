// Original-bytes region dump: the
// exit-time capture of dirty regions exactly as they sit in guest memory -
// one raw .bin per region (no header, no wrapper) plus a manifest listing
// base / size / type / protection / first dirty page per file, so the
// repair pipeline can load each image directly at its base. Deterministic:
// the same replay produces byte-identical files. The
// unicorn handle is forward declared.

#ifndef SHELLER_ENGINE_DUMP_WRITER_H
#define SHELLER_ENGINE_DUMP_WRITER_H

#include "write_ledger.h"

#include <filesystem>

struct uc_struct;
typedef struct uc_struct uc_engine;

namespace sheller::engine {

// Writes directory/<base-hex>.bin for every written region plus a
// manifest.txt index; region bytes are read from the live guest at dump
// time. Returns false on any read or write failure (partial files possible).
bool write_dump(const std::filesystem::path& directory, const MemWriteLedger& ledger,
                uc_engine* uc);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_DUMP_WRITER_H
