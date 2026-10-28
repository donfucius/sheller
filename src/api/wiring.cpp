// Facade wiring implementation: the absorbed CLI behavior setup plus the
// facade-only pieces (semantic collector, timeline re-encode, sink tee).
// Everything here is a pure function of the event/fact stream - the sinks
// observe, engine semantics never depend on them, so the golden event
// streams stay byte-identical with or without a subscriber.

#include "wiring.h"

#include "../syscalls/syscall_policy.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <ranges>
#include <span>
#include <string_view>
#include <utility>

namespace sheller::api::detail {

std::optional<std::uint16_t> peek_pe_magic(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 0x40> dos{};
    in.read(reinterpret_cast<char*>(dos.data()), static_cast<std::streamsize>(dos.size()));
    if (!in || dos[0] != 'M' || dos[1] != 'Z') {
        return std::nullopt;
    }
    const auto e_lfanew = static_cast<std::uint32_t>(dos[0x3C]) |
                          (static_cast<std::uint32_t>(dos[0x3D]) << 8) |
                          (static_cast<std::uint32_t>(dos[0x3E]) << 16) |
                          (static_cast<std::uint32_t>(dos[0x3F]) << 24);
    std::array<std::uint8_t, 2> magic{};
    in.seekg(static_cast<std::streamoff>(e_lfanew) + 0x18);
    in.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
    if (!in) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(magic[0] | (magic[1] << 8));
}

void register_module_names(TimelineNameTable& names, const std::size_t module_index,
                           const engine::mem_region::ModuleImage& image)
{
    if (module_index >= TimelineNameTable::kRegionSentinelBase) {
        return;
    }
    if (names.modules.size() <= module_index) {
        names.modules.resize(module_index + 1);
    }
    if (names.sections.size() <= module_index) {
        names.sections.resize(module_index + 1);
    }
    names.modules[module_index] = image.module.name.data();
    auto& sections = names.sections[module_index];
    sections.clear();
    sections.emplace_back("headers");
    engine::mem_region::ImageLayout layout;
    if (engine::mem_region::parse_section_table(image.header_bytes.data(),
                                                image.header_bytes.size(), layout) ==
        engine::mem_region::PeParseError::kNone) {
        for (const auto& section : layout.sections) {
            sections.emplace_back(section.name.data());
        }
    }
}

TimelineNameTable build_timeline_names(const Wiring& wiring)
{
    TimelineNameTable names;
    // Keep the snapshot's Ldr/unknown-image indexes. Runtime registrations
    // extend this table through the fact channel using their actual indexes.
    const auto append_names = [&names](const engine::mem_region::ModuleImage& image) {
        register_module_names(names, names.modules.size(), image);
    };
    for (const auto& image : wiring.images) {
        append_names(image);
    }
    for (const auto& image : wiring.unknown_images) {
        append_names(image);
    }
    // The two tables name one number space from two routes, and only the first
    // is discoverable from the guest image. Stub route: the numbers decoded
    // out of this snapshot's own ntdll stubs, so they are that build's real
    // numbers.
    for (const auto& entry : wiring.syscall_numbers) {
        names.syscalls.emplace(entry.number, std::string(entry.name.data()));
    }
    // Reserved-number route: the sample writes its own syscall immediate, so
    // no stub carries the number and the enumeration above cannot produce it.
    // This is the policy's own table (syscall_policy.h registers the builtins
    // from these same rows), so a number cannot be answered here and stay
    // unnamed: dropping a row takes the builtin with it, and the call
    // default-denies instead. A named number still loses its parameter names
    // if the string misses the description table's key below.
    for (const auto& synthetic : syscalls::kSyntheticSyscalls) {
        names.syscalls.emplace(synthetic.number, std::string(synthetic.name));
    }
    // Join the description tables: Nt names via the second hop (name-keyed),
    // Win32 entries under their module!name key.
    behavior::default_descriptions().fill_apicall_params(names.apicall_params);
    // Sample-source view facts: module ranges plus the sample image's own
    // range. Ldr modules only - synthesized unknown images are out-of-range
    // callers for the filter.
    for (const auto& image : wiring.images) {
        names.module_ranges.emplace_back(image.module.base, image.module.base + image.module.size);
    }
    for (const auto& mod : wiring.params.modules) {
        if (mod.base == wiring.params.sample_image_base) {
            names.sample_image_range = {mod.base, mod.base + mod.size};
            break;
        }
    }
    return names;
}

namespace {

// Decodes the parameter-record stream into named semantic params (stack
// slots included, kind-tagged with an empty name - attribution-only).
void append_semantic_params(std::vector<SemanticParam>& out,
                            const std::span<const std::uint8_t> records,
                            const std::vector<std::string>* param_names)
{
    std::size_t cursor = 0;
    std::size_t index = 0;
    while (cursor < records.size()) {
        const auto record = read_param_record(records, cursor);
        if (!record.has_value()) {
            break; // malformed tail: deterministic stop
        }
        SemanticParam param;
        param.kind = record->kind;
        param.truncated = record->truncated;
        if (record->kind == ParamKind::kStackSlot) {
            if (record->bytes.size() == 8) {
                param.integer = le::load_le64(record->bytes.data());
            }
            out.push_back(std::move(param));
            continue;
        }
        if (param_names != nullptr && index < param_names->size()) {
            param.name = (*param_names)[index];
        } else {
            param.name = "arg" + std::to_string(index + 1);
        }
        const auto bytes = record->bytes;
        switch (record->kind) {
        case ParamKind::kU32:
            if (bytes.size() == 4) {
                param.integer = le::load_le32(bytes.data());
            }
            break;
        case ParamKind::kU64:
        case ParamKind::kPtr:
            if (bytes.size() == 8) {
                param.integer = le::load_le64(bytes.data());
            }
            break;
        case ParamKind::kBool:
            param.integer = bytes.size() == 1 && bytes[0] != 0 ? 1 : 0;
            break;
        case ParamKind::kStrA:
        case ParamKind::kStrW:
            // strW is already UTF-8 at capture (pinned conversion).
            param.text.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            break;
        case ParamKind::kBuf:
            param.bytes.assign(bytes.begin(), bytes.end());
            break;
        case ParamKind::kUnreadable:
        default:
            break;
        }
        out.push_back(std::move(param));
        ++index;
    }
}

} // namespace

bool SemanticCollector::is_system_module_address(const std::uint64_t address) const
{
    const auto [sample_base, sample_end] = names_.sample_image_range;
    if (sample_base != 0 && address >= sample_base && address < sample_end) {
        return false; // the sample's own image is not a system module
    }
    for (const auto& [base, end] : names_.module_ranges) {
        if (address >= base && address < end) {
            return true;
        }
    }
    return false; // stack, heap, private-exec, unmapped
}

void SemanticCollector::on_event(const EventTypeId type, const EventPreamble& preamble,
                                 const std::span<const std::uint8_t> fields)
{
    bool selected = type == EventTypeId::kSyscall || type == EventTypeId::kApiCall ||
                    type == EventTypeId::kXfer || type == EventTypeId::kException ||
                    type == EventTypeId::kThreadCreate || type == EventTypeId::kCpuid ||
                    type == EventTypeId::kRdtsc || type == EventTypeId::kStackRestore ||
                    (is_judgment_event(type) && type != EventTypeId::kSmcExecute);
    if (type == EventTypeId::kMemWrite || type == EventTypeId::kMemRead) {
        const auto access = read_mem_access(fields);
        if (!access.has_value()) {
            // Let the decode switch below count the malformed payload as a
            // semantic drop instead of dropping it in the filter.
            selected = true;
        } else {
            selected = is_system_module_address(access->address);
            if (selected && type == EventTypeId::kMemWrite) {
                // The read seam already carries sample-side readers only; the
                // write seam also carries system writers, so the writer flag
                // decides that half of the policy.
                selected = (access->flags & kMemAccessFlagSampleWriter) != 0;
            }
        }
    }
    if (!selected) {
        // Window-side types (block-exec, sample-code, smc-execute), and the
        // page accesses that are not a sample-code access into a system
        // module, belong to counts/ledger/observer only. Their sequence
        // numbers were consumed by the stream tee and they never spend a
        // semantic arrival ordinal.
        return;
    }

    SemanticEvent event;
    event.type = type;
    event.wire_seq = preamble.seq;
    event.tid = preamble.tid;
    event.pc = preamble.pc;
    event.flags = 0;
    event.truncated = false;

    switch (type) {
    case EventTypeId::kSyscall: {
        const auto call = read_syscall(fields);
        if (!call.has_value()) {
            ++dropped_; // malformed payload: counted, never a silent gap
            return;
        }
        event.flags = call->fields.flags;
        event.truncated = (call->fields.flags & kEventFlagTruncated) != 0;
        event.syscall_number = call->fields.number;
        const auto name = names_.syscalls.find(call->fields.number);
        if (name != names_.syscalls.end()) {
            event.syscall_name = name->second;
        }
        event.status = call->fields.status;
        event.success = (call->fields.flags & kEventFlagSuccess) != 0;
        event.caller_retaddr = call->fields.caller_retaddr;
        const auto param_names = names_.apicall_params.find(event.syscall_name);
        append_semantic_params(event.params, call->records,
                               param_names != names_.apicall_params.end() ? &param_names->second
                                                                          : nullptr);
        break;
    }
    case EventTypeId::kApiCall: {
        const auto call = read_api_call(fields);
        if (!call.has_value()) {
            ++dropped_;
            return;
        }
        event.flags = call->fields.flags;
        event.truncated = (call->fields.flags & kEventFlagTruncated) != 0;
        event.api_name = std::string{call->fields.name};
        event.api_module = module_name_of(names_, call->fields.module);
        event.success = (call->fields.flags & kEventFlagSuccess) != 0;
        event.retval = call->fields.retval;
        event.caller_retaddr = call->fields.caller_retaddr;
        const auto key = event.api_module + "!" + event.api_name;
        const auto param_names = names_.apicall_params.find(key);
        append_semantic_params(event.params, call->records,
                               param_names != names_.apicall_params.end() ? &param_names->second
                                                                          : nullptr);
        break;
    }
    case EventTypeId::kXfer: {
        if (fields.size() < 8) {
            ++dropped_;
            return;
        }
        const auto from_module_idx = le::load_le16(fields.data());
        const auto from_section_idx = le::load_le16(fields.data() + 2);
        const auto to_module_idx = le::load_le16(fields.data() + 4);
        const auto to_section_idx = le::load_le16(fields.data() + 6);
        // The module slot carries the attribution; the section slot carries
        // the bare section name (index 0 is the headers pseudo-section).
        // Region-class sentinels keep the class in the module name and no
        // section. Out-of-range indexes resolve to "runtime".
        const auto bare_section = [&](const std::uint16_t module_idx,
                                      const std::uint16_t section_idx) -> std::string {
            if (module_idx >= TimelineNameTable::kRegionSentinelBase) {
                return {};
            }
            if (module_idx == TimelineNameTable::kRuntimeIndex ||
                module_idx >= names_.modules.size()) {
                return "runtime";
            }
            if (section_idx != TimelineNameTable::kRuntimeIndex &&
                module_idx < names_.sections.size() &&
                section_idx < names_.sections[module_idx].size()) {
                return names_.sections[module_idx][section_idx];
            }
            return "runtime";
        };
        event.from_module = module_name_of(names_, from_module_idx);
        event.from_section = bare_section(from_module_idx, from_section_idx);
        event.to_module = module_name_of(names_, to_module_idx);
        event.to_section = bare_section(to_module_idx, to_section_idx);
        break;
    }
    case EventTypeId::kException:
        if (fields.size() < sizeof(std::uint32_t)) {
            ++dropped_;
            return;
        }
        event.exception_code = le::load_le32(fields.data());
        break;
    case EventTypeId::kThreadCreate: {
        if (fields.size() < 12) {
            ++dropped_;
            return;
        }
        event.new_tid = le::load_le32(fields.data());
        event.start_routine = le::load_le64(fields.data() + 4);
        break;
    }
    case EventTypeId::kCpuid:
    case EventTypeId::kRdtsc:
    case EventTypeId::kStackRestore:
        break; // preamble-only events today
    case EventTypeId::kMemRead:
    case EventTypeId::kMemWrite: {
        const auto access = read_mem_access(fields);
        if (!access.has_value()) {
            ++dropped_;
            return;
        }
        event.address = access->address;
        event.value = access->value;
        event.access_size = access->size;
        break;
    }
    default:
        // The remaining selected types are judgments (window-side
        // smc-execute was filtered above): the payload carries the rule's
        // address/aux/subtype and the resolved annotation.
        if (is_judgment_event(type)) {
            const auto judgment = read_judgment(fields);
            if (!judgment.has_value()) {
                ++dropped_;
                return;
            }
            event.address = judgment->fields.address;
            event.aux = judgment->fields.aux;
            event.subtype = judgment->fields.subtype;
            event.judgment_api = std::string{judgment->fields.api};
        }
        break;
    }
    // The semantic seq counts delivered records only - gapless 1..N even
    // when payload decodes dropped events.
    event.seq = next_seq_++;
    events_.push_back(std::move(event));
}

std::expected<std::vector<std::uint8_t>, std::string>
encode_timeline_tlv(const behavior::EventLedger& ledger)
{
    std::vector<std::uint8_t> tlv;
    std::vector<std::uint8_t> buffer;
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        buffer.resize(kEventHeaderSize + kEventPreambleSize + entry.type_fields.size());
        const auto written = encode_event(buffer, entry.type, entry.preamble, entry.type_fields);
        if (!written.has_value()) {
            return std::unexpected("timeline encoding failed: " +
                                   std::string{event_codec_error_message(written.error())});
        }
        tlv.insert(tlv.end(), buffer.begin(),
                   buffer.begin() + static_cast<std::ptrdiff_t>(*written));
    }
    return tlv;
}

namespace {

// The judgment queue is empty or a handful of entries between dispatches.
constexpr std::size_t kPendingEventReserve = 8;

} // namespace

EventStream::EventStream(
    behavior::BehaviorRules* rules, behavior::EventTally& tally, SemanticCollector& collector,
    behavior::EventLedger* ledger,
    std::function<void(EventTypeId, const EventPreamble&, std::span<const std::uint8_t>)> observer,
    const std::uint64_t event_type_mask)
    : rules_(rules), tally_(tally), collector_(collector), ledger_(ledger),
      observer_(std::move(observer)), event_type_mask_(event_type_mask)
{
    pending_.reserve(kPendingEventReserve);
    if (rules_ != nullptr) {
        // Emit-time numbering: the rule layer is only ever entered from a
        // dispatch on this stream, so the cursor is at the current event and
        // the judgment takes the next number.
        rules_->set_event_emitter([this](const EventTypeId type, const EventPreamble& preamble,
                                         const std::span<const std::uint8_t> fields) {
            queue_judgment(type, preamble, fields);
        });
    }
}

void EventStream::deliver(const EventTypeId type, const EventPreamble& preamble,
                          const std::span<const std::uint8_t> fields)
{
    // The internal tiers belong to the instrumented run: with no rules there
    // is no behavior report, and the counts/records stay empty (the ledger and
    // the host tap still record - the raw tiers are independent).
    if (rules_ != nullptr) {
        tally_.on_event(type, preamble, fields);
        collector_.on_event(type, preamble, fields);
    }
    if (ledger_ != nullptr) {
        ledger_->record(type, preamble, fields);
    }
    // Host subscription: mask first (zero crossings for unselected types),
    // throw guard second. The callback runs on the engine's hook paths; those
    // frames carry unwind info, so without this guard a host throw would
    // unwind out of the facade's own event delivery instead of being
    // contained at the crossing.
    const auto type_index = static_cast<std::uint64_t>(type);
    if (observer_ && type_index < 64 && ((event_type_mask_ >> type_index) & 1u) != 0) {
        try {
            observer_(type, preamble, fields);
        } catch (...) {
            // A violated no-throw contract must not terminate the host;
            // the run continues.
        }
    }
}

void EventStream::queue_judgment(const EventTypeId type, const EventPreamble& preamble,
                                 const std::span<const std::uint8_t> fields)
{
    PendingEvent pending;
    pending.type = type;
    pending.preamble = preamble;
    pending.preamble.seq = next_seq_++;
    const auto kept = std::min(fields.size(), pending.fields.size());
    std::copy_n(fields.data(), kept, pending.fields.begin());
    pending.field_count = static_cast<std::uint16_t>(kept);
    pending_.push_back(std::move(pending));
}

void EventStream::drain()
{
    for (const auto& pending : pending_) {
        deliver(pending.type, pending.preamble,
                std::span(pending.fields.data(), pending.field_count));
    }
    pending_.clear();
}

void EventStream::on_engine_event(const EventTypeId type, const EventPreamble& preamble,
                                  const std::span<const std::uint8_t> fields)
{
    EventPreamble numbered = preamble;
    numbered.seq = next_seq_++;
    if (rules_ != nullptr) {
        rules_->on_event(type, numbered, fields);
    }
    deliver(type, numbered, fields);
    // The rules' judgments were numbered while the event was being handled;
    // they land after it, before the next engine event.
    drain();
}

void EventStream::forward_mem_fact(const engine::BehaviorFact& fact, const EventTypeId type)
{
    const MemAccessFields access{.address = fact.addr,
                                 .value = type == EventTypeId::kMemRead ? fact.aux : 0,
                                 .size = fact.size,
                                 .flags = type == EventTypeId::kMemWrite && fact.writer_sample_code
                                              ? kMemAccessFlagSampleWriter
                                              : std::uint8_t{0}};
    std::array<std::uint8_t, kMemAccessFixedBytes> fields{};
    const auto written = encode_mem_access(fields, access);
    if (!written.has_value()) {
        return; // fixed-size payload: unreachable
    }
    const EventPreamble preamble{.seq = next_seq_++, .tid = 0, .pc = fact.pc};
    deliver(type, preamble, std::span(fields.data(), *written));
}

void EventStream::forward_code_fact(const engine::BehaviorFact& fact)
{
    // The fact still reaches the rules below: on_code consumes the bytes for
    // GetPC. Only the sample-code event itself is optional - without a ledger
    // and with no observer selecting it, the event is a count. The ordinal is
    // still consumed so semantic and full levels number every other entry
    // identically.
    const auto sample_code_index = static_cast<std::uint64_t>(EventTypeId::kSampleCode);
    const bool observer_wants_code = static_cast<bool>(observer_) && sample_code_index < 64 &&
                                     ((event_type_mask_ >> sample_code_index) & 1u) != 0;
    if (ledger_ == nullptr && !observer_wants_code) {
        ++next_seq_;
        tally_.add_count(EventTypeId::kSampleCode, 1);
        return;
    }
    const auto bytes =
        std::span(fact.bytes.data(), std::min<std::size_t>(fact.length, fact.bytes.size()));
    const SampleCodeFields code{.length = fact.length, .bytes = bytes};
    std::array<std::uint8_t, kSampleCodeBytesOffset + kSampleCodeMaxBytes> fields{};
    const auto written = encode_sample_code(fields, code);
    if (!written.has_value()) {
        return; // bounded by the fact's 15-byte buffer: unreachable
    }
    const EventPreamble preamble{.seq = next_seq_++, .tid = 0, .pc = fact.pc};
    deliver(EventTypeId::kSampleCode, preamble, std::span(fields.data(), *written));
}

void EventStream::on_behavior_fact(const engine::BehaviorFact& fact)
{
    // The forwarded event precedes the judgments the same fact triggers.
    switch (fact.kind) {
    case engine::BehaviorFact::Kind::kMemRead:
        forward_mem_fact(fact, EventTypeId::kMemRead);
        break;
    case engine::BehaviorFact::Kind::kMemWrite:
        forward_mem_fact(fact, EventTypeId::kMemWrite);
        break;
    case engine::BehaviorFact::Kind::kCode:
        forward_code_fact(fact);
        break;
    default:
        break;
    }
    if (rules_ != nullptr) {
        rules_->on_fact(fact);
    }
    drain();
}

void EventStream::on_stub_call(const std::uint16_t module, const std::string_view name,
                               const std::uint64_t count)
{
    tally_.on_stub_call(module, name, count);
    if (ledger_ != nullptr) {
        ledger_->record_stub_call(module, name, count);
    }
}

engine::FactChannel install_behavior_sinks(engine::SyscallRunOptions& run, EventStream& stream,
                                           TimelineNameTable* const names)
{
    // Guest output needs no default here: the engine drops the bytes when the
    // host sets no write_sink, so the facade no longer installs a lambda to
    // keep the host's stdout out of the picture.
    engine::FactChannel facts;
    if (!stream.active()) {
        run.event_sink = nullptr;
        run.stub_sink = nullptr;
        return facts;
    }
    if (stream.has_rules()) {
        if (names != nullptr) {
            facts.module_sink = [names](const std::size_t index,
                                        const engine::mem_region::ModuleImage& image) {
                register_module_names(*names, index, image);
            };
        }
        facts.behavior_sink = [&stream](const engine::BehaviorFact& fact) {
            stream.on_behavior_fact(fact);
        };
        run.stub_sink = [&stream](const std::uint16_t module, const std::string_view name,
                                  const std::uint64_t count) {
            stream.on_stub_call(module, name, count);
        };
    } else {
        // Un-instrumented: the behavior tier stays off entirely (no
        // monitored windows, no per-instruction crossings), so its artifacts
        // stay empty while the ledger and the host tap keep recording.
        run.stub_sink = nullptr;
    }
    run.event_sink = [&stream](const EventTypeId type, const EventPreamble& preamble,
                               const std::span<const std::uint8_t> fields) {
        stream.on_engine_event(type, preamble, fields);
    };
    return facts;
}

AnalysisArtifacts assemble_artifacts(behavior::EventTally& tally, SemanticCollector& collector,
                                     const TimelineNameTable& names,
                                     const behavior::EventLedger* ledger, const bool instrumented,
                                     std::string note,
                                     std::optional<engine::SyscallRunStats> run_stats,
                                     std::string& timeline_error)
{
    AnalysisArtifacts artifacts;
    artifacts.instrumented = instrumented;
    artifacts.note = std::move(note);
    artifacts.run_stats = std::move(run_stats);
    artifacts.semantic_events = collector.take();
    artifacts.semantic_dropped = collector.dropped();
    // OEP candidates in first-occurrence order: the semantic stream is in
    // arrival order, and the first candidate per page is what the rule
    // emitted, so a filter-and-copy keeps the order.
    for (const auto& event : artifacts.semantic_events) {
        if (event.type == EventTypeId::kOepCandidate) {
            artifacts.oep_candidates.push_back(event.pc);
        }
    }
    for (std::size_t i = 0; i < artifacts.event_counts.size(); ++i) {
        artifacts.event_counts[i] = tally.count_of(static_cast<EventTypeId>(i));
    }
    for (const auto& [key, count] : tally.stub_counts()) {
        StubCall stub;
        stub.module = key.first;
        stub.name = key.second;
        // module_name_of spells sentinel classes (private-exec/...) and
        // "runtime" for out-of-range indexes - the report's key stays
        // "模块!名字" shaped exactly like the pre-facade render.
        stub.module_name = module_name_of(names, key.first);
        stub.count = count;
        artifacts.stub_calls.push_back(std::move(stub));
    }
    if (ledger != nullptr) {
        auto tlv = encode_timeline_tlv(*ledger);
        if (tlv.has_value()) {
            artifacts.timeline_tlv = std::move(*tlv);
        } else {
            // A codec error is the caller's failure signal: reported through
            // the out-param so the entry maps it into a kRun failure - a
            // truncated byte stream is never delivered as a success
            // artifact.
            artifacts.timeline_tlv.clear();
            timeline_error = tlv.error();
        }
        artifacts.timeline_names = names;
        artifacts.timeline_dropped = ledger->dropped();
        artifacts.timeline_truncated = ledger->truncated();
    }
    return artifacts;
}

} // namespace sheller::api::detail
