// Shared test adapter: attribution probe -> BehaviorRulesParams. The e2e
// suites that attach the real event stream (behavior_e2e, event_baseline)
// both need the same tables; keeping one builder means a probe field added
// later cannot silently reach one suite and miss the other.

#pragma once

#include "../behavior/behavior_rules.h"
#include "../engine/rebuild_probe.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

inline sheller::behavior::BehaviorRulesParams
behavior_params_from_probe(const sheller::engine::detail::AttributionProbe& probe)
{
    sheller::behavior::BehaviorRulesParams params;
    params.teb_address = probe.teb_address;
    params.peb_address = probe.peb_address;
    params.sample_image_base = probe.image_base;
    params.sample_image_size = probe.image_size;
    for (const auto& image : probe.images) {
        params.modules.push_back(image.module);
        if (std::string_view(image.module.name.data()) == "ntdll.dll") {
            params.ntdll_base = image.module.base;
        }
    }
    for (const auto& entry : probe.syscall_numbers) {
        if (std::string_view(entry.name.data()) == "NtQueryInformationProcess") {
            params.query_process_number = entry.number;
        }
    }
    for (const auto& slot : probe.export_slots) {
        if (slot.module_base == params.ntdll_base &&
            std::string_view(slot.name.data()).starts_with("Nt")) {
            params.syscall_entries.push_back(slot.function_va);
        }
    }
    std::ranges::sort(params.syscall_entries);
    const auto module_name = [&](const std::uint64_t base) -> std::string_view {
        for (const auto& module : params.modules) {
            if (module.base == base) {
                return std::string_view(module.name.data());
            }
        }
        return {};
    };
    // Function-entry annotations, plus the two entry-arrival API tables the
    // rules layer resolves against (probe calls, handler registration).
    for (const auto& slot : probe.export_slots) {
        sheller::behavior::BehaviorRulesParams::ExportSlot function_entry;
        function_entry.slot_va = slot.function_va;
        std::string annotation{module_name(slot.module_base)};
        annotation += '!';
        annotation += std::string_view(slot.name.data());
        annotation.resize(std::min(annotation.size(), function_entry.annotation.size() - 1));
        std::ranges::copy(annotation, function_entry.annotation.begin());
        params.function_entries.push_back(function_entry);
        const std::string_view name{slot.name.data()};
        if (name == "CheckRemoteDebuggerPresent" || name == "IsDebuggerPresent" ||
            name == "NtQueryInformationProcess" || name == "RtlQueryProcessDebugInformation") {
            params.probe_api_entries.push_back(slot.function_va);
        }
        if (name == "RtlAddVectoredExceptionHandler" || name == "RtlAddVectoredContinueHandler" ||
            name == "SetUnhandledExceptionFilter" || name == "RtlAddFunctionTable" ||
            name == "RtlInstallFunctionTableCallback") {
            params.exception_handler_api_entries.push_back(slot.function_va);
        }
    }
    std::ranges::sort(params.function_entries, std::ranges::less{},
                      &sheller::behavior::BehaviorRulesParams::ExportSlot::slot_va);
    const auto unique_sorted = [](std::vector<std::uint64_t>& values) {
        std::ranges::sort(values);
        values.erase(std::unique(values.begin(), values.end()), values.end());
    };
    unique_sorted(params.probe_api_entries);
    unique_sorted(params.exception_handler_api_entries);
    return params;
}
