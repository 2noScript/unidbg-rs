#include "dynarmic_capi.h"

#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/config.h>
#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/A64/config.h>
#include <dynarmic/interface/exclusive_monitor.h>

namespace {

constexpr uint64_t kPageSize = 0x1000;
constexpr uint64_t kPageMask = kPageSize - 1;

struct MemoryRegion {
    uint64_t base;
    std::vector<uint8_t> data;
    int perm;
};

struct DynarmicA64Env final : Dynarmic::A64::UserCallbacks {
    std::unordered_map<uint64_t, uint8_t *> pages;
    uint64_t ticks_left = 0;

    uint8_t *get_ptr(uint64_t vaddr) const {
        auto it = pages.find(vaddr & ~kPageMask);
        if (it == pages.end()) return nullptr;
        return it->second + (vaddr & kPageMask);
    }

    std::optional<std::uint32_t> MemoryReadCode(Dynarmic::A64::VAddr vaddr) override {
        return MemoryRead32(vaddr);
    }
    uint8_t MemoryRead8(Dynarmic::A64::VAddr vaddr) override {
        auto *p = get_ptr(vaddr);
        return p ? *p : 0;
    }
    uint16_t MemoryRead16(Dynarmic::A64::VAddr vaddr) override {
        uint16_t v = 0;
        if (auto *p = get_ptr(vaddr)) std::memcpy(&v, p, sizeof(v));
        return v;
    }
    uint32_t MemoryRead32(Dynarmic::A64::VAddr vaddr) override {
        uint32_t v = 0;
        if (auto *p = get_ptr(vaddr)) std::memcpy(&v, p, sizeof(v));
        return v;
    }
    uint64_t MemoryRead64(Dynarmic::A64::VAddr vaddr) override {
        uint64_t v = 0;
        if (auto *p = get_ptr(vaddr)) std::memcpy(&v, p, sizeof(v));
        return v;
    }
    Dynarmic::A64::Vector MemoryRead128(Dynarmic::A64::VAddr vaddr) override {
        Dynarmic::A64::Vector v{};
        if (auto *p = get_ptr(vaddr)) std::memcpy(&v, p, sizeof(v));
        return v;
    }

    void MemoryWrite8(Dynarmic::A64::VAddr vaddr, uint8_t value) override {
        if (auto *p = get_ptr(vaddr)) *p = value;
    }
    void MemoryWrite16(Dynarmic::A64::VAddr vaddr, uint16_t value) override {
        if (auto *p = get_ptr(vaddr)) std::memcpy(p, &value, sizeof(value));
    }
    void MemoryWrite32(Dynarmic::A64::VAddr vaddr, uint32_t value) override {
        if (auto *p = get_ptr(vaddr)) std::memcpy(p, &value, sizeof(value));
    }
    void MemoryWrite64(Dynarmic::A64::VAddr vaddr, uint64_t value) override {
        if (auto *p = get_ptr(vaddr)) std::memcpy(p, &value, sizeof(value));
    }
    void MemoryWrite128(Dynarmic::A64::VAddr vaddr, Dynarmic::A64::Vector value) override {
        if (auto *p = get_ptr(vaddr)) std::memcpy(p, &value, sizeof(value));
    }

    void InterpreterFallback(Dynarmic::A64::VAddr, size_t) override {}
    void CallSVC(uint32_t) override {}
    void ExceptionRaised(Dynarmic::A64::VAddr, Dynarmic::A64::Exception) override {}
    void AddTicks(uint64_t ticks) override {
        ticks_left = (ticks > ticks_left) ? 0 : (ticks_left - ticks);
    }
    uint64_t GetTicksRemaining() override { return ticks_left; }
    uint64_t GetCNTPCT() override { return 0; }
};

} // namespace

struct UnidbgDynarmic {
    bool is_64bit;
    Dynarmic::ExclusiveMonitor monitor{1};
    std::vector<MemoryRegion> regions;
    DynarmicA64Env env64;
    std::unique_ptr<Dynarmic::A64::Jit> jit64;
};

extern "C" {

UnidbgDynarmic *unidbg_dynarmic_create(int is_64bit) {
    auto *ctx = new UnidbgDynarmic();
    ctx->is_64bit = is_64bit != 0;
    if (ctx->is_64bit) {
        Dynarmic::A64::UserConfig cfg{};
        cfg.callbacks = &ctx->env64;
        cfg.global_monitor = &ctx->monitor;
        ctx->jit64 = std::make_unique<Dynarmic::A64::Jit>(cfg);
    }
    return ctx;
}

void unidbg_dynarmic_destroy(UnidbgDynarmic *ctx) {
    delete ctx;
}

int unidbg_dynarmic_mem_map(UnidbgDynarmic *ctx, uint64_t addr, size_t size, int perm) {
    if (!ctx || (addr & kPageMask) || (size & kPageMask)) return -1;
    MemoryRegion reg{addr, std::vector<uint8_t>(size, 0), perm};
    for (size_t off = 0; off < size; off += kPageSize) {
        ctx->env64.pages[addr + off] = reg.data.data() + off;
    }
    ctx->regions.push_back(std::move(reg));
    return 0;
}

int unidbg_dynarmic_mem_unmap(UnidbgDynarmic *ctx, uint64_t addr, size_t size) {
    if (!ctx) return -1;
    for (size_t off = 0; off < size; off += kPageSize) {
        ctx->env64.pages.erase(addr + off);
    }
    return 0;
}

int unidbg_dynarmic_mem_read(UnidbgDynarmic *ctx, uint64_t addr, void *buf, size_t size) {
    if (!ctx) return -1;
    auto *out = static_cast<uint8_t *>(buf);
    for (size_t i = 0; i < size; ++i) {
        auto *p = ctx->env64.get_ptr(addr + i);
        if (!p) return -1;
        out[i] = *p;
    }
    return 0;
}

int unidbg_dynarmic_mem_write(UnidbgDynarmic *ctx, uint64_t addr, const void *buf, size_t size) {
    if (!ctx) return -1;
    const auto *in = static_cast<const uint8_t *>(buf);
    for (size_t i = 0; i < size; ++i) {
        auto *p = ctx->env64.get_ptr(addr + i);
        if (!p) return -1;
        *p = in[i];
    }
    return 0;
}

uint64_t unidbg_dynarmic_reg_read(UnidbgDynarmic *ctx, uint32_t reg) {
    if (!ctx || !ctx->jit64) return 0;
    if (reg == 31) return ctx->jit64->GetSP();
    if (reg == 32) return ctx->jit64->GetPC();
    if (reg < 31) return ctx->jit64->GetRegister(reg);
    return 0;
}

void unidbg_dynarmic_reg_write(UnidbgDynarmic *ctx, uint32_t reg, uint64_t value) {
    if (!ctx || !ctx->jit64) return;
    if (reg == 31) ctx->jit64->SetSP(value);
    else if (reg == 32) ctx->jit64->SetPC(value);
    else if (reg < 31) ctx->jit64->SetRegister(reg, value);
}

int unidbg_dynarmic_emu_start(UnidbgDynarmic *ctx, uint64_t begin, uint64_t /*until*/, size_t count) {
    if (!ctx || !ctx->jit64) return -1;
    ctx->jit64->SetPC(begin);
    ctx->env64.ticks_left = count ? count : 1000000;
    ctx->jit64->Run();
    return 0;
}

void unidbg_dynarmic_emu_stop(UnidbgDynarmic *ctx) {
    if (ctx && ctx->jit64) ctx->jit64->HaltExecution();
}

}
