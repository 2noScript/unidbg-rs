#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct UnidbgDynarmic UnidbgDynarmic;

UnidbgDynarmic *unidbg_dynarmic_create(int is_64bit);
void unidbg_dynarmic_destroy(UnidbgDynarmic *ctx);

int unidbg_dynarmic_mem_map(UnidbgDynarmic *ctx, uint64_t addr, size_t size, int perm);
int unidbg_dynarmic_mem_unmap(UnidbgDynarmic *ctx, uint64_t addr, size_t size);
int unidbg_dynarmic_mem_read(UnidbgDynarmic *ctx, uint64_t addr, void *buf, size_t size);
int unidbg_dynarmic_mem_write(UnidbgDynarmic *ctx, uint64_t addr, const void *buf, size_t size);

uint64_t unidbg_dynarmic_reg_read(UnidbgDynarmic *ctx, uint32_t reg);
void unidbg_dynarmic_reg_write(UnidbgDynarmic *ctx, uint32_t reg, uint64_t value);

int unidbg_dynarmic_emu_start(UnidbgDynarmic *ctx, uint64_t begin, uint64_t until, size_t count);
void unidbg_dynarmic_emu_stop(UnidbgDynarmic *ctx);

#ifdef __cplusplus
}
#endif
