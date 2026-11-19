/*
 * rvm.c — ARMv7-A(ARM 态)指令集模拟器 + 故障注入仿真器
 *
 * 功能:
 *   1. 加载 lld 链接出的 ELF32 固件,解释执行 ARMv7(ARM 态)指令子集;
 *   2. 故障注入:
 *      - 指令跳过:把指定地址的指令替换为 NOP(每次取指命中都跳过,
 *        等价于攻击者可在该指令的任意一次执行时下毛刺,从严建模);
 *      - 寄存器比特翻转:在第 N 条已执行指令之前,翻转 r0-r14 的任意
 *        比特,或 CPSR 的 N/Z/C/V 标志位;
 *   3. 注入战役(campaign):
 *      - skip1:枚举 .text 内每条指令,单跳过;
 *      - skip2:枚举所有指令对,双跳过;
 *      - flip1:枚举 (指令步数 × 寄存器 × 比特),单比特翻转;
 *      统计有多少种注入能把"密钥错误 -> 拒绝"翻成"误放行"。
 *
 * 门锁建模(与固件约定一致):写 DOOR_ARM 后紧接着写 DOOR_OPEN 才算开门
 * (开门状态锁存);其他写入解除 armed。超时/非法访存/未实现指令一律
 * 按"未放行"计(安全侧)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include "door.h"

/* ---------------- 内存映射 ---------------- */
#define ROM_BASE   0x00000000u
#define ROM_SIZE   0x00100000u
#define RAM_BASE   0x10000000u
#define RAM_SIZE   0x00100000u
#define CARD_BASE  0x20000000u
#define CARD_SIZE  0x100u
#define MMIO_DOOR  0x40000000u
#define MMIO_EXIT  0x40000004u

#define MAX_INSN   2000000u   /* 单次运行的指令数上限,超过判超时 */

static uint8_t rom[ROM_SIZE];
static uint8_t ram[RAM_SIZE];
static uint8_t card_buf[CARD_SIZE];

/* ---------------- CPU 状态 ---------------- */
static uint32_t R[15];            /* r0-r14,r15(pc) 单独存放 */
static uint32_t pc;
static uint32_t flgN, flgZ, flgC, flgV;
static int      pc_written;

/* ---------------- 故障注入配置 ---------------- */
static uint32_t f_skip1 = 0xFFFFFFFFu, f_skip2 = 0xFFFFFFFFu;
static int64_t  f_flip_step = -1;
static int      f_flip_reg = 0, f_flip_bit = 0;

/* ---------------- 运行状态 ---------------- */
static int      halted, mem_fault, unimpl;
static uint64_t icount;
static int      door_armed, door_opened;
static uint64_t trace_left;
static uint32_t text_lo = 0xFFFFFFFFu, text_hi = 0;
static uint32_t elf_entry;

/* ---------------- 内存访问 ---------------- */
static int mem_read(uint32_t a, uint32_t *v, int size)
{
    uint32_t r = 0;
    for (int i = 0; i < size; i++) {
        uint32_t ad = a + (uint32_t)i, b;
        if      (ad < ROM_SIZE)                          b = rom[ad];
        else if (ad >= RAM_BASE && ad < RAM_BASE + RAM_SIZE) b = ram[ad - RAM_BASE];
        else if (ad >= CARD_BASE && ad < CARD_BASE + CARD_SIZE) b = card_buf[ad - CARD_BASE];
        else if (ad == MMIO_DOOR)                        b = (uint32_t)door_armed;
        else return -1;
        r |= b << (8 * i);
    }
    *v = r;
    return 0;
}

static int mem_write(uint32_t a, uint32_t v, int size)
{
    if (a == MMIO_DOOR && size == 4) {
        if (v == DOOR_ARM) door_armed = 1;
        else if (v == DOOR_OPEN && door_armed) door_opened = 1;
        else door_armed = 0;
        return 0;
    }
    if (a == MMIO_EXIT && size == 4) { halted = 1; return 0; }
    for (int i = 0; i < size; i++) {
        uint32_t ad = a + (uint32_t)i;
        if (ad >= RAM_BASE && ad < RAM_BASE + RAM_SIZE)
            ram[ad - RAM_BASE] = (uint8_t)(v >> (8 * i));
        else if (ad >= CARD_BASE && ad < CARD_BASE + CARD_SIZE)
            card_buf[ad - CARD_BASE] = (uint8_t)(v >> (8 * i));
        else
            return -1;   /* ROM 只读、其余地址非法 */
    }
    return 0;
}

static uint32_t mem_rd32(uint32_t a) { uint32_t v; if (mem_read(a, &v, 4)) { mem_fault = 1; return 0; } return v; }
static uint32_t mem_rd16(uint32_t a) { uint32_t v; if (mem_read(a, &v, 2)) { mem_fault = 1; return 0; } return v; }
static uint32_t mem_rd8 (uint32_t a) { uint32_t v; if (mem_read(a, &v, 1)) { mem_fault = 1; return 0; } return v; }
static void mem_wr32(uint32_t a, uint32_t v) { if (mem_write(a, v, 4)) mem_fault = 1; }
static void mem_wr16(uint32_t a, uint32_t v) { if (mem_write(a, v, 2)) mem_fault = 1; }
static void mem_wr8 (uint32_t a, uint32_t v) { if (mem_write(a, v, 1)) mem_fault = 1; }

/* ---------------- 寄存器读写(r15 特殊) ---------------- */
static uint32_t rd_reg(int i) { return i == 15 ? pc + 8 : R[i]; }
static void wr_reg(int i, uint32_t v)
{
    if (i == 15) {
        if (v & 3) { unimpl = 1; return; }   /* 不支持 Thumb 态切换 */
        pc = v; pc_written = 1;
    } else R[i] = v;
}

/* ---------------- 条件码 ---------------- */
static int cond_ok(uint32_t c)
{
    switch (c) {
    case 0: return flgZ;            case 1: return !flgZ;
    case 2: return flgC;            case 3: return !flgC;
    case 4: return flgN;            case 5: return !flgN;
    case 6: return flgV;            case 7: return !flgV;
    case 8: return flgC && !flgZ;   case 9: return !flgC || flgZ;
    case 10: return flgN == flgV;   case 11: return flgN != flgV;
    case 12: return !flgZ && (flgN == flgV);
    case 13: return flgZ || (flgN != flgV);
    case 14: return 1;
    default: return 0;
    }
}

/* ---------------- 移位器 ---------------- */
static uint32_t ror32(uint32_t v, int n) { n &= 31; return n ? (v >> n) | (v << (32 - n)) : v; }

static uint32_t shift_imm(uint32_t v, int type, int amt, uint32_t *cout)
{
    switch (type) {
    case 0: /* LSL */
        if (amt == 0) { *cout = flgC; return v; }
        *cout = (v >> (32 - amt)) & 1; return v << amt;
    case 1: /* LSR */
        if (amt == 0) amt = 32;
        *cout = (v >> (amt - 1)) & 1;
        return amt == 32 ? 0 : v >> amt;
    case 2: /* ASR */
        if (amt == 0) amt = 32;
        *cout = (uint32_t)((int32_t)v >> (amt - 1)) & 1;
        return amt == 32 ? (uint32_t)((int32_t)v >> 31) : (uint32_t)((int32_t)v >> amt);
    default: /* ROR / RRX */
        if (amt == 0) {
            uint32_t c = v & 1;
            uint32_t r = (v >> 1) | (flgC << 31);
            *cout = c; return r;
        }
        *cout = (v >> (amt - 1)) & 1;
        return ror32(v, amt);
    }
}

static uint32_t shift_reg(uint32_t v, int type, uint32_t amt, uint32_t *cout)
{
    if (amt == 0) { *cout = flgC; return v; }
    switch (type) {
    case 0:
        if (amt < 32)  { *cout = (v >> (32 - amt)) & 1; return v << amt; }
        if (amt == 32) { *cout = v & 1; return 0; }
        *cout = 0; return 0;
    case 1:
        if (amt < 32)  { *cout = (v >> (amt - 1)) & 1; return v >> amt; }
        if (amt == 32) { *cout = (v >> 31) & 1; return 0; }
        *cout = 0; return 0;
    case 2:
        if (amt < 32)  { *cout = (uint32_t)((int32_t)v >> (amt - 1)) & 1;
                         return (uint32_t)((int32_t)v >> amt); }
        *cout = (v >> 31) & 1; return (uint32_t)((int32_t)v >> 31);
    default:
        amt &= 31;
        if (amt == 0)  { *cout = (v >> 31) & 1; return v; }
        *cout = (v >> (amt - 1)) & 1; return ror32(v, amt);
    }
}

static void set_nz(uint32_t r) { flgN = (r >> 31) & 1; flgZ = (r == 0); }

/* ---------------- 数据处理 ---------------- */
static void exec_dp(uint32_t insn)
{
    int I = (insn >> 25) & 1, S = (insn >> 20) & 1;
    int opc = (insn >> 21) & 0xF;
    int rn = (insn >> 16) & 0xF, rd = (insn >> 12) & 0xF;
    uint32_t op2, scout = flgC;

    if (I) {
        uint32_t imm8 = insn & 0xFF;
        int rot = ((insn >> 8) & 0xF) * 2;
        if (rot) { op2 = ror32(imm8, rot); scout = (op2 >> 31) & 1; }
        else op2 = imm8;
    } else {
        uint32_t v = rd_reg(insn & 0xF);
        if (insn & 0x10) {
            uint32_t amt = rd_reg((insn >> 8) & 0xF) & 0xFF;
            op2 = shift_reg(v, (insn >> 5) & 3, amt, &scout);
        } else {
            op2 = shift_imm(v, (insn >> 5) & 3, (insn >> 7) & 0x1F, &scout);
        }
    }

    uint32_t a = rd_reg(rn), res = 0;
    uint32_t c_out = flgC, v_out = flgV;
    int write_rd = 1, arith = 0;
    int64_t s;
    uint64_t wide, sub;

    switch (opc) {
    case 0:  res = a & op2; break;                                  /* AND */
    case 1:  res = a ^ op2; break;                                  /* EOR */
    case 2:  case 10:                                               /* SUB/CMP */
        res = a - op2; c_out = (a >= op2);
        s = (int64_t)(int32_t)a - (int64_t)(int32_t)op2;
        v_out = (s < INT32_MIN || s > INT32_MAX); arith = 1; break;
    case 3:                                                         /* RSB */
        res = op2 - a; c_out = (op2 >= a);
        s = (int64_t)(int32_t)op2 - (int64_t)(int32_t)a;
        v_out = (s < INT32_MIN || s > INT32_MAX); arith = 1; break;
    case 4:  case 11:                                               /* ADD/CMN */
        wide = (uint64_t)a + op2; res = (uint32_t)wide;
        c_out = (uint32_t)(wide >> 32);
        s = (int64_t)(int32_t)a + (int64_t)(int32_t)op2;
        v_out = (s < INT32_MIN || s > INT32_MAX); arith = 1; break;
    case 5:                                                         /* ADC */
        wide = (uint64_t)a + op2 + flgC; res = (uint32_t)wide;
        c_out = (uint32_t)(wide >> 32);
        s = (int64_t)(int32_t)a + (int64_t)(int32_t)op2 + flgC;
        v_out = (s < INT32_MIN || s > INT32_MAX); arith = 1; break;
    case 6:                                                         /* SBC */
        sub = (uint64_t)op2 + (1 - flgC);
        res = a - (uint32_t)sub; c_out = ((uint64_t)a >= sub);
        s = (int64_t)(int32_t)a - (int64_t)(int32_t)op2 - (1 - flgC);
        v_out = (s < INT32_MIN || s > INT32_MAX); arith = 1; break;
    case 7:                                                         /* RSC */
        sub = (uint64_t)a + (1 - flgC);
        res = op2 - (uint32_t)sub; c_out = ((uint64_t)op2 >= sub);
        s = (int64_t)(int32_t)op2 - (int64_t)(int32_t)a - (1 - flgC);
        v_out = (s < INT32_MIN || s > INT32_MAX); arith = 1; break;
    case 8:  res = a & op2; write_rd = 0; break;                    /* TST */
    case 9:  res = a ^ op2; write_rd = 0; break;                    /* TEQ */
    case 12: res = a | op2; break;                                  /* ORR */
    case 13: res = op2; break;                                      /* MOV */
    case 14: res = a & ~op2; break;                                 /* BIC */
    case 15: res = ~op2; break;                                     /* MVN */
    }
    if (opc == 10 || opc == 11) write_rd = 0;

    if (S || !write_rd) {
        if (arith) { flgC = c_out; flgV = v_out; }
        else flgC = scout;
        set_nz(res);
    }
    if (write_rd) wr_reg(rd, res);
}

/* ---------------- 单寄存器 load/store ---------------- */
static void exec_ls(uint32_t insn)
{
    int I = (insn >> 25) & 1, P = (insn >> 24) & 1, U = (insn >> 23) & 1;
    int B = (insn >> 22) & 1, W = (insn >> 21) & 1, L = (insn >> 20) & 1;
    int rn = (insn >> 16) & 0xF, rd = (insn >> 12) & 0xF;
    uint32_t off, sc;

    if (!I) off = insn & 0xFFF;
    else    off = shift_imm(rd_reg(insn & 0xF), (insn >> 5) & 3, (insn >> 7) & 0x1F, &sc);

    uint32_t base = rd_reg(rn);
    uint32_t addr = P ? (U ? base + off : base - off) : base;

    if (L) {
        uint32_t v = B ? mem_rd8(addr) : mem_rd32(addr);
        wr_reg(rd, v);
    } else {
        uint32_t v = rd_reg(rd);
        if (B) mem_wr8(addr, v & 0xFF); else mem_wr32(addr, v);
    }
    if (!P || W) {
        if (!(L && rd == rn))
            wr_reg(rn, U ? base + off : base - off);
    }
}

/* ---------------- 半字/有符号 load/store ---------------- */
static void exec_extra_ls(uint32_t insn)
{
    int P = (insn >> 24) & 1, U = (insn >> 23) & 1, I = (insn >> 22) & 1;
    int W = (insn >> 21) & 1, L = (insn >> 20) & 1;
    int rn = (insn >> 16) & 0xF, rd = (insn >> 12) & 0xF;
    int SH = (insn >> 5) & 3;
    uint32_t off;

    if (I) off = ((insn >> 4) & 0xF0) | (insn & 0xF);
    else   off = rd_reg(insn & 0xF);

    uint32_t base = rd_reg(rn);
    uint32_t addr = P ? (U ? base + off : base - off) : base;

    if (L) {
        uint32_t v;
        switch (SH) {
        case 1: v = mem_rd16(addr); break;                          /* LDRH */
        case 2: v = (uint32_t)(int32_t)(int8_t)mem_rd8(addr); break;/* LDRSB */
        case 3: v = (uint32_t)(int32_t)(int16_t)mem_rd16(addr); break;/* LDRSH */
        default: unimpl = 1; return;
        }
        wr_reg(rd, v);
    } else {
        if (SH != 1) { unimpl = 1; return; }
        mem_wr16(addr, rd_reg(rd) & 0xFFFF);                        /* STRH */
    }
    if (!P || W) {
        if (!(L && rd == rn))
            wr_reg(rn, U ? base + off : base - off);
    }
}

/* ---------------- 批量 load/store(push/pop) ---------------- */
static void exec_lsm(uint32_t insn)
{
    int P = (insn >> 24) & 1, U = (insn >> 23) & 1;
    int W = (insn >> 21) & 1, L = (insn >> 20) & 1;
    int rn = (insn >> 16) & 0xF;
    uint32_t list = insn & 0xFFFF;
    uint32_t n = (uint32_t)__builtin_popcount(list);
    uint32_t base = rd_reg(rn), addr;

    if (U) addr = P ? base + 4 : base;
    else   addr = P ? base - 4u * n : base - 4u * n + 4;

    for (int i = 0; i < 16; i++) {
        if (!(list & (1u << i))) continue;
        if (L) wr_reg(i, mem_rd32(addr));
        else   mem_wr32(addr, rd_reg(i));
        addr += 4;
    }
    if (W) wr_reg(rn, U ? base + 4u * n : base - 4u * n);
}

/* ---------------- 符号扩展 ---------------- */
static void exec_extend(uint32_t insn)
{
    uint32_t kind = insn & 0x0FFF00F0u;
    int rd = (insn >> 12) & 0xF;
    uint32_t v = ror32(rd_reg(insn & 0xF), ((insn >> 8) & 0xF) * 8);
    switch (kind) {
    case 0x06AF0070u: wr_reg(rd, (uint32_t)(int32_t)(int8_t)v);  break; /* SXTB */
    case 0x06EF0070u: wr_reg(rd, v & 0xFF);                      break; /* UXTB */
    case 0x06BF0070u: wr_reg(rd, (uint32_t)(int32_t)(int16_t)v); break; /* SXTH */
    case 0x06FF0030u: wr_reg(rd, v & 0xFFFF);                    break; /* UXTH */
    default: unimpl = 1;
    }
}

/* ---------------- 单步执行 ---------------- */
static void step(void)
{
    uint32_t insn = mem_rd32(pc);
    if (mem_fault) return;
    if (trace_left) { printf("  %08x: %08x\n", pc, insn); trace_left--; }
    pc_written = 0;

    if (!cond_ok(insn >> 28)) { pc += 4; return; }

    if ((insn & 0x0FFFFFF0u) == 0x012FFF10u) {              /* BX */
        uint32_t t = rd_reg(insn & 0xF);
        if (t & 3) { unimpl = 1; return; }
        pc = t; pc_written = 1;
    } else if ((insn & 0x0FFFFFF0u) == 0x012FFF30u) {       /* BLX reg */
        uint32_t t = rd_reg(insn & 0xF);
        wr_reg(14, pc + 4);
        if (t & 3) { unimpl = 1; return; }
        pc = t; pc_written = 1;
    } else if ((insn & 0x0FF000F0u) == 0x01200070u) {       /* BKPT */
        halted = 1;
    } else if ((insn & 0x0FC000F0u) == 0x00000090u) {       /* MUL/MLA */
        int A = (insn >> 21) & 1, S = (insn >> 20) & 1;
        int rd = (insn >> 16) & 0xF, rn = (insn >> 12) & 0xF;
        uint32_t res = rd_reg(insn & 0xF) * rd_reg((insn >> 8) & 0xF);
        if (A) res += rd_reg(rn);
        if (S) set_nz(res);
        wr_reg(rd, res);
    } else if ((insn & 0x0FB00FF0u) == 0x01000090u) {       /* SWP */
        unimpl = 1;
    } else switch ((insn >> 25) & 7) {
    case 0: case 1:
        if ((insn & 0x0E000090u) == 0x00000090u) exec_extra_ls(insn);
        else if ((insn & 0x0FF00000u) == 0x03000000u) {     /* MOVW */
            wr_reg((insn >> 12) & 0xF, ((insn >> 16) & 0xF) << 12 | (insn & 0xFFF));
        }
        else if ((insn & 0x0FF00000u) == 0x03400000u) {     /* MOVT */
            int rd = (insn >> 12) & 0xF;
            uint32_t imm16 = ((insn >> 16) & 0xF) << 12 | (insn & 0xFFF);
            wr_reg(rd, (rd_reg(rd) & 0xFFFF) | (imm16 << 16));
        }
        else if ((insn & 0x0FFF0FF0u) == 0x016F0F10u) {     /* CLZ */
            uint32_t v = rd_reg(insn & 0xF);
            wr_reg((insn >> 12) & 0xF, v ? (uint32_t)__builtin_clz(v) : 32);
        }
        else exec_dp(insn);
        break;
    case 2: case 3:
        if ((insn & 0x0FFF00F0u) == 0x06AF0070u ||          /* SXTB */
            (insn & 0x0FFF00F0u) == 0x06EF0070u ||          /* UXTB */
            (insn & 0x0FFF00F0u) == 0x06BF0070u ||          /* SXTH */
            (insn & 0x0FFF00F0u) == 0x06FF0030u)            /* UXTH */
            exec_extend(insn);
        else
            exec_ls(insn);
        break;
    case 4: exec_lsm(insn); break;
    case 5: {                                               /* B/BL */
        if (insn & (1u << 24)) wr_reg(14, pc + 4);
        int32_t off = (int32_t)(insn << 8) >> 6;
        pc = pc + 8 + (uint32_t)off; pc_written = 1;
        break;
    }
    case 7:
        if ((insn & 0x0F000000u) == 0x0F000000u) halted = 1; /* SVC */
        else unimpl = 1;
        break;
    default:
        unimpl = 1;
    }

    if (!pc_written && !halted && !unimpl && !mem_fault) pc += 4;
}

/* ---------------- ELF 加载 ---------------- */
static uint16_t rd16le(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32le(const uint8_t *p) { return p[0] | p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static int load_elf(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    static uint8_t buf[1 << 20];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n < 52 || memcmp(buf, "\x7f""ELF", 4) || buf[4] != 1 || buf[5] != 1) {
        fprintf(stderr, "不是 ELF32 LE 文件\n"); return -1;
    }
    if (rd16le(buf + 18) != 40) { fprintf(stderr, "不是 ARM ELF\n"); return -1; }
    elf_entry = rd32le(buf + 24);
    uint32_t phoff = rd32le(buf + 28), shoff = rd32le(buf + 32);
    uint16_t phentsize = rd16le(buf + 42), phnum = rd16le(buf + 44);
    uint16_t shentsize = rd16le(buf + 46), shnum = rd16le(buf + 48);
    uint16_t shstrndx = rd16le(buf + 50);

    for (int i = 0; i < phnum; i++) {
        const uint8_t *ph = buf + phoff + (uint32_t)i * phentsize;
        if (rd32le(ph) != 1) continue;   /* PT_LOAD */
        uint32_t off = rd32le(ph + 4), paddr = rd32le(ph + 12);
        uint32_t filesz = rd32le(ph + 16), memsz = rd32le(ph + 20);
        if (paddr < ROM_SIZE && filesz) {
            if (paddr + filesz > ROM_SIZE) { fprintf(stderr, "段超出 ROM\n"); return -1; }
            memcpy(rom + paddr, buf + off, filesz);
        } else if (paddr >= RAM_BASE && paddr + memsz <= RAM_BASE + RAM_SIZE) {
            if (filesz) memcpy(ram + paddr - RAM_BASE, buf + off, filesz);
        } else if (memsz) {
            fprintf(stderr, "未知段地址 %#x\n", paddr); return -1;
        }
    }
    /* 找 .text 范围(注入枚举用) */
    if (shoff && shstrndx < shnum) {
        const uint8_t *shstr = buf + shoff + (uint32_t)shstrndx * shentsize;
        const char *strtab = (const char *)buf + rd32le(shstr + 16);
        for (int i = 0; i < shnum; i++) {
            const uint8_t *sh = buf + shoff + (uint32_t)i * shentsize;
            const char *name = strtab + rd32le(sh);
            if (!strcmp(name, ".text")) {
                text_lo = rd32le(sh + 12);
                text_hi = text_lo + rd32le(sh + 20);
            }
        }
    }
    if (text_lo >= text_hi) { fprintf(stderr, "找不到 .text\n"); return -1; }
    return 0;
}

/* ---------------- 单次运行 ---------------- */
enum { RES_LOCKED, RES_OPENED, RES_TIMEOUT, RES_MEMFAULT, RES_UNIMPL };

static int run_once(const uint8_t *key, uint64_t *cycles)
{
    memset(ram, 0, RAM_SIZE);
    memset(R, 0, sizeof R);
    memset(card_buf, 0, CARD_SIZE);
    memcpy(card_buf, key, KEY_LEN);
    pc = elf_entry;
    R[13] = RAM_BASE + RAM_SIZE - 16;   /* sp */
    flgN = flgZ = flgC = flgV = 0;
    halted = mem_fault = unimpl = 0;
    door_armed = door_opened = 0;
    icount = 0;

    while (!halted && !mem_fault && !unimpl) {
        if (icount >= MAX_INSN) return RES_TIMEOUT;
        if (pc == f_skip1 || pc == f_skip2) { pc += 4; continue; }
        if ((int64_t)icount == f_flip_step) {
            if (f_flip_reg < 15) {
                R[f_flip_reg] ^= (1u << f_flip_bit);
            } else {   /* reg 15 表示 CPSR 标志位(只用 28-31) */
                if (f_flip_bit == 31) flgN ^= 1;
                if (f_flip_bit == 30) flgZ ^= 1;
                if (f_flip_bit == 29) flgC ^= 1;
                if (f_flip_bit == 28) flgV ^= 1;
            }
        }
        step();
        icount++;
    }
    if (cycles) *cycles = icount;
    if (mem_fault) return RES_MEMFAULT;
    if (unimpl)    return RES_UNIMPL;
    return door_opened ? RES_OPENED : RES_LOCKED;
}

/* ---------------- 注入战役统计 ---------------- */
#define MAX_WRONG_KEYS 8
#define MAX_LISTED     20

static uint8_t good_key[KEY_LEN];
static uint8_t wrong_keys[MAX_WRONG_KEYS][KEY_LEN];
static int n_wrong = 5;

static uint64_t st_total, st_open, st_timeout, st_memfault, st_unimpl;
static char st_listed[MAX_LISTED][128];
static int st_nlisted;

static void tally(int res, const char *fmt, ...)
{
    st_total++;
    if (res == RES_OPENED) {
        st_open++;
        if (st_nlisted < MAX_LISTED) {
            va_list ap; va_start(ap, fmt);
            vsnprintf(st_listed[st_nlisted++], sizeof st_listed[0], fmt, ap);
            va_end(ap);
        }
    }
    else if (res == RES_TIMEOUT)   st_timeout++;
    else if (res == RES_MEMFAULT)  st_memfault++;
    else if (res == RES_UNIMPL)    st_unimpl++;
}

static void reset_stats(void)
{
    st_total = st_open = st_timeout = st_memfault = st_unimpl = 0;
    st_nlisted = 0;
}

static void print_stats(void)
{
    printf("  注入总数: %" PRIu64 "\n", st_total);
    printf("  误放行:   %" PRIu64, st_open);
    if (st_open == 0) printf("  (0 —— 该故障模型下未观察到误放行)");
    printf("\n");
    printf("  (超时 %" PRIu64 " / 访存故障 %" PRIu64 " / 未实现指令 %" PRIu64 ",均按安全侧计)\n",
           st_timeout, st_memfault, st_unimpl);
    for (int i = 0; i < st_nlisted; i++)
        printf("    [误放行样例] %s\n", st_listed[i]);
    if (st_open > MAX_LISTED)
        printf("    …… 其余 %" PRIu64 " 条从略\n", st_open - MAX_LISTED);
}

static void gen_wrong_keys(void)
{
    memset(wrong_keys[0], 0x00, KEY_LEN);
    memset(wrong_keys[1], 0xFF, KEY_LEN);
    memcpy(wrong_keys[2], good_key, KEY_LEN); wrong_keys[2][0] ^= 0x01;
    memcpy(wrong_keys[3], good_key, KEY_LEN); wrong_keys[3][KEY_LEN - 1] ^= 0xFF;
    uint32_t x = 0x12345678u;
    for (int i = 0; i < KEY_LEN; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        wrong_keys[4][i] = (uint8_t)x;
    }
    if (!memcmp(wrong_keys[4], good_key, KEY_LEN)) wrong_keys[4][0] ^= 1;
}

/* ---------------- 常量自检 ---------------- */
static int popcount32(uint32_t v) { return __builtin_popcount(v); }

static int check_constants(void)
{
    static const uint32_t Sx[4] = { S1, S2, S3, S4 };
    static const uint32_t Ux[3] = { U1, U2, U3 };
    int bad = 0;

    /* 所有非空子集异或的汉明重量 >= 2 */
    for (int mask = 1; mask < 16; mask++) {
        uint32_t x = 0;
        for (int i = 0; i < 4; i++) if (mask & (1 << i)) x ^= Sx[i];
        if (popcount32(x) < 2) { printf("  [自检失败] S 子集 %#x 重量 %d\n", mask, popcount32(x)); bad = 1; }
    }
    for (int mask = 1; mask < 8; mask++) {
        uint32_t x = 0;
        for (int i = 0; i < 3; i++) if (mask & (1 << i)) x ^= Ux[i];
        if (popcount32(x) < 2) { printf("  [自检失败] U 子集 %#x 重量 %d\n", mask, popcount32(x)); bad = 1; }
    }
    /* 拒绝态 any = C:C 及其单比特邻居远离危险值 */
    uint32_t C = (S1 ^ S2 ^ S3 ^ S4) | (U1 ^ U2 ^ U3);
    if (popcount32(C) < 2 || C == 0xFFFFFFFFu || C == 0x80000000u) {
        printf("  [自检失败] C=%#x\n", C); bad = 1;
    }
    for (int k = 0; k < 32; k++) {
        uint32_t c2 = C ^ (1u << k);
        if (c2 == 0 || c2 == 0x80000000u || c2 == 0xFFFFFFFFu) {
            printf("  [自检失败] C^2^%d 危险\n", k); bad = 1;
        }
    }
    /* 门磁值距离 */
    if (popcount32(DOOR_OPEN ^ DOOR_LOCK) < 2) { printf("  [自检失败] OPEN/LOCK 距离\n"); bad = 1; }
    if (popcount32(DOOR_OPEN ^ DOOR_ARM)  < 2) { printf("  [自检失败] OPEN/ARM 距离\n");  bad = 1; }

    if (!bad) printf("  常量自检通过(令牌子集距离>=2,拒绝态远离危险值,门磁值距离足够)\n");
    return bad;
}

/* ---------------- 战役 ---------------- */
static uint64_t baseline_cycles(void)
{
    uint64_t mx = 0;
    for (int k = 0; k < n_wrong; k++) {
        uint64_t c;
        f_skip1 = f_skip2 = 0xFFFFFFFFu; f_flip_step = -1;
        run_once(wrong_keys[k], &c);
        if (c > mx) mx = c;
    }
    return mx;
}

static void campaign_functional(void)
{
    printf("[功能测试] 无故障注入\n");
    f_skip1 = f_skip2 = 0xFFFFFFFFu; f_flip_step = -1;
    uint64_t c;
    int r = run_once(good_key, &c);
    printf("  正确密钥   -> %s (周期 %" PRIu64 ") %s\n",
           r == RES_OPENED ? "放行" : "拒绝", c,
           r == RES_OPENED ? "[通过]" : "[失败:拒真!]");
    for (int k = 0; k < n_wrong; k++) {
        r = run_once(wrong_keys[k], &c);
        printf("  错误密钥#%d -> %s (周期 %" PRIu64 ") %s\n", k,
               r == RES_OPENED ? "放行" : "拒绝", c,
               r == RES_LOCKED ? "[通过]" : "[失败:纳伪!]");
    }
}

static void campaign_skip1(void)
{
    printf("[skip1] 单指令跳过(枚举 .text 全部 %" PRIu32 " 条指令 x %d 种错误密钥)\n",
           (text_hi - text_lo) / 4, n_wrong);
    reset_stats();
    for (uint32_t a = text_lo; a < text_hi; a += 4) {
        for (int k = 0; k < n_wrong; k++) {
            f_skip1 = a; f_skip2 = 0xFFFFFFFFu; f_flip_step = -1;
            tally(run_once(wrong_keys[k], 0), "跳过 @%#x, 密钥#%d", a, k);
        }
    }
    print_stats();
}

static void campaign_skip2(void)
{
    uint32_t n = (text_hi - text_lo) / 4;
    printf("[skip2] 双指令跳过(枚举 %" PRIu32 " 对指令 x %d 种错误密钥)\n",
           n * (n - 1) / 2, n_wrong);
    reset_stats();
    for (uint32_t a = text_lo; a < text_hi; a += 4) {
        for (uint32_t b = a + 4; b < text_hi; b += 4) {
            for (int k = 0; k < n_wrong; k++) {
                f_skip1 = a; f_skip2 = b; f_flip_step = -1;
                tally(run_once(wrong_keys[k], 0), "跳过 @%#x + @%#x, 密钥#%d", a, b, k);
            }
        }
    }
    print_stats();
}

static void campaign_flip1(uint64_t baseline)
{
    printf("[flip1] 单比特翻转(枚举 步数<%" PRIu64 " x 16 寄存器 x 32 比特 x %d 种错误密钥;reg15=CPSR 仅 NZCV)\n",
           baseline, n_wrong);
    reset_stats();
    f_skip1 = f_skip2 = 0xFFFFFFFFu;
    for (uint64_t s = 0; s < baseline; s++) {
        for (int reg = 0; reg < 16; reg++) {
            int b0 = (reg == 15) ? 28 : 0;
            for (int bit = b0; bit < 32; bit++) {
                for (int k = 0; k < n_wrong; k++) {
                    f_flip_step = (int64_t)s; f_flip_reg = reg; f_flip_bit = bit;
                    tally(run_once(wrong_keys[k], 0),
                          "翻转 第%" PRIu64 "步 r%d bit%d, 密钥#%d", s, reg, bit, k);
                }
            }
        }
    }
    f_flip_step = -1;
    print_stats();
}

/* ---------------- main ---------------- */
static int parse_hex_key(const char *s, uint8_t *out)
{
    if (strlen(s) != (size_t)KEY_LEN * 2) return -1;
    for (int i = 0; i < KEY_LEN; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *elf = 0, *mode = "all", *keyhex = 0;
    int do_trace = 0;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--mode=", 7)) mode = argv[i] + 7;
        else if (!strncmp(argv[i], "--good-key=", 11)) keyhex = argv[i] + 11;
        else if (!strncmp(argv[i], "--trace=", 8)) do_trace = atoi(argv[i] + 8);
        else if (!strncmp(argv[i], "--keys=", 7)) { /* 保留 */ }
        else if (argv[i][0] != '-') elf = argv[i];
        else { fprintf(stderr, "未知参数 %s\n", argv[i]); return 2; }
    }
    if (!elf) {
        fprintf(stderr, "用法: rvm <firmware.elf> --good-key=<16hex> [--mode=functional|skip1|skip2|flip1|all] [--trace=N]\n");
        return 2;
    }
    static const uint8_t ref_default[KEY_LEN] = REF_KEY_INIT;
    if (keyhex) {
        if (parse_hex_key(keyhex, good_key)) { fprintf(stderr, "密钥格式错误\n"); return 2; }
    } else {
        memcpy(good_key, ref_default, KEY_LEN);
    }
    gen_wrong_keys();

    printf("== 加载固件 %s ==\n", elf);
    if (load_elf(elf)) return 1;
    printf("  入口 %#x,.text [%#x, %#x) 共 %" PRIu32 " 字节 / %" PRIu32 " 条指令\n",
           elf_entry, text_lo, text_hi, text_hi - text_lo, (text_hi - text_lo) / 4);

    printf("== 加固常量自检 ==\n");
    if (check_constants()) return 1;

    trace_left = (uint64_t)do_trace;
    if (do_trace) { f_skip1 = f_skip2 = 0xFFFFFFFFu; f_flip_step = -1; run_once(good_key, 0); return 0; }

    uint64_t base = baseline_cycles();
    printf("== 无故障基线:错误密钥运行周期 %" PRIu64 " ==\n", base);

    if (!strcmp(mode, "functional") || !strcmp(mode, "all")) campaign_functional();
    if (!strcmp(mode, "skip1") || !strcmp(mode, "all")) campaign_skip1();
    if (!strcmp(mode, "skip2") || !strcmp(mode, "all")) campaign_skip2();
    if (!strcmp(mode, "flip1") || !strcmp(mode, "all")) campaign_flip1(base);
    return 0;
}
