/*
 * door.h — 门禁固件与故障仿真器共享的常量定义
 *
 * 内存映射(仿真环境):
 *   0x00000000  ROM(固件 .text/.rodata,只读)
 *   0x10000000  RAM(栈、.data/.bss)
 *   0x20000000  卡片密钥缓冲区(读卡器硬件写入,固件只读)
 *   0x40000000  门锁执行机构 MMIO(arm/fire 状态机)
 *   0x40000004  退出端口(写任意值 = 固件流程结束,仿真停机)
 */
#ifndef DOOR_H
#define DOOR_H

#include <stdint.h>

#define KEY_LEN 8
/* 参考密钥,烧录在固件里(真实设备中存于受保护 Flash) */
#define REF_KEY_INIT { 0x3F, 0x91, 0xA4, 0x5C, 0x77, 0x0B, 0xE2, 0xD8 }
/* 参考密钥的逐字节取反副本,用于运行时完整性校验:
 * 若密钥指针被故障翻转指向他处(如全零内存),b1^b2 != 0xFF 即暴露 */
#define REF_KEY2_INIT { 0xC0, 0x6E, 0x5B, 0xA3, 0x88, 0xF4, 0x1D, 0x27 }

#define CARD_KEY  ((volatile uint8_t  *)0x20000000u)
#define DOOR_PORT ((volatile uint32_t *)0x40000000u)
#define EXIT_PORT ((volatile uint32_t *)0x40000004u)

/*
 * 门锁执行机构协议(硬件状态机,仿真器按同一规则建模):
 *   1. 先写 DOOR_ARM  置为 armed
 *   2. 紧接着写 DOOR_OPEN 才真正开门(开门状态被锁存)
 *   3. 任何其他值写入都会解除 armed
 * DOOR_LOCK 取为 ~DOOR_OPEN,两者汉明距离 32,
 * 单个比特翻转不可能把"锁"值变成"开"值。
 */
#define DOOR_ARM   0xA5A50F0Fu
#define DOOR_OPEN  0xC33C9669u
#define DOOR_LOCK  0x3CC36996u   /* = ~DOOR_OPEN */

/*
 * 加固判定用的令牌常量。
 * token 从 T_BASE 出发,每一路独立比对通过就异或进一个阶段常量;
 * 四路全部通过时 token == TOKEN_GRANT。
 * 所有"非空子集异或"的汉明重量都 >= 2(由仿真器启动时自检),
 * 因此单个寄存器比特翻转不可能把任何中间令牌值翻成 GRANT。
 */
#define T_BASE 0x6B3A91E4u
#define S1     0x9E2C47D1u
#define S2     0x53B8E06Au
#define S3     0xC7F1293Du
#define S4     0x3A6DB482u
#define TOKEN_GRANT (T_BASE ^ S1 ^ S2 ^ S3 ^ S4)

/* 第二枚独立令牌(证据 2),常量与第一枚完全不同 */
#define T2_BASE 0x1F4C8A2Eu
#define U1      0xB73D19C4u
#define U2      0x4A8E6F21u
#define U3      0xD2C593B7u
#define TOKEN2_GRANT (T2_BASE ^ U1 ^ U2 ^ U3)

/* 步进计数器(证据 3):每个阶段无条件累加,少执行一条指令就对不上 */
#define GUARD_BASE   0x00000101u
#define G1           0x1111u
#define G2           0x2222u
#define G3           0x4444u
#define G4           0x8888u
#define GUARD_EXPECT (GUARD_BASE + G1 + G2 + G3 + G4)

#endif /* DOOR_H */
