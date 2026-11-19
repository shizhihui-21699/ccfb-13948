/*
 * auth_hardened.c — 抗电压毛刺(故障注入)加固的门禁关键判断逻辑。
 *
 * 威胁模型(与仿真器一致):
 *   - 攻击者可在任意时刻跳过 1 条或 2 条指令(电压毛刺);
 *   - 或把任意一个通用寄存器(r0-r14)/ CPSR 标志位翻转 1 个比特;
 *   - 目标:让一张密钥错误的卡被放行。
 *
 * 加固手段(组合):
 *   1. 默认拒绝:所有状态初始化为"拒绝",开门需要主动、完整地构造证据;
 *   2. 四路独立比对:前向异或累积 / 反向旋转累积 / 逐字节相等计数 / 再次前向,
 *      指令序列互不相同,单次跳过无法同时废掉两路以上;
 *   3. 无分支掩码累积:比对结果经 0/-1 掩码并入令牌,不给"跳过分支"留目标;
 *   4. 魔法值令牌:GRANT 与一切中间态的汉明距离 >= 2(常量经自检),
 *      单比特翻转无法把拒绝令牌翻成放行令牌;
 *   5. 三证据联合:token、token2、步进计数器 guard 必须同时精确匹配,
 *      证据之间常量不同、计算路径不同;
 *   6. 开门值由证据位流直接算出(无单比特布尔变量),最终写锁值与开门值
 *      汉明距离 32,单比特翻转无法把锁值变成开门值;
 *   7. 执行机构 ARM->FIRE 双写状态机:跳过任何一条写操作都无法开门;
 *   8. 编译屏障防止冗余检查被优化掉。
 */
#include "door.h"

#define BAR()   __asm__ volatile("" ::: "memory")   /* 阻断跨阶段重排/合并 */
#define BARR(x) __asm__ volatile("" : "+r"(x))      /* 阻断对 x 的常量传播/CSE */

static const uint8_t ref_key[KEY_LEN]  = REF_KEY_INIT;
static const uint8_t ref_key2[KEY_LEN] = REF_KEY2_INIT;   /* 取反副本 */

/*
 * 第 1 路:前向异或累积,常数时间。
 * 同时校验参考密钥完整性(b1 ^ ~b1 == 0xFF):
 * 防止密钥指针被比特翻转指向全零/攻击者可控内存后"假密钥比真卡"。
 */
static __attribute__((always_inline)) uint32_t diff_fwd(void)
{
    uint32_t d = 0;
    for (int i = 0; i < KEY_LEN; i++) {
        uint32_t b1 = (uint32_t)ref_key[i];
        uint32_t b2 = (uint32_t)ref_key2[i];
        d |= (uint32_t)CARD_KEY[i] ^ b1;     /* 与卡比对 */
        d |= (b1 ^ b2) ^ 0xFFu;              /* 参考密钥完整性 */
    }
    return d;   /* 0 当且仅当完全匹配且密钥副本完好 */
}

/* 第 2 路:反向 + 旋转混合,刻意使用不同的指令序列 */
static __attribute__((always_inline)) uint32_t diff_rev(void)
{
    uint32_t d = 0;
    for (int i = KEY_LEN - 1; i >= 0; i--) {
        uint32_t x = (uint32_t)CARD_KEY[i] ^ (uint32_t)ref_key[i];
        d = (d << 3) | (d >> 29) | x;
    }
    return d;
}

/* 第 3 路:逐字节相等计数 */
static __attribute__((always_inline)) uint32_t eq_count(void)
{
    uint32_t n = 0;
    for (int i = 0; i < KEY_LEN; i++)
        n += (uint32_t)(CARD_KEY[i] == ref_key[i]);
    return n;   /* == KEY_LEN 当且仅当完全匹配 */
}

__attribute__((section(".text.entry"), used, noreturn))
void _start(void)
{
    uint32_t token  = T_BASE;     /* 证据 1:默认拒绝 */
    uint32_t token2 = T2_BASE;    /* 证据 2:默认拒绝 */
    uint32_t guard  = GUARD_BASE; /* 证据 3:步进计数 */

    /* —— 第 1 遍:前向异或 —— */
    uint32_t d1 = diff_fwd();
    BAR();
    uint32_t m1 = 0u - (uint32_t)(d1 == 0u);   /* 全 1 当且仅当匹配 */
    token ^= S1 & m1;
    guard += G1;
    BAR();

    /* —— 第 2 遍:反向旋转 —— */
    uint32_t d2 = diff_rev();
    uint32_t m2 = 0u - (uint32_t)(d2 == 0u);
    token  ^= S2 & m2;
    token2 ^= U1 & m2;
    guard  += G2;
    BAR();

    /* —— 第 3 遍:相等计数 —— */
    uint32_t n3 = eq_count();
    uint32_t m3 = 0u - (uint32_t)(n3 == (uint32_t)KEY_LEN);
    token  ^= S3 & m3;
    token2 ^= U2 & m3;
    guard  += G3;
    BAR();

    /* —— 第 4 遍:再次前向,独立重算(volatile 读保证不被 CSE) —— */
    uint32_t d4 = diff_fwd();
    uint32_t m4 = 0u - (uint32_t)(d4 == 0u);
    token  ^= S4 & m4;
    token2 ^= U3 & m1;      /* 交叉使用第 1 遍的掩码,增加耦合 */
    guard  += G4;
    BAR();

    /*
     * —— 最终判定 ——
     * 三份证据必须同时精确成立;any == 0 当且仅当全部通过。
     * 不引入任何单比特布尔:开门值由 any 的位模式直接推出。
     *   any == 0  -> w = 0xFFFFFFFF -> out = DOOR_LOCK ^ (OPEN^LOCK) = DOOR_OPEN
     *   any != 0  -> w 最高位为 0   -> out 不可能是 DOOR_OPEN
     * 常量保证拒绝态下 any 及其单比特翻转邻居都远离危险值(见仿真器自检)。
     */
    uint32_t sel  = token  ^ TOKEN_GRANT;   BARR(sel);
    uint32_t sel2 = token2 ^ TOKEN2_GRANT;  BARR(sel2);
    uint32_t sel3 = guard  ^ GUARD_EXPECT;  BARR(sel3);
    uint32_t any  = sel | sel2 | sel3;
    uint32_t w    = ~(any | (0u - any));    /* any==0 时为全 1,否则最高位为 0 */
    BARR(w);
    uint32_t out  = DOOR_LOCK ^ ((DOOR_LOCK ^ DOOR_OPEN) & w);
    BARR(out);

    *DOOR_PORT = DOOR_ARM;   /* 执行机构:先 arm …… */
    *DOOR_PORT = out;        /* …… 再 fire;只有 out==DOOR_OPEN 才开门 */
    *DOOR_PORT = DOOR_LOCK;

    *EXIT_PORT = 0;
    for (;;) { }
}
