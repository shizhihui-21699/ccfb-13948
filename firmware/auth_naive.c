/*
 * auth_naive.c — 未加固的对照固件:典型的密钥比对 + 单次判断开门。
 * 用来验证故障仿真器确实能抓到"拒绝被翻成放行"。
 */
#include "door.h"

static const uint8_t ref_key[KEY_LEN] = REF_KEY_INIT;

__attribute__((section(".text.entry"), used, noreturn))
void _start(void)
{
    uint32_t diff = 0;
    for (int i = 0; i < KEY_LEN; i++)
        diff |= (uint32_t)CARD_KEY[i] ^ (uint32_t)ref_key[i];

    if (diff == 0) {                 /* ← 攻击目标:毛刺跳过这个分支即放行 */
        *DOOR_PORT = DOOR_ARM;
        *DOOR_PORT = DOOR_OPEN;
    } else {
        *DOOR_PORT = DOOR_LOCK;
    }

    *EXIT_PORT = 0;
    for (;;) { }
}
