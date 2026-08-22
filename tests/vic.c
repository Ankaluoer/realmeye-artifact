/* vic.c — RealmEye A/B/C 时机演示的受控测试进程。
 *
 * 它在收到信号时切换自己的 real uid：
 *   SIGUSR1 -> 降为非 root (real uid = 1000)   ← "藏"
 *   SIGUSR2 -> 回到 root   (real uid = 0)       ← "提权"
 *
 * 这不是 rootkit：只用 setresuid 改自己的凭据（标准的降权/复权，
 * 保留 saved uid = 0 以便返回 0），不 hook、不隐藏、不触碰其它进程。
 * 必须以 root 启动，saved uid 才会是 0。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t want_root = 1;

static void on_hide(int s){ (void)s; want_root = 0; }  /* USR1: 降为非 root */
static void on_show(int s){ (void)s; want_root = 1; }  /* USR2: 回到 root   */

int main(void)
{
    signal(SIGUSR1, on_hide);
    signal(SIGUSR2, on_show);

    setresuid(0, 0, 0);                 /* 以 root 起步，saved uid = 0 */
    printf("vic pid=%d start uid=%d\n", getpid(), (int)getuid());
    fflush(stdout);

    int last = -1;
    for (;;) {
        if (want_root && getuid() != 0) {
            setresuid(0, 0, 0);         /* saved uid=0，可以回到 0 */
        } else if (!want_root && getuid() == 0) {
            setresuid(1000, 1000, 0);   /* real/euid=1000，保留 saved=0 */
        }
        int cur = (int)getuid();
        if (cur != last) {
            printf("vic pid=%d uid=%d\n", getpid(), cur);
            fflush(stdout);
            last = cur;
        }
        usleep(100000);                 /* 100ms 轮询 */
    }
    return 0;
}
