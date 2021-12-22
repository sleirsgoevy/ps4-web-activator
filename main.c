#include "libjbc/jailbreak.h"
#include <sys/mman.h>
#define pid_t not_pid_t
#include <sys/thr.h>
#include <signal.h>

void* dlopen(const char*, int);
void* dlsym(void*, const char*);

extern int _start;

extern char gadget[];

asm(".global gadget\ngadget:\nmov 0x38(%rdi), %rsp\npop %rdi\njmp callback");

struct
{
    void* header;
    void* ptr;
    unsigned long long idx;
    unsigned long long action;
    unsigned long long account_id;
    char account_name[17];
} __attribute__((packed))* callback_header;

int(*sceRegMgrGetInt)(int, int*);
int(*sceRegMgrSetInt)(int, int);
int(*sceRegMgrGetStr)(int, char*, size_t);
int(*sceRegMgrSetStr)(int, const char*, size_t);
int(*sceRegMgrGetBin)(int, void*, size_t);
int(*sceRegMgrSetBin)(int, const void*, size_t);

int callback(void)
{
    int shift = callback_header->idx << 16;
    if(callback_header->action == 0) //get
    {
        sceRegMgrGetStr(125829632+shift, callback_header->account_name, 17);
        sceRegMgrGetBin(125830400+shift, &callback_header->account_id, 8);
    }
    else if(callback_header->action == 1) //set&activate
    {
        sceRegMgrSetBin(125830400+shift, &callback_header->account_id, 8);
        sceRegMgrSetStr(125874183+shift, "np", 3);
        sceRegMgrSetInt(125831168+shift, 6);
    }
    return 0;
}

void sigsegv(int sig)
{
    thr_exit(0);
}

int main()
{
    //dbg_enter();
    struct sigaction sa = {
        .sa_handler = sigsegv,
        .sa_flags = 0,
    };
    sigaction(SIGSEGV, &sa, 0);
    struct jbc_cred cr;
    jbc_get_cred(&cr);
    jbc_jailbreak_cred(&cr);
    cr.jdir = 0;
    cr.sceProcType = 0x3800000000000010;
    cr.sonyCred = 0x40001c0000000000;
    cr.sceProcCap = 0x900000000000ff00;
    jbc_set_cred(&cr);
    void* dll = dlopen("/system/common/lib/libSceRegMgr.sprx", 0);
    sceRegMgrGetInt = dlsym(dll, "sceRegMgrGetInt");
    sceRegMgrSetInt = dlsym(dll, "sceRegMgrSetInt");
    sceRegMgrGetStr = dlsym(dll, "sceRegMgrGetStr");
    sceRegMgrSetStr = dlsym(dll, "sceRegMgrSetStr");
    sceRegMgrGetBin = dlsym(dll, "sceRegMgrGetBin");
    sceRegMgrSetBin = dlsym(dll, "sceRegMgrSetBin");
    callback_header = mmap((void*)0x9111110000, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    callback_header->ptr = gadget;
    return 0;
}
