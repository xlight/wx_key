#include "../include/shellcode_builder.h"
#include "../include/ipc_manager.h"
#include <xbyak/xbyak.h>
#include <cstddef>

namespace {
    constexpr size_t kSharedDataSizeOffset = offsetof(SharedKeyData, dataSize);
    constexpr size_t kSharedKeyBufferOffset = offsetof(SharedKeyData, keyBuffer);
    constexpr size_t kSharedSequenceOffset = offsetof(SharedKeyData, sequenceNumber);
}

ShellcodeBuilder::ShellcodeBuilder() {
    shellcode.reserve(512);
}

ShellcodeBuilder::~ShellcodeBuilder() {
}

void ShellcodeBuilder::Clear() {
    shellcode.clear();
}

size_t ShellcodeBuilder::GetShellcodeSize() const {
    return shellcode.size();
}

// 使用 Xbyak 生成 Hook Shellcode
std::vector<BYTE> ShellcodeBuilder::BuildHookShellcode(const ShellcodeConfig& config) {
    shellcode.clear();

    // 只支持 x64
    if (sizeof(void*) != 8) {
        return shellcode;
    }

    const bool enableStackSpoofing = config.enableStackSpoofing && config.spoofStackPointer != 0;
    uint64_t spoofStackAligned = 0;
    if (enableStackSpoofing) {
        spoofStackAligned = static_cast<uint64_t>(config.spoofStackPointer) & ~static_cast<uint64_t>(0xF);
    }

    // 生成机器码
    Xbyak::CodeGenerator code(1024, Xbyak::AutoGrow);

    Xbyak::Label skipCopy;

    auto emitSaveRegs = [&]() {
        code.pushfq();
        code.push(code.rax);
        code.push(code.rcx);
        code.push(code.rdx);
        code.push(code.rbx);
        code.push(code.rbp);
        code.push(code.rsi);
        code.push(code.rdi);
        code.push(code.r8);
        code.push(code.r9);
        code.push(code.r10);
        code.push(code.r11);
        code.push(code.r12);
        code.push(code.r13);
        code.push(code.r14);
        code.push(code.r15);
    };

    auto emitRestoreRegs = [&]() {
        code.pop(code.r15);
        code.pop(code.r14);
        code.pop(code.r13);
        code.pop(code.r12);
        code.pop(code.r11);
        code.pop(code.r10);
        code.pop(code.r9);
        code.pop(code.r8);
        code.pop(code.rdi);
        code.pop(code.rsi);
        code.pop(code.rbp);
        code.pop(code.rbx);
        code.pop(code.rdx);
        code.pop(code.rcx);
        code.pop(code.rax);
        code.popfq();
    };

    if (enableStackSpoofing) {
        // 先把会被临时占用的寄存器保存到真实栈
        code.push(code.rsi); // 保存原始 rsi
        code.push(code.rdx); // 保存原始 rdx
        code.push(code.rax); // 保存原始 rax
        code.push(code.r10); // 保存原始 r10
        code.push(code.r11); // 保存原始 r11

        // 计算切换前的真实 RSP
        code.lea(code.rcx, code.ptr[code.rsp + 5 * 8]); // rcx = original rsp

        // 切换到伪栈（对齐到16字节），预留一定空间
        code.mov(code.rsp, spoofStackAligned);
        code.sub(code.rsp, 0x20);

        // 将真实 RSP 存到伪栈，并构造一个假的返回地址槽位
        code.push(code.rcx);                        // [rsp] = original rsp
        code.mov(code.rdx, (uint64_t)config.trampolineAddress); // 伪造返回地址指向 trampoline
        code.push(code.rdx);

        // 从原始栈帧恢复被暂存的寄存器值，确保后续保存的是进入时的原始寄存器状态
        code.mov(code.rsi, code.rcx); // rsi = original rsp
        code.sub(code.rsi, 5 * 8);    // rsi -> 保存区域起点
        code.mov(code.r11, code.qword[code.rsi + 0]);   // 原始 r11
        code.mov(code.r10, code.qword[code.rsi + 8]);   // 原始 r10
        code.mov(code.rax, code.qword[code.rsi + 16]);  // 原始 rax
        code.mov(code.rdx, code.qword[code.rsi + 24]);  // 原始 rdx
        code.mov(code.rsi, code.qword[code.rsi + 32]);  // 原始 rsi
    }

    // ===== 保存寄存器/标志位 =====
    emitSaveRegs();

    // ===== keySize 检查 =====
    code.mov(code.rax, code.ptr[code.rdx + 0x10]); // rax = keySize
    code.cmp(code.rax, 32);
    code.jne(skipCopy);

    // ===== 拷贝 32 字节密钥到共享内存 =====
    code.mov(code.rcx, code.ptr[code.rdx + 0x08]); // rcx = pKeyBuffer
    code.mov(code.rdx, (uint64_t)config.sharedMemoryAddress);
    code.mov(code.rdi, code.rdx);
    code.mov(code.dword[code.rdi + static_cast<uint32_t>(kSharedDataSizeOffset)], 32);            // dataSize = 32
    code.add(code.rdi, static_cast<uint32_t>(kSharedKeyBufferOffset));     // rdi -> keyBuffer
    code.mov(code.rsi, code.rcx);                  // rsi = source
    code.mov(code.rcx, 32);                        // count
    code.rep();
    code.movsb();                                  // rep movsb

    // ===== 递增序列号 =====
    code.mov(code.eax, code.dword[code.rdx + static_cast<uint32_t>(kSharedSequenceOffset)]); // 读取 sequenceNumber
    code.inc(code.eax);
    code.mov(code.dword[code.rdx + static_cast<uint32_t>(kSharedSequenceOffset)], code.eax); // 写回递增后的序列号

    code.L(skipCopy);

    // ===== 恢复寄存器/标志位 =====
    emitRestoreRegs();

    if (enableStackSpoofing) {
        // 丢弃伪造返回地址并恢复真实 RSP，切回原始栈
        code.add(code.rsp, 8); // skip fake return slot
        code.pop(code.rsp);
    }

    // ===== 跳回 Trampoline =====
    code.mov(code.rax, (uint64_t)config.trampolineAddress);
    code.jmp(code.rax);

    // 输出机器码
    shellcode.assign(code.getCode(), code.getCode() + code.getSize());
    return shellcode;
}
