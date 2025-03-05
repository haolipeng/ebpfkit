/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _ARP_H_
#define _ARP_H_

SEC("xdp/ingress/arp_monitoring")
int xdp_ingress_arp_monitoring(struct xdp_md *ctx) {
    // 初始化游标用于解析数据包
    struct cursor c;
    struct pkt_ctx_t pkt;

    // 设置游标以解析数据包
    xdp_cursor_init(&c, ctx);
    // 解析以太网头，如果无效则返回
    if (!(pkt.eth = parse_ethhdr(&c))) {
        return -1;
    }

    // 通过检查 EtherType 过滤仅 ARP 流量
    if (pkt.eth->h_proto != htons(ETH_P_ARP)) {
        return XDP_PASS;
    }

    // 解析 ARP 头
    struct arp *ar = 0;
    if (!(ar = parse_arp(&c))) {
        return XDP_PASS;
    }

    // 仅处理 ARP 回复（忽略请求）
    if (ar->hdr.ar_op != htons(ARPOP_REPLY)) {
        return XDP_PASS;
    }

    // 验证硬件类型为以太网且协议为 IPv4
    if (ar->hdr.ar_hrd != htons(ARPHRD_ETHER) || ar->hdr.ar_pro != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 创建用于监控的流结构
    struct flow_t flow = {
        .data = {
            .saddr = *(u32*)ar->ar_sip,  // 源 IP
            .daddr = *(u32*)ar->ar_tip,  // 目标 IP
            .flow_type = ARP_REPLY,      // 流类型
        },
    };

    // 初始化网络流计数器
    struct network_flow_counter_t counter = {};
    // 监控该网络流
    monitor_flow(&flow, &counter);

    // 在 ARP 缓存中插入新条目
    // 将 ARP 回复的源 IP 和 MAC 地址存储在 ARP 缓存中
    bpf_map_update_elem(&arp_cache, ar->ar_sip, ar->ar_sha, BPF_ANY);

    // 更新扫描步骤
    // 检查是否存在与 ARP 回复源 IP 相关的扫描任务
    struct network_scan_t *scan = bpf_map_lookup_elem(&arp_ip_scan_key, ar->ar_sip);
    if (scan != NULL) {
        // 获取扫描任务的状态
        struct network_scan_state_t *state = bpf_map_lookup_elem(&network_scans, scan);
        if (state == NULL) {
            goto next;
        }

        // 更新状态为 SYN 步骤
        // 将扫描任务的状态更新为 SYN 步骤
        state->step = SYN_STEP;
        // 从 ARP IP 扫描键中删除该条目
        // 删除与 ARP 回复源 IP 相关的扫描任务
        bpf_map_delete_elem(&arp_ip_scan_key, scan);

        // 打印调试信息
        // 输出 ARP 响应信息
        bpf_printk("ARP 响应！\n");
        // 丢弃数据包以隐藏 ARP 回复
        // 丢弃 ARP 回复数据包以防止其被传递给上层协议
        return XDP_DROP;
    }

next:
    // 无需进一步处理，直接传递数据包
    // 如果没有相关的扫描任务，则直接传递 ARP 回复数据包
    return XDP_PASS;
}

#endif