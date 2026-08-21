#!/usr/bin/env python3
"""生成 fixtures/ 下的确定性测试 pcap（web-session / mid-capture / edge-cases / tls-cert）。

quic-sample.pcapng 不由本脚本生成：来自 Wireshark 官方测试集
test/captures/quic_follow_multistream.pcapng（GPL 项目测试文件），
用于 QUIC stream 聚合的真实回归。

需要 scapy（已验证 scapy==2.7.0 字节级可复现）：
    python3 -m venv /tmp/scapy-venv && /tmp/scapy-venv/bin/pip install scapy==2.7.0
    /tmp/scapy-venv/bin/python fixtures/generate.py

内容（时间轴相对捕获起点，毫秒）：
  conv A  TCP 192.168.1.4:53124 -> 142.250.74.14:443  TLS 会话
          SYN@0 / SYNACK@35 / ACK@70 / ClientHello@75 / ServerHello@220
          3 次 TCP 重传（2 次客户端方向，1 次服务端方向），FIN 收尾
  conv B  TCP 192.168.1.4:53125 -> 93.184.216.34:80   明文 HTTP
          GET@1100 + 1 次重传@1150，200 响应@1300
  conv C  UDP 192.168.1.4:53126 -> 8.8.8.8:53         DNS
          youtube.com A 查询@50 响应@95（rcode=0）
          nonexistent.example A 查询@200 响应@260（rcode=3 NXDOMAIN）
  噪声    ARP@1500，孤立 UDP@1600

所有 IP/TCP/UDP/DNS 校验和由 scapy 序列化时自动计算。

--- ground truth 双产物（RFC-002 §4.1） --------------------------------

wrpcap 之外，本脚本同步导出 ground_truth/<fixture>.gt.json。gold 语义：

  * detection_basis: generator_intent —— gold 帧集来自生成时刻的构造意图
    （"我在第 N 帧放了一个重传/握手/……"），不是事后用 tshark 反推，
    避免"用被测系统的同款解析器产 gold"的循环论证；
  * 帧号 = wrpcap 写入顺序，从 1 编号（scapy 不重排包，与 tshark 显示的
    frame.number 一致）；
  * intent.kind 词表：
    syn|synack|ack|retransmission|data|fin|dns_query|dns_response|
    http_request|http_response|zero_window|out_of_order|dup_ack|
    tls_client_hello|tls_server_hello|tls_certificate|noise|orphan
    （missing_segment 不作为帧 kind，仅出现在 facts.tcp_anomalies）；
  * retransmission.of_frame = 被重传帧的帧号；原发帧未入包（丢包后的
    快速重传，edge X2 的 segA）时为 null，note 说明，seq 为期望 seq；
  * handshake 三元组经 conv 标签互相关联，附 isn/ack 上下文：
    syn.isn + 1 == synack.ack，synack.isn + 1 == 完成_ack.ack；
  * dns_query 带 qname/qtype；dns_response 带 qname/rcode/ttl/address
    （NXDOMAIN 无应答记录，ttl=null、address=null；A 记录的 address 即生成器
    写入 rdata 的应答地址——S4 关联题据此可从 gt 推导 DNS→后续会话的 pivot）；
  * conversations[].bytes = 该会话全部帧的线上字节数之和（Ethernet 起算，
    **含重传帧**），与插件 ConversationMetrics.bytes_total（tshark conv 表
    双向字节和）同口径；
  * facts.tcp_anomalies 只收 out_of_order / missing_segment / dup_ack /
    zero_window；重传单列在 facts.retransmissions，不进 anomalies；
  * out_of_order 附着规则：早到段（缺口未合时先到）role=early，迟到合口
    段 role=late，两帧各自进 tcp_anomalies 作为同一乱序事件的证据；
    missing_segment 附着于揭示缺口的帧（detail 给期望 seq 与 gap 字节数）；
  * 分段 HTTP 响应（edge X1 的 200 分两个 TCP 段）：response_frame 取
    首段，response_frames 列出全部分段；
  * noise / orphan 帧不归属任何 conversation；
  * 列表按首次出现帧排序；direction: c2s = 客户端（会话发起方向）→服务端。

改动纪律：对本脚本的任何修改不得改变包构造、顺序与时间戳——重新运行后
4 个 pcap 必须与已提交版本字节级一致（sha256 不变），gt.json 是纯增量导出。
"""
import json
import re
import sys

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
GW_MAC = "02:00:00:00:00:01"
CLIENT_IP = "192.168.1.4"

packets = []


def _tuple_of(pkt):
    """只读提取五元组（不触碰包内容，wrpcap 字节不受影响）。非 IP/TCP/UDP 返回 None。"""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        l4, proto = pkt[TCP], "tcp"
    elif UDP in pkt:
        l4, proto = pkt[UDP], "udp"
    else:
        return None
    return {"proto": proto, "src": ip.src, "sport": int(l4.sport),
            "dst": ip.dst, "dport": int(l4.dport)}


def make_add(sink):
    """包添加函数工厂：pkt.time 赋值与 append 逻辑和原始版本逐字一致。

    intent 只记录构造意图（不参与包构造）；返回帧号（= 写入顺序，从 1 起），
    供 retransmission.of_frame 等跨帧引用。
    """
    log = []

    def add(pkt, t_ms, intent=None):
        pkt.time = t_ms / 1000.0
        sink.append(pkt)
        log.append({"frame": len(sink), "t_ms": t_ms,
                    "tuple": _tuple_of(pkt), "intent": intent,
                    "wire_len": len(bytes(pkt))})
        return len(sink)

    return add, log


add, web_log = make_add(packets)


def eth(ip):
    return Ether(src=CLIENT_MAC, dst=GW_MAC) / ip


# ---- conv A: TLS on 443 ----------------------------------------------------
A_SVR, A_PORT = "142.250.74.14", 443
c, s = CLIENT_IP, A_SVR
cp, sp = 53124, A_PORT
ISN_C, ISN_S = 1000, 5000

# body = version(2) + random(32) + sid_len(1) + cipher_len(2)+cipher(2) + comp_len(1)+comp(1)
# ClientHello body 41=0x29，握手头 4B，record 长度 45=0x2d
client_hello = bytes.fromhex(
    "160303002d"          # TLS record: handshake, TLS1.2, len 0x2d
    "01000029"            # ClientHello, body len 0x29
    "0303"                # client_version TLS1.2
    + "11" * 32           # random
    + "00"                # session_id_len
    + "0002" + "1301"     # cipher_suites: TLS_AES_128_GCM_SHA256
    + "01" + "00"         # compression: null
)
# ServerHello body 38=0x26，握手头 4B，record 长度 42=0x2a
server_hello = bytes.fromhex(
    "160303002a"          # TLS record: handshake, TLS1.2, len 0x2a
    "02000026"            # ServerHello, body len 0x26
    "0303"
    + "22" * 32
    + "00"                # session_id_len
    + "1301"              # cipher
    + "00"                # compression
)

add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="S", seq=ISN_C, window=64240)), 0,
    {"conv": "A", "kind": "syn", "isn": ISN_C})
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="SA", seq=ISN_S, ack=ISN_C + 1, window=65535)), 35,
    {"conv": "A", "kind": "synack", "isn": ISN_S, "ack": ISN_C + 1})
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=ISN_C + 1, ack=ISN_S + 1)), 70,
    {"conv": "A", "kind": "ack", "note": "handshake completion ack"})
# ClientHello（1 个 TCP 段承载）
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=ISN_C + 1, ack=ISN_S + 1) / Raw(client_hello)), 75,
    {"conv": "A", "kind": "tls_client_hello", "note": "TLS1.2 ClientHello, cipher TLS_AES_128_GCM_SHA256"})
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=ISN_C + 1 + len(client_hello), ack=ISN_S + 1)), 110,
    {"conv": "A", "kind": "ack"})
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=ISN_S + 1, ack=ISN_C + 1 + len(client_hello)) / Raw(server_hello)), 220,
    {"conv": "A", "kind": "tls_server_hello", "note": "TLS1.2 ServerHello"})

seg1 = b"GETDATA-" * 40  # 320B 客户端数据
seq1 = ISN_C + 1 + len(client_hello)
f_seg1 = add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq1, ack=ISN_S + 1 + len(server_hello)) / Raw(seg1)), 300,
             {"conv": "A", "kind": "data", "note": "client app data 320B"})
# 重传 #1：未收到覆盖 seq1 的 ACK 前原样重发
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq1, ack=ISN_S + 1 + len(server_hello)) / Raw(seg1)), 340,
    {"conv": "A", "kind": "retransmission", "of_frame": f_seg1})

seg2 = b"RESPBODY" * 180  # 1440B 服务端数据
seq2 = ISN_S + 1 + len(server_hello)
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=seq2, ack=seq1 + len(seg1)) / Raw(seg2)), 400,
    {"conv": "A", "kind": "data", "note": "server app data 1440B part 1/2"})
f_seg2b = add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=seq2 + len(seg2), ack=seq1 + len(seg1)) / Raw(seg2)), 410,
              {"conv": "A", "kind": "data", "note": "server app data 1440B part 2/2"})
# 重传 #2：服务端重发第二段（对端尚未 ACK）
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=seq2 + len(seg2), ack=seq1 + len(seg1)) / Raw(seg2)), 450,
    {"conv": "A", "kind": "retransmission", "of_frame": f_seg2b})
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=seq1 + len(seg1), ack=seq2 + 2 * len(seg2))), 470,
    {"conv": "A", "kind": "ack", "note": "cumulative ack of both seg2 parts"})

seg3 = b"CLIENT-ACK-DATA" * 20
seq3 = seq1 + len(seg1)
f_seg3 = add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq3, ack=seq2 + 2 * len(seg2)) / Raw(seg3)), 500,
             {"conv": "A", "kind": "data", "note": "client app data 320B"})
# 重传 #3：客户端再次重发
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq3, ack=seq2 + 2 * len(seg2)) / Raw(seg3)), 540,
    {"conv": "A", "kind": "retransmission", "of_frame": f_seg3})
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="A", seq=seq2 + 2 * len(seg2), ack=seq3 + len(seg3))), 560,
    {"conv": "A", "kind": "ack"})
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="FA", seq=seq3 + len(seg3), ack=seq2 + 2 * len(seg2))), 600,
    {"conv": "A", "kind": "fin"})
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="FA", seq=seq2 + 2 * len(seg2), ack=seq3 + len(seg3) + 1)), 620,
    {"conv": "A", "kind": "fin", "note": "server FIN closing the session"})

# ---- conv C: DNS（放在 conv B 之前的时间轴位置，见脚本注释实际为 50/95/200/260ms）----
D_SVR = "8.8.8.8"
dp = 53126
qid1, qname1 = 0x1234, "youtube.com"
qid2, qname2 = 0x1235, "nonexistent.example"

add(eth(IP(src=c, dst=D_SVR) / UDP(sport=dp, dport=53) /
        DNS(id=qid1, qd=DNSQR(qname=qname1, qtype="A"))), 50,
    {"conv": "C", "kind": "dns_query", "qname": qname1, "qtype": "A"})
add(eth(IP(src=D_SVR, dst=c) / UDP(sport=53, dport=dp) /
        DNS(id=qid1, qr=1, qdcount=1, ancount=1, qd=DNSQR(qname=qname1, qtype="A"),
            an=DNSRR(rrname=qname1, type="A", rdata="142.250.74.14", ttl=120))), 95,
    {"conv": "C", "kind": "dns_response", "qname": qname1, "rcode": 0, "ttl": 120,
     "answer": "142.250.74.14"})
add(eth(IP(src=c, dst=D_SVR) / UDP(sport=dp, dport=53) /
        DNS(id=qid2, qd=DNSQR(qname=qname2, qtype="A"))), 200,
    {"conv": "C", "kind": "dns_query", "qname": qname2, "qtype": "A"})
add(eth(IP(src=D_SVR, dst=c) / UDP(sport=53, dport=dp) /
        DNS(id=qid2, qr=1, rcode=3, qdcount=1, qd=DNSQR(qname=qname2, qtype="A"))), 260,
    {"conv": "C", "kind": "dns_response", "qname": qname2, "rcode": 3, "ttl": None,
     "note": "NXDOMAIN, no answer records"})

# ---- conv B: 明文 HTTP ------------------------------------------------------
B_SVR, B_PORT = "93.184.216.34", 80
bp = 53125
BISN_C, BISN_S = 9000, 7000
http_get = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fixture\r\n\r\n"
http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"

add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="S", seq=BISN_C, window=64240)), 1000,
    {"conv": "B", "kind": "syn", "isn": BISN_C})
add(eth(IP(src=B_SVR, dst=c) / TCP(sport=B_PORT, dport=bp, flags="SA", seq=BISN_S, ack=BISN_C + 1)), 1035,
    {"conv": "B", "kind": "synack", "isn": BISN_S, "ack": BISN_C + 1})
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="A", seq=BISN_C + 1, ack=BISN_S + 1)), 1070,
    {"conv": "B", "kind": "ack", "note": "handshake completion ack"})
f_get = add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="PA", seq=BISN_C + 1, ack=BISN_S + 1) / Raw(http_get)), 1100,
            {"conv": "B", "kind": "http_request", "method": "GET", "host": "example.com", "uri": "/index.html"})
# 重传 #4：GET 重发
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="PA", seq=BISN_C + 1, ack=BISN_S + 1) / Raw(http_get)), 1150,
    {"conv": "B", "kind": "retransmission", "of_frame": f_get})
add(eth(IP(src=B_SVR, dst=c) / TCP(sport=B_PORT, dport=bp, flags="PA", seq=BISN_S + 1, ack=BISN_C + 1 + len(http_get)) / Raw(http_resp)), 1300,
    {"conv": "B", "kind": "http_response", "status": 200, "part": 1, "parts": 1})
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="A", seq=BISN_C + 1 + len(http_get), ack=BISN_S + 1 + len(http_resp))), 1340,
    {"conv": "B", "kind": "ack"})
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="FA", seq=BISN_C + 1 + len(http_get), ack=BISN_S + 1 + len(http_resp))), 1400,
    {"conv": "B", "kind": "fin"})
add(eth(IP(src=B_SVR, dst=c) / TCP(sport=B_PORT, dport=bp, flags="FA", seq=BISN_S + 1 + len(http_resp), ack=BISN_C + 2 + len(http_get))), 1420,
    {"conv": "B", "kind": "fin", "note": "server FIN closing the session"})

# ---- 噪声 -------------------------------------------------------------------
add(Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src=CLIENT_IP, dst="192.168.1.1") / UDP(sport=138, dport=138) / Raw(b"noise"), 1500,
    {"kind": "noise", "note": "broadcast UDP to gateway, no conversation"})
add(Ether(src=CLIENT_MAC, dst=GW_MAC) /
    IP(src=CLIENT_IP, dst="10.0.0.9") / UDP(sport=40000, dport=9999) / Raw(b"orphan"), 1600,
    {"kind": "orphan", "note": "one-way UDP, no reply, no conversation"})

wrpcap("fixtures/web-session.pcap", packets)
print(f"wrote fixtures/web-session.pcap with {len(packets)} packets", file=sys.stderr)

# ---- mid-capture fixture：中途开始抓包（无 SYN），首个数据包来自服务端 -------
# 用于回归 initiator 方向启发式：client 192.168.9.9:52300（临时端口），
# server 93.184.10.20:443 先发 TLS 应用数据。
mid = []
madd, mid_log = make_add(mid)
MS_SVR, MS_PORT = "93.184.10.20", 443
mc, ms = "192.168.9.9", MS_SVR
mcp, msp = 52300, MS_PORT
MISN_S, MISN_C = 8000, 3000
srv_payload = bytes.fromhex("1703030075") + b"S" * 117  # TLS appdata record 头 + 载荷
cli_payload = bytes.fromhex("1703030010") + b"C" * 16

madd(eth(IP(src=ms, dst=mc) / TCP(sport=msp, dport=mcp, flags="PA", seq=MISN_S, ack=MISN_C) / Raw(srv_payload)), 0,
     {"conv": "M", "kind": "data", "note": "server-first TLS appdata; capture starts mid-stream, no SYN"})
madd(eth(IP(src=mc, dst=ms) / TCP(sport=mcp, dport=msp, flags="A", seq=MISN_C, ack=MISN_S + len(srv_payload))), 2,
     {"conv": "M", "kind": "ack"})
madd(eth(IP(src=ms, dst=mc) / TCP(sport=msp, dport=mcp, flags="PA", seq=MISN_S + len(srv_payload), ack=MISN_C) / Raw(srv_payload)), 4,
     {"conv": "M", "kind": "data", "note": "server second segment (seq advanced — NOT a retransmission)"})
madd(eth(IP(src=mc, dst=ms) / TCP(sport=mcp, dport=msp, flags="PA", seq=MISN_C, ack=MISN_S + 2 * len(srv_payload)) / Raw(cli_payload)), 8,
     {"conv": "M", "kind": "data", "note": "client TLS appdata"})
madd(eth(IP(src=ms, dst=mc) / TCP(sport=msp, dport=mcp, flags="A", seq=MISN_S + 2 * len(srv_payload), ack=MISN_C + len(cli_payload))), 10,
     {"conv": "M", "kind": "ack"})

wrpcap("fixtures/mid-capture.pcap", mid)
print(f"wrote fixtures/mid-capture.pcap with {len(mid)} packets (mid-capture, server-first, no SYN)", file=sys.stderr)

# ---- edge-cases fixture：v0.2 事件族的确定性覆盖 ------------------------------
# conv X1 TCP 10.0.0.1:6001 -> 10.0.0.2:80  HTTP（响应分两个 TCP 段，重组后一个 200）
# conv X2 TCP 10.0.0.1:6002 -> 10.0.0.3:443 乱序+缺失段+dup-ack+快速重传+零窗口
# 节奏设计让 tcp.analysis.ack_rtt 有非平凡样本（数据->ACK 间隔 12ms/25ms）。
edge = []
eadd, edge_log = make_add(edge)
E1_C, E1_S = "10.0.0.1", "10.0.0.2"
E2_C, E2_S = "10.0.0.1", "10.0.0.3"


# conv X1: HTTP with split response ------------------------------------------------
x1p, x1sp = 6001, 80
X1_C_ISN, X1_S_ISN = 11000, 12000
get_req = b"GET /data HTTP/1.1\r\nHost: edge.test\r\n\r\n"
resp_head = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
resp_body = b"E" * 40
resp_all = resp_head + resp_body
resp_part1, resp_part2 = resp_all[:30], resp_all[30:]  # 强制两个 TCP 段

eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="S", seq=X1_C_ISN)), 0,
     {"conv": "X1", "kind": "syn", "isn": X1_C_ISN})
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="SA", seq=X1_S_ISN, ack=X1_C_ISN + 1)), 4,
     {"conv": "X1", "kind": "synack", "isn": X1_S_ISN, "ack": X1_C_ISN + 1})
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="A", seq=X1_C_ISN + 1, ack=X1_S_ISN + 1)), 8,
     {"conv": "X1", "kind": "ack", "note": "handshake completion ack"})
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="PA", seq=X1_C_ISN + 1, ack=X1_S_ISN + 1) / Raw(get_req)), 10,
     {"conv": "X1", "kind": "http_request", "method": "GET", "host": "edge.test", "uri": "/data"})
# ACK 在 12ms 后 → ack_rtt ≈ 12ms 样本
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="A", seq=X1_S_ISN + 1, ack=X1_C_ISN + 1 + len(get_req))), 22,
     {"conv": "X1", "kind": "ack", "note": "acks GET; ack_rtt sample ~12ms"})
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="PA", seq=X1_S_ISN + 1, ack=X1_C_ISN + 1 + len(get_req)) / Raw(resp_part1)), 30,
     {"conv": "X1", "kind": "http_response", "status": 200, "part": 1, "parts": 2})
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="PA", seq=X1_S_ISN + 1 + len(resp_part1), ack=X1_C_ISN + 1 + len(get_req)) / Raw(resp_part2)), 32,
     {"conv": "X1", "kind": "http_response", "status": 200, "part": 2, "parts": 2})
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="A", seq=X1_C_ISN + 1 + len(get_req), ack=X1_S_ISN + 1 + len(resp_all))), 57,  # rtt≈25ms
     {"conv": "X1", "kind": "ack", "note": "acks full response; ack_rtt sample ~25ms"})
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="FA", seq=X1_C_ISN + 1 + len(get_req), ack=X1_S_ISN + 1 + len(resp_all))), 70,
     {"conv": "X1", "kind": "fin"})
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="FA", seq=X1_S_ISN + 1 + len(resp_all), ack=X1_C_ISN + 2 + len(get_req))), 74,
     {"conv": "X1", "kind": "fin", "note": "server FIN closing the session"})

# conv X2: 乱序 / 缺失段 / dup-ack / 快速重传 / 零窗口 --------------------------------
x2p, x2sp = 6002, 443
X2_C_ISN, X2_S_ISN = 21000, 22000
segA = b"A" * 100  # seq S0（将丢失）
segB = b"B" * 100  # seq S0+100（先到 → out_of_order + lost_segment gap=100）
segC = b"C" * 100  # seq S0+200

s0 = X2_S_ISN + 1
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="S", seq=X2_C_ISN)), 100,
     {"conv": "X2", "kind": "syn", "isn": X2_C_ISN})
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="SA", seq=X2_S_ISN, ack=X2_C_ISN + 1)), 104,
     {"conv": "X2", "kind": "synack", "isn": X2_S_ISN, "ack": X2_C_ISN + 1})
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=X2_S_ISN + 1)), 108,
     {"conv": "X2", "kind": "ack", "note": "handshake completion ack"})
# B 先到（乱序 + 缺失段：期望 s0，收到 s0+100，gap=100）
f_x2_segB = eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0 + 100, ack=X2_C_ISN + 1) / Raw(segB)), 120,
                 {"conv": "X2", "kind": "out_of_order", "role": "early",
                  "note": f"segB(seq {s0 + 100}) arrives while {s0} expected: 100B gap below, segA lost"})
# C 到（缺口仍在：相对最高连续 s0 仍缺 100）
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0 + 200, ack=X2_C_ISN + 1) / Raw(segC)), 124,
     {"conv": "X2", "kind": "out_of_order", "role": "early",
      "note": f"segC(seq {s0 + 200}) arrives while gap at {s0} persists"})
# 客户端 3 个重复 ACK（等 s0）
for i in range(3):
    eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0)), 130 + i * 3,
         {"conv": "X2", "kind": "dup_ack", "dup_index": i + 1, "ack": s0,
          "note": f"dup #{i + 1} of ack={s0}, waiting for lost segA"})
# 服务端快速重传 segA（填缺口）
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0, ack=X2_C_ISN + 1) / Raw(segA)), 142,
     {"conv": "X2", "kind": "retransmission", "of_frame": None, "seq": s0,
      "note": "fast retransmit of segA after 3 dup acks; original transmission lost before capture"})
# 客户端 ACK 越过全部（dup-ack 系列结束）
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0 + 300)), 150,
     {"conv": "X2", "kind": "ack", "note": "cumulative ack closes gap, ends dup-ack series"})
# 零窗口：客户端通告 win=0，随后窗口更新
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0 + 300, ack=X2_C_ISN + 1) / Raw(segA)), 160,
     {"conv": "X2", "kind": "data", "note": "server sends another 100B segment"})
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0 + 300, window=0)), 168,
     {"conv": "X2", "kind": "zero_window", "note": "client advertises receive window = 0"})
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0 + 300, window=64240)), 190,
     {"conv": "X2", "kind": "ack", "note": "window update: win 0 -> 64240"})


# conv X3: 乱序。Wireshark OOO 判定（packet-tcp.c）：迟到段须在接收方最后一个
# ACK 之后 ~3ms 内到达、此前未见过、且 nextseq != seq+seglen。
# 节奏：D2(t0+100) 先到 → 1ms 后接收方 dup ACK(t0)（仅 1 个，低于 fast-retrans
# 的 dupack>=2 阈值）→ 再 1.5ms 后 D1(t0) 首份到达。
X3_C, X3_S = "10.0.0.1", "10.0.0.4"
x3p, x3sp = 6003, 8080
X3_C_ISN, X3_S_ISN = 31000, 32000
t0 = X3_S_ISN + 1
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="S", seq=X3_C_ISN)), 300,
     {"conv": "X3", "kind": "syn", "isn": X3_C_ISN})
eadd(eth(IP(src=X3_S, dst=X3_C) / TCP(sport=x3sp, dport=x3p, flags="SA", seq=X3_S_ISN, ack=X3_C_ISN + 1)), 304,
     {"conv": "X3", "kind": "synack", "isn": X3_S_ISN, "ack": X3_C_ISN + 1})
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="A", seq=X3_C_ISN + 1, ack=X3_S_ISN + 1)), 308,
     {"conv": "X3", "kind": "ack", "note": "handshake completion ack"})
eadd(eth(IP(src=X3_S, dst=X3_C) / TCP(sport=x3sp, dport=x3p, flags="PA", seq=t0 + 100, ack=X3_C_ISN + 1) / Raw(b"X" * 100)), 320,
     {"conv": "X3", "kind": "out_of_order", "role": "early",
      "note": f"D2(seq {t0 + 100}) arrives before D1(seq {t0}): 100B gap below"})
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="A", seq=X3_C_ISN + 1, ack=t0)), 321,
     {"conv": "X3", "kind": "dup_ack", "dup_index": 1, "ack": t0,
      "note": "single dup, below fast-retransmit dupack>=2 threshold"})
eadd(eth(IP(src=X3_S, dst=X3_C) / TCP(sport=x3sp, dport=x3p, flags="PA", seq=t0, ack=X3_C_ISN + 1) / Raw(b"W" * 100)), 322.5,
     {"conv": "X3", "kind": "out_of_order", "role": "late",
      "note": f"delayed first copy of seq {t0} arrives after D2 and closes the gap (not a retransmission)"})
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="A", seq=X3_C_ISN + 1, ack=t0 + 200)), 340,
     {"conv": "X3", "kind": "ack", "note": "cumulative ack of both segments"})

wrpcap("fixtures/edge-cases.pcap", edge)
print(f"wrote fixtures/edge-cases.pcap with {len(edge)} packets (out_of_order/lost_segment/dup_ack/zero_window/http/ack_rtt)", file=sys.stderr)


# ---- tls-cert fixture：v0.4 tls_certificate 事件（TLS 1.2 明文握手证书） --------
# 自签证书（CN=fixture.example.test，SAN=www/api.fixture.example.test）DER 内嵌，
# 保证 fixture 可复现不依赖外部文件。
import base64 as _b64
CERT_DER = _b64.b64decode("MIIDkjCCAnqgAwIBAgIUNzVtR9WucGkKHw4lXlRbtwhS/bowDQYJKoZIhvcNAQELBQAwODEdMBsGA1UEAwwUZml4dHVyZS5leGFtcGxlLnRlc3QxFzAVBgNVBAoMDlRyYWZmaWNGaXh0dXJlMB4XDTI2MDgxNTA3NTYzMloXDTM2MDgxMjA3NTYzMlowODEdMBsGA1UEAwwUZml4dHVyZS5leGFtcGxlLnRlc3QxFzAVBgNVBAoMDlRyYWZmaWNGaXh0dXJlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA29BnIBF7dIqSsFslt1T6KasZBZJ61nNRd+1JccemzU7VMf300oGItCKI0rBFjLyqjh3teLNvOAvdOCllyjkmDocAYNOz2Z4oZ/4hyZ/P1UfmCBXBRMSm72nM7/YodE2Epk2G4LjaKSFO5DqTNTS6LzvKR951EP6HiJVl/N1hePa7u2Xb/X/lVwOxnpZvhaChPeJ7gcD03DCF5UPz0DhmPx7fAIVagIM7W9oxAc3nDCLNjEMDG1Gee/IeZAIiOCnRfBirAHRC9IpfMN6qM97iSSBKeuvEL39+SSr9UUPyZhUnYQVNI+yw7nKu53Ud0cSYiBmyxMqK5e413jelZI68qQIDAQABo4GTMIGQMB0GA1UdDgQWBBQTCVm0PJGAR41AjQbunN/ChdbVDjAfBgNVHSMEGDAWgBQTCVm0PJGAR41AjQbunN/ChdbVDjAPBgNVHRMBAf8EBTADAQH/MD0GA1UdEQQ2MDSCGHd3dy5maXh0dXJlLmV4YW1wbGUudGVzdIIYYXBpLmZpeHR1cmUuZXhhbXBsZS50ZXN0MA0GCSqGSIb3DQEBCwUAA4IBAQAIVh4c015/GNNlVquLhOMvXCw24KqCp0W8jLhmIWROpzaa/kaeHUJEYuRlcn8ZBviH3tEKZ+Vl9AQ4DcCmXplMSd0qNmDGGvUDHLflOWlj3pou0lETcAcaA8e8K5cHxP5tFEt0lAKgKqjwxSi2Ik/wV7PurpZtT52bGd2+pwF3fwDIwR+rh8EiiAOoYtuYp0z/X8utmdv0pv8pDIhQFCsKRWjkGGkL6eJA3k6bgTftCx9yT+prnpEq2unt5NejgjgKJj/wKVIzmFPQWG1BAJvBArfLFu1uqg5d9hnNkGWVqKjcd6eKxyZDqOuT+fc6Byw+kmXlunBtE2qY7BtGQ9lE")

certs = []
cadd, certs_log = make_add(certs)

TC_C, TC_S = "10.0.0.1", "10.0.0.5"
tcp_cp, tcp_sp = 7001, 443
TC_C_ISN, TC_S_ISN = 41000, 42000

ch_body = bytes.fromhex("0303") + bytes(32) + b"\x00" + b"\x00\x02" + bytes.fromhex("1301") + b"\x01\x00"
ch = bytes.fromhex("160303" + format(len(ch_body) + 4, "04x")) + bytes.fromhex("01" + format(len(ch_body), "06x")) + ch_body
sh_body = bytes.fromhex("0303") + bytes(range(32)) + b"\x00" + bytes.fromhex("1301") + b"\x00"
sh = bytes.fromhex("160303" + format(len(sh_body) + 4, "04x")) + bytes.fromhex("02" + format(len(sh_body), "06x")) + sh_body
cert_entry = len(CERT_DER).to_bytes(3, "big") + CERT_DER
cert_body = len(cert_entry).to_bytes(3, "big") + cert_entry
certmsg = bytes.fromhex("160303" + format(len(cert_body) + 4, "04x")) + bytes.fromhex("0b" + format(len(cert_body), "06x")) + cert_body
shd = bytes.fromhex("1603030004") + bytes.fromhex("0e000000")

cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="S", seq=TC_C_ISN)), 0,
     {"conv": "T", "kind": "syn", "isn": TC_C_ISN})
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="SA", seq=TC_S_ISN, ack=TC_C_ISN + 1)), 5,
     {"conv": "T", "kind": "synack", "isn": TC_S_ISN, "ack": TC_C_ISN + 1})
cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="A", seq=TC_C_ISN + 1, ack=TC_S_ISN + 1)), 10,
     {"conv": "T", "kind": "ack", "note": "handshake completion ack"})
cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="PA", seq=TC_C_ISN + 1, ack=TC_S_ISN + 1) / Raw(ch)), 15,
     {"conv": "T", "kind": "tls_client_hello", "note": "TLS1.2 ClientHello"})
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="PA", seq=TC_S_ISN + 1, ack=TC_C_ISN + 1 + len(ch)) / Raw(sh)), 40,
     {"conv": "T", "kind": "tls_server_hello", "note": "TLS1.2 ServerHello"})
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="PA", seq=TC_S_ISN + 1 + len(sh), ack=TC_C_ISN + 1 + len(ch)) / Raw(certmsg)), 45,
     {"conv": "T", "kind": "tls_certificate",
      "note": "self-signed DER cert, CN=fixture.example.test, SAN=www/api.fixture.example.test"})
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="PA", seq=TC_S_ISN + 1 + len(sh) + len(certmsg), ack=TC_C_ISN + 1 + len(ch)) / Raw(shd)), 47,
     {"conv": "T", "kind": "data", "note": "ServerHelloDone"})
cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="A", seq=TC_C_ISN + 1 + len(ch), ack=TC_S_ISN + 1 + len(sh) + len(certmsg) + len(shd))), 60,
     {"conv": "T", "kind": "ack", "note": "acks ServerHelloDone"})

wrpcap("fixtures/tls-cert.pcap", certs)
print("wrote fixtures/tls-cert.pcap with " + str(len(certs)) + " packets (TLS1.2 + certificate)", file=sys.stderr)


# ============================================================================
# ground truth 导出（RFC-002 §4.1：detection_basis = generator_intent）
# ============================================================================

ANOMALY_KINDS = ("out_of_order", "missing_segment", "dup_ack", "zero_window")


def _conv_of(registry, tup):
    """按五元组（双向）查 conv 标签；查不到返回 None。"""
    if not tup:
        return None
    for label, m in registry.items():
        if tup["proto"] != m["proto"]:
            continue
        fwd = (tup["src"], tup["sport"], tup["dst"], tup["dport"]) == (m["src"], m["sport"], m["dst"], m["dport"])
        rev = (tup["src"], tup["sport"], tup["dst"], tup["dport"]) == (m["dst"], m["dport"], m["src"], m["sport"])
        if fwd or rev:
            return label
    return None


def _direction(meta, tup):
    if (tup["src"], tup["sport"]) == (meta["src"], meta["sport"]):
        return "c2s"
    if (tup["src"], tup["sport"]) == (meta["dst"], meta["dport"]):
        return "s2c"
    raise AssertionError(f"tuple {tup} matches neither direction of conv {meta}")


def build_gt(capture, log, registry, extra_anomalies=()):
    t0 = min(r["t_ms"] for r in log)
    frames = []
    conv_frames = {label: [] for label in registry}
    for r in log:
        it = r["intent"] or {}
        conv, kind = it.get("conv"), it.get("kind")
        # 自检：intent 的 conv 标签必须与包五元组一致（噪声帧两者皆 None）
        derived = _conv_of(registry, r["tuple"])
        assert (conv or None) == derived, (
            f"{capture} frame {r['frame']}: intent conv={conv!r} but tuple maps to {derived!r}")
        rec = {"frame": r["frame"], "t_ms": r["t_ms"], "conv": conv,
               "kind": kind, "tuple": r["tuple"]}
        rec.update({k: v for k, v in it.items() if k not in ("conv", "kind")})
        frames.append(rec)
        if conv:
            conv_frames[conv].append((r["frame"], r["t_ms"]))

    conversations = []
    for label, meta in registry.items():
        pairs = conv_frames[label]
        assert pairs, f"{capture}: conv {label} has no frames"
        conversations.append({
            "id": label, "proto": meta["proto"],
            "src": meta["src"], "sport": meta["sport"],
            "dst": meta["dst"], "dport": meta["dport"],
            "start_ms": pairs[0][1] - t0,
            "frames": [f for f, _ in pairs],
            "bytes": sum(r["wire_len"] for r in log
                         if (r["intent"] or {}).get("conv") == label),
        })

    handshakes, pending = [], {}
    for r in log:
        it = r["intent"] or {}
        conv, kind = it.get("conv"), it.get("kind")
        if kind == "syn":
            pending[conv] = {"syn": r}
        elif kind == "synack" and conv in pending and "synack" not in pending[conv]:
            pending[conv]["synack"] = r
        elif (kind == "ack" and conv in pending and "synack" in pending[conv]
              and "done" not in pending[conv]):
            st = pending[conv]
            handshakes.append({
                "conv": conv,
                "syn_frame": st["syn"]["frame"],
                "synack_frame": st["synack"]["frame"],
                "ack_frame": r["frame"],
                "handshake_ms": r["t_ms"] - st["syn"]["t_ms"],
            })
            pending[conv]["done"] = True

    retransmissions = []
    for r in log:
        it = r["intent"] or {}
        if it.get("kind") == "retransmission":
            rec = {"frame": r["frame"], "conv": it["conv"],
                   "of_frame": it.get("of_frame"),
                   "direction": _direction(registry[it["conv"]], r["tuple"])}
            if "note" in it:
                rec["note"] = it["note"]
            retransmissions.append(rec)

    dns, dns_pending = [], {}
    for r in log:
        it = r["intent"] or {}
        kind = it.get("kind")
        if kind == "dns_query":
            dns_pending[(it["conv"], it["qname"])] = r["frame"]
        elif kind == "dns_response":
            dns.append({
                "query_frame": dns_pending.pop((it["conv"], it["qname"]), None),
                "response_frame": r["frame"],
                "qname": it["qname"],
                "rcode": it["rcode"],
                "ttl": it.get("ttl"),
                "address": it.get("answer"),
            })

    http, http_cur = [], {}
    for r in log:
        it = r["intent"] or {}
        kind, conv = it.get("kind"), it.get("conv")
        if kind == "http_request":
            http_cur[conv] = {"request_frame": r["frame"], "response_frames": [],
                              "method": it["method"], "host": it["host"],
                              "uri": it["uri"], "status": None}
            http.append(http_cur[conv])
        elif kind == "http_response" and conv in http_cur:
            http_cur[conv]["response_frames"].append(r["frame"])
            http_cur[conv]["status"] = it["status"]
    http_transactions = [{
        "request_frame": txn["request_frame"],
        "response_frame": txn["response_frames"][0] if txn["response_frames"] else None,
        "response_frames": txn["response_frames"],
        "method": txn["method"], "host": txn["host"], "uri": txn["uri"],
        "status": txn["status"],
    } for txn in http]

    anomalies = []
    for r in log:
        it = r["intent"] or {}
        if it.get("kind") in ANOMALY_KINDS:
            anomalies.append({"kind": it["kind"], "frame": r["frame"],
                              "conv": it["conv"], "detail": it.get("note", "")})
    anomalies.extend(extra_anomalies)
    anomalies.sort(key=lambda a: a["frame"])

    return {
        "capture": capture,
        "generator": "generate.py",
        "detection_basis": "generator_intent",
        "packet_count": len(log),
        "duration_ms": max(r["t_ms"] for r in log) - t0,
        "frames": frames,
        "facts": {
            "conversations": conversations,
            "handshakes": handshakes,
            "retransmissions": retransmissions,
            "dns": dns,
            "http_transactions": http_transactions,
            "tcp_anomalies": anomalies,
        },
    }


# gt 导出队列：export_gt 只入队；JSON 经 --emit-gt 输出到 stdout，脚本自身不写任何 JSON 文件
_GT_QUEUE = []


def export_gt(capture, log, registry, extra_anomalies=()):
    # capture 只允许本文件内的固定 slug（下方 4 处字面量调用）；显式白名单防止未来传入相对路径
    if not re.fullmatch(r"[a-z0-9-]+", capture):
        raise ValueError(f"capture 必须只含小写字母/数字/连字符: {capture!r}")
    _GT_QUEUE.append(build_gt(capture, log, registry, extra_anomalies))


WEB_REGISTRY = {
    "A": {"proto": "tcp", "src": CLIENT_IP, "sport": 53124, "dst": A_SVR, "dport": A_PORT},
    "C": {"proto": "udp", "src": CLIENT_IP, "sport": dp, "dst": D_SVR, "dport": 53},
    "B": {"proto": "tcp", "src": CLIENT_IP, "sport": bp, "dst": B_SVR, "dport": B_PORT},
}
export_gt("web-session", web_log, WEB_REGISTRY)

export_gt("mid-capture", mid_log, {
    "M": {"proto": "tcp", "src": mc, "sport": mcp, "dst": ms, "dport": msp},
})

EDGE_REGISTRY = {
    "X1": {"proto": "tcp", "src": E1_C, "sport": x1p, "dst": E1_S, "dport": x1sp},
    "X2": {"proto": "tcp", "src": E2_C, "sport": x2p, "dst": E2_S, "dport": x2sp},
    "X3": {"proto": "tcp", "src": X3_C, "sport": x3p, "dst": X3_S, "dport": x3sp},
}
export_gt("edge-cases", edge_log, EDGE_REGISTRY, extra_anomalies=[
    {"kind": "missing_segment", "frame": f_x2_segB, "conv": "X2",
     "detail": f"expected seq {s0}, arrived {s0 + 100}: 100B gap — segA original transmission lost before capture"},
])

export_gt("tls-cert", certs_log, {
    "T": {"proto": "tcp", "src": TC_C, "sport": tcp_cp, "dst": TC_S, "dport": tcp_sp},
})

# ground truth 输出：--emit-gt <capture> 把单个 capture 的 gt JSON 打到 stdout，
# 由调用方重定向到 ground_truth/<capture>.gt.json（重建命令见 README 开发节）
_gt_by_capture = {g["capture"]: g for g in _GT_QUEUE}

if "--emit-gt" in sys.argv:
    _which = sys.argv[sys.argv.index("--emit-gt") + 1]
    if _which not in _gt_by_capture:
        raise SystemExit(f"unknown capture: {_which} (available: {', '.join(_gt_by_capture)})")
    sys.stdout.write(json.dumps(_gt_by_capture[_which], indent=2, ensure_ascii=False, sort_keys=True) + "\n")
else:
    for _g in _GT_QUEUE:
        _f = _g["facts"]
        print(f"gt ready: {_g['capture']} ({_g['packet_count']} frames, "
              f"{len(_f['conversations'])} convs, {len(_f['handshakes'])} handshakes, "
              f"{len(_f['retransmissions'])} retrans, {len(_f['tcp_anomalies'])} anomalies) "
              f"— 用 --emit-gt <capture> 导出", file=sys.stderr)
