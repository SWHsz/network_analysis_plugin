#!/usr/bin/env python3
"""生成 fixtures/web-session.pcap —— 确定性测试抓包。

quic-sample.pcapng 不由本脚本生成：来自 Wireshark 官方测试集
test/captures/quic_follow_multistream.pcapng（GPL 项目测试文件），
用于 QUIC stream 聚合的真实回归。

需要 scapy：
    python3 -m venv /tmp/scapy-venv && /tmp/scapy-venv/bin/pip install scapy
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
"""
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
GW_MAC = "02:00:00:00:00:01"
CLIENT_IP = "192.168.1.4"

packets = []


def add(pkt, t_ms):
    pkt.time = t_ms / 1000.0
    packets.append(pkt)


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

add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="S", seq=ISN_C, window=64240)), 0)
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="SA", seq=ISN_S, ack=ISN_C + 1, window=65535)), 35)
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=ISN_C + 1, ack=ISN_S + 1)), 70)
# ClientHello（1 个 TCP 段承载）
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=ISN_C + 1, ack=ISN_S + 1) / Raw(client_hello)), 75)
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=ISN_C + 1 + len(client_hello), ack=ISN_S + 1)), 110)
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=ISN_S + 1, ack=ISN_C + 1 + len(client_hello)) / Raw(server_hello)), 220)

seg1 = b"GETDATA-" * 40  # 320B 客户端数据
seq1 = ISN_C + 1 + len(client_hello)
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq1, ack=ISN_S + 1 + len(server_hello)) / Raw(seg1)), 300)
# 重传 #1：未收到覆盖 seq1 的 ACK 前原样重发
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq1, ack=ISN_S + 1 + len(server_hello)) / Raw(seg1)), 340)

seg2 = b"RESPBODY" * 180  # 1440B 服务端数据
seq2 = ISN_S + 1 + len(server_hello)
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=seq2, ack=seq1 + len(seg1)) / Raw(seg2)), 400)
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=seq2 + len(seg2), ack=seq1 + len(seg1)) / Raw(seg2)), 410)
# 重传 #2：服务端重发第二段（对端尚未 ACK）
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=seq2 + len(seg2), ack=seq1 + len(seg1)) / Raw(seg2)), 450)
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=seq1 + len(seg1), ack=seq2 + 2 * len(seg2))), 470)

seg3 = b"CLIENT-ACK-DATA" * 20
seq3 = seq1 + len(seg1)
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq3, ack=seq2 + 2 * len(seg2)) / Raw(seg3)), 500)
# 重传 #3：客户端再次重发
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=seq3, ack=seq2 + 2 * len(seg2)) / Raw(seg3)), 540)
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="A", seq=seq2 + 2 * len(seg2), ack=seq3 + len(seg3))), 560)
add(eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="FA", seq=seq3 + len(seg3), ack=seq2 + 2 * len(seg2))), 600)
add(eth(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="FA", seq=seq2 + 2 * len(seg2), ack=seq3 + len(seg3) + 1)), 620)

# ---- conv C: DNS（放在 conv B 之前的时间轴位置，见脚本注释实际为 50/95/200/260ms）----
D_SVR = "8.8.8.8"
dp = 53126
qid1, qname1 = 0x1234, "youtube.com"
qid2, qname2 = 0x1235, "nonexistent.example"

add(eth(IP(src=c, dst=D_SVR) / UDP(sport=dp, dport=53) /
        DNS(id=qid1, qd=DNSQR(qname=qname1, qtype="A"))), 50)
add(eth(IP(src=D_SVR, dst=c) / UDP(sport=53, dport=dp) /
        DNS(id=qid1, qr=1, qdcount=1, ancount=1, qd=DNSQR(qname=qname1, qtype="A"),
            an=DNSRR(rrname=qname1, type="A", rdata="142.250.74.14", ttl=120))), 95)
add(eth(IP(src=c, dst=D_SVR) / UDP(sport=dp, dport=53) /
        DNS(id=qid2, qd=DNSQR(qname=qname2, qtype="A"))), 200)
add(eth(IP(src=D_SVR, dst=c) / UDP(sport=53, dport=dp) /
        DNS(id=qid2, qr=1, rcode=3, qdcount=1, qd=DNSQR(qname=qname2, qtype="A"))), 260)

# ---- conv B: 明文 HTTP ------------------------------------------------------
B_SVR, B_PORT = "93.184.216.34", 80
bp = 53125
BISN_C, BISN_S = 9000, 7000
http_get = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fixture\r\n\r\n"
http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"

add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="S", seq=BISN_C, window=64240)), 1000)
add(eth(IP(src=B_SVR, dst=c) / TCP(sport=B_PORT, dport=bp, flags="SA", seq=BISN_S, ack=BISN_C + 1)), 1035)
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="A", seq=BISN_C + 1, ack=BISN_S + 1)), 1070)
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="PA", seq=BISN_C + 1, ack=BISN_S + 1) / Raw(http_get)), 1100)
# 重传 #4：GET 重发
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="PA", seq=BISN_C + 1, ack=BISN_S + 1) / Raw(http_get)), 1150)
add(eth(IP(src=B_SVR, dst=c) / TCP(sport=B_PORT, dport=bp, flags="PA", seq=BISN_S + 1, ack=BISN_C + 1 + len(http_get)) / Raw(http_resp)), 1300)
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="A", seq=BISN_C + 1 + len(http_get), ack=BISN_S + 1 + len(http_resp))), 1340)
add(eth(IP(src=c, dst=B_SVR) / TCP(sport=bp, dport=B_PORT, flags="FA", seq=BISN_C + 1 + len(http_get), ack=BISN_S + 1 + len(http_resp))), 1400)
add(eth(IP(src=B_SVR, dst=c) / TCP(sport=B_PORT, dport=bp, flags="FA", seq=BISN_S + 1 + len(http_resp), ack=BISN_C + 2 + len(http_get))), 1420)

# ---- 噪声 -------------------------------------------------------------------
add(Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src=CLIENT_IP, dst="192.168.1.1") / UDP(sport=138, dport=138) / Raw(b"noise"), 1500)
add(Ether(src=CLIENT_MAC, dst=GW_MAC) /
    IP(src=CLIENT_IP, dst="10.0.0.9") / UDP(sport=40000, dport=9999) / Raw(b"orphan"), 1600)

wrpcap("fixtures/web-session.pcap", packets)
print(f"wrote fixtures/web-session.pcap with {len(packets)} packets")

# ---- mid-capture fixture：中途开始抓包（无 SYN），首个数据包来自服务端 -------
# 用于回归 initiator 方向启发式：client 192.168.9.9:52300（临时端口），
# server 93.184.10.20:443 先发 TLS 应用数据。
mid = []
MS_SVR, MS_PORT = "93.184.10.20", 443
mc, ms = "192.168.9.9", MS_SVR
mcp, msp = 52300, MS_PORT
MISN_S, MISN_C = 8000, 3000
srv_payload = bytes.fromhex("1703030075") + b"S" * 117  # TLS appdata record 头 + 载荷
cli_payload = bytes.fromhex("1703030010") + b"C" * 16


def madd(pkt, t_ms):
    pkt.time = t_ms / 1000.0
    mid.append(pkt)


madd(eth(IP(src=ms, dst=mc) / TCP(sport=msp, dport=mcp, flags="PA", seq=MISN_S, ack=MISN_C) / Raw(srv_payload)), 0)
madd(eth(IP(src=mc, dst=ms) / TCP(sport=mcp, dport=msp, flags="A", seq=MISN_C, ack=MISN_S + len(srv_payload))), 2)
madd(eth(IP(src=ms, dst=mc) / TCP(sport=msp, dport=mcp, flags="PA", seq=MISN_S + len(srv_payload), ack=MISN_C) / Raw(srv_payload)), 4)
madd(eth(IP(src=mc, dst=ms) / TCP(sport=mcp, dport=msp, flags="PA", seq=MISN_C, ack=MISN_S + 2 * len(srv_payload)) / Raw(cli_payload)), 8)
madd(eth(IP(src=ms, dst=mc) / TCP(sport=msp, dport=mcp, flags="A", seq=MISN_S + 2 * len(srv_payload), ack=MISN_C + len(cli_payload))), 10)

wrpcap("fixtures/mid-capture.pcap", mid)
print(f"wrote fixtures/mid-capture.pcap with {len(mid)} packets (mid-capture, server-first, no SYN)")

# ---- edge-cases fixture：v0.2 事件族的确定性覆盖 ------------------------------
# conv X1 TCP 10.0.0.1:6001 -> 10.0.0.2:80  HTTP（响应分两个 TCP 段，重组后一个 200）
# conv X2 TCP 10.0.0.1:6002 -> 10.0.0.3:443 乱序+缺失段+dup-ack+快速重传+零窗口
# 节奏设计让 tcp.analysis.ack_rtt 有非平凡样本（数据->ACK 间隔 12ms/25ms）。
edge = []
E1_C, E1_S = "10.0.0.1", "10.0.0.2"
E2_C, E2_S = "10.0.0.1", "10.0.0.3"


def eadd(pkt, t_ms):
    pkt.time = t_ms / 1000.0
    edge.append(pkt)


# conv X1: HTTP with split response ------------------------------------------------
x1p, x1sp = 6001, 80
X1_C_ISN, X1_S_ISN = 11000, 12000
get_req = b"GET /data HTTP/1.1\r\nHost: edge.test\r\n\r\n"
resp_head = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"
resp_body = b"E" * 40
resp_all = resp_head + resp_body
resp_part1, resp_part2 = resp_all[:30], resp_all[30:]  # 强制两个 TCP 段

eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="S", seq=X1_C_ISN)), 0)
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="SA", seq=X1_S_ISN, ack=X1_C_ISN + 1)), 4)
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="A", seq=X1_C_ISN + 1, ack=X1_S_ISN + 1)), 8)
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="PA", seq=X1_C_ISN + 1, ack=X1_S_ISN + 1) / Raw(get_req)), 10)
# ACK 在 12ms 后 → ack_rtt ≈ 12ms 样本
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="A", seq=X1_S_ISN + 1, ack=X1_C_ISN + 1 + len(get_req))), 22)
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="PA", seq=X1_S_ISN + 1, ack=X1_C_ISN + 1 + len(get_req)) / Raw(resp_part1)), 30)
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="PA", seq=X1_S_ISN + 1 + len(resp_part1), ack=X1_C_ISN + 1 + len(get_req)) / Raw(resp_part2)), 32)
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="A", seq=X1_C_ISN + 1 + len(get_req), ack=X1_S_ISN + 1 + len(resp_all))), 57)  # rtt≈25ms
eadd(eth(IP(src=E1_C, dst=E1_S) / TCP(sport=x1p, dport=x1sp, flags="FA", seq=X1_C_ISN + 1 + len(get_req), ack=X1_S_ISN + 1 + len(resp_all))), 70)
eadd(eth(IP(src=E1_S, dst=E1_C) / TCP(sport=x1sp, dport=x1p, flags="FA", seq=X1_S_ISN + 1 + len(resp_all), ack=X1_C_ISN + 2 + len(get_req))), 74)

# conv X2: 乱序 / 缺失段 / dup-ack / 快速重传 / 零窗口 --------------------------------
x2p, x2sp = 6002, 443
X2_C_ISN, X2_S_ISN = 21000, 22000
segA = b"A" * 100  # seq S0（将丢失）
segB = b"B" * 100  # seq S0+100（先到 → out_of_order + lost_segment gap=100）
segC = b"C" * 100  # seq S0+200

s0 = X2_S_ISN + 1
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="S", seq=X2_C_ISN)), 100)
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="SA", seq=X2_S_ISN, ack=X2_C_ISN + 1)), 104)
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=X2_S_ISN + 1)), 108)
# B 先到（乱序 + 缺失段：期望 s0，收到 s0+100，gap=100）
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0 + 100, ack=X2_C_ISN + 1) / Raw(segB)), 120)
# C 到（缺口仍在：相对最高连续 s0 仍缺 100）
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0 + 200, ack=X2_C_ISN + 1) / Raw(segC)), 124)
# 客户端 3 个重复 ACK（等 s0）
for i in range(3):
    eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0)), 130 + i * 3)
# 服务端快速重传 segA（填缺口）
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0, ack=X2_C_ISN + 1) / Raw(segA)), 142)
# 客户端 ACK 越过全部（dup-ack 系列结束）
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0 + 300)), 150)
# 零窗口：客户端通告 win=0，随后窗口更新
eadd(eth(IP(src=E2_S, dst=E2_C) / TCP(sport=x2sp, dport=x2p, flags="PA", seq=s0 + 300, ack=X2_C_ISN + 1) / Raw(segA)), 160)
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0 + 300, window=0)), 168)
eadd(eth(IP(src=E2_C, dst=E2_S) / TCP(sport=x2p, dport=x2sp, flags="A", seq=X2_C_ISN + 1, ack=s0 + 300, window=64240)), 190)


# conv X3: 乱序。Wireshark OOO 判定（packet-tcp.c）：迟到段须在接收方最后一个
# ACK 之后 ~3ms 内到达、此前未见过、且 nextseq != seq+seglen。
# 节奏：D2(t0+100) 先到 → 1ms 后接收方 dup ACK(t0)（仅 1 个，低于 fast-retrans
# 的 dupack>=2 阈值）→ 再 1.5ms 后 D1(t0) 首份到达。
X3_C, X3_S = "10.0.0.1", "10.0.0.4"
x3p, x3sp = 6003, 8080
X3_C_ISN, X3_S_ISN = 31000, 32000
t0 = X3_S_ISN + 1
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="S", seq=X3_C_ISN)), 300)
eadd(eth(IP(src=X3_S, dst=X3_C) / TCP(sport=x3sp, dport=x3p, flags="SA", seq=X3_S_ISN, ack=X3_C_ISN + 1)), 304)
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="A", seq=X3_C_ISN + 1, ack=X3_S_ISN + 1)), 308)
eadd(eth(IP(src=X3_S, dst=X3_C) / TCP(sport=x3sp, dport=x3p, flags="PA", seq=t0 + 100, ack=X3_C_ISN + 1) / Raw(b"X" * 100)), 320)
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="A", seq=X3_C_ISN + 1, ack=t0)), 321)
eadd(eth(IP(src=X3_S, dst=X3_C) / TCP(sport=x3sp, dport=x3p, flags="PA", seq=t0, ack=X3_C_ISN + 1) / Raw(b"W" * 100)), 322.5)
eadd(eth(IP(src=X3_C, dst=X3_S) / TCP(sport=x3p, dport=x3sp, flags="A", seq=X3_C_ISN + 1, ack=t0 + 200)), 340)

wrpcap("fixtures/edge-cases.pcap", edge)
print(f"wrote fixtures/edge-cases.pcap with {len(edge)} packets (out_of_order/lost_segment/dup_ack/zero_window/http/ack_rtt)")


# ---- tls-cert fixture：v0.4 tls_certificate 事件（TLS 1.2 明文握手证书） --------
# 自签证书（CN=fixture.example.test，SAN=www/api.fixture.example.test）DER 内嵌，
# 保证 fixture 可复现不依赖外部文件。
import base64 as _b64
CERT_DER = _b64.b64decode("MIIDkjCCAnqgAwIBAgIUNzVtR9WucGkKHw4lXlRbtwhS/bowDQYJKoZIhvcNAQELBQAwODEdMBsGA1UEAwwUZml4dHVyZS5leGFtcGxlLnRlc3QxFzAVBgNVBAoMDlRyYWZmaWNGaXh0dXJlMB4XDTI2MDgxNTA3NTYzMloXDTM2MDgxMjA3NTYzMlowODEdMBsGA1UEAwwUZml4dHVyZS5leGFtcGxlLnRlc3QxFzAVBgNVBAoMDlRyYWZmaWNGaXh0dXJlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA29BnIBF7dIqSsFslt1T6KasZBZJ61nNRd+1JccemzU7VMf300oGItCKI0rBFjLyqjh3teLNvOAvdOCllyjkmDocAYNOz2Z4oZ/4hyZ/P1UfmCBXBRMSm72nM7/YodE2Epk2G4LjaKSFO5DqTNTS6LzvKR951EP6HiJVl/N1hePa7u2Xb/X/lVwOxnpZvhaChPeJ7gcD03DCF5UPz0DhmPx7fAIVagIM7W9oxAc3nDCLNjEMDG1Gee/IeZAIiOCnRfBirAHRC9IpfMN6qM97iSSBKeuvEL39+SSr9UUPyZhUnYQVNI+yw7nKu53Ud0cSYiBmyxMqK5e413jelZI68qQIDAQABo4GTMIGQMB0GA1UdDgQWBBQTCVm0PJGAR41AjQbunN/ChdbVDjAfBgNVHSMEGDAWgBQTCVm0PJGAR41AjQbunN/ChdbVDjAPBgNVHRMBAf8EBTADAQH/MD0GA1UdEQQ2MDSCGHd3dy5maXh0dXJlLmV4YW1wbGUudGVzdIIYYXBpLmZpeHR1cmUuZXhhbXBsZS50ZXN0MA0GCSqGSIb3DQEBCwUAA4IBAQAIVh4c015/GNNlVquLhOMvXCw24KqCp0W8jLhmIWROpzaa/kaeHUJEYuRlcn8ZBviH3tEKZ+Vl9AQ4DcCmXplMSd0qNmDGGvUDHLflOWlj3pou0lETcAcaA8e8K5cHxP5tFEt0lAKgKqjwxSi2Ik/wV7PurpZtT52bGd2+pwF3fwDIwR+rh8EiiAOoYtuYp0z/X8utmdv0pv8pDIhQFCsKRWjkGGkL6eJA3k6bgTftCx9yT+prnpEq2unt5NejgjgKJj/wKVIzmFPQWG1BAJvBArfLFu1uqg5d9hnNkGWVqKjcd6eKxyZDqOuT+fc6Byw+kmXlunBtE2qY7BtGQ9lE")

certs = []
def cadd(pkt, t_ms):
    pkt.time = t_ms / 1000.0
    certs.append(pkt)

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

cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="S", seq=TC_C_ISN)), 0)
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="SA", seq=TC_S_ISN, ack=TC_C_ISN + 1)), 5)
cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="A", seq=TC_C_ISN + 1, ack=TC_S_ISN + 1)), 10)
cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="PA", seq=TC_C_ISN + 1, ack=TC_S_ISN + 1) / Raw(ch)), 15)
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="PA", seq=TC_S_ISN + 1, ack=TC_C_ISN + 1 + len(ch)) / Raw(sh)), 40)
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="PA", seq=TC_S_ISN + 1 + len(sh), ack=TC_C_ISN + 1 + len(ch)) / Raw(certmsg)), 45)
cadd(eth(IP(src=TC_S, dst=TC_C) / TCP(sport=tcp_sp, dport=tcp_cp, flags="PA", seq=TC_S_ISN + 1 + len(sh) + len(certmsg), ack=TC_C_ISN + 1 + len(ch)) / Raw(shd)), 47)
cadd(eth(IP(src=TC_C, dst=TC_S) / TCP(sport=tcp_cp, dport=tcp_sp, flags="A", seq=TC_C_ISN + 1 + len(ch), ack=TC_S_ISN + 1 + len(sh) + len(certmsg) + len(shd))), 60)

wrpcap("fixtures/tls-cert.pcap", certs)
print("wrote fixtures/tls-cert.pcap with " + str(len(certs)) + " packets (TLS1.2 + certificate)")
