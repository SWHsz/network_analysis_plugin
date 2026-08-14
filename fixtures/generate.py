#!/usr/bin/env python3
"""生成 fixtures/web-session.pcap —— 确定性测试抓包。

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
