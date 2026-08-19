#!/usr/bin/env python3
"""ground_truth/*.gt.json 的 schema 校验 +（可选）scapy pcap 读回抽查。

用法（仓库根目录）：
    python3 scripts/validate_gt.py                     # 结构/一致性校验（纯 stdlib）
    /tmp/scapy-venv/bin/python scripts/validate_gt.py --spotcheck 5 [--seed N]

语义约定见 fixtures/generate.py 头部注释：
gold 来自生成时刻的构造意图（detection_basis: generator_intent），
帧号 = wrpcap 写入顺序（从 1 起）。

--spotcheck N：从全部 4 个 gt.json 的帧级 intent 中随机抽 N 个，
用 rdpcap 读回对应 pcap 帧做物理一致性验证（如标注为 retransmission 的帧，
其五元组/seq/负载须与 of_frame 完全一致）；随后对 facts.retransmissions
做全量复核。退出码 0 = 全部通过，1 = 存在失败项。
"""
import argparse
import json
import os
import random
import sys

try:  # spotcheck 模式才需要 scapy；schema 校验保持纯 stdlib
    from scapy.all import DNS, IP, TCP, UDP, rdpcap  # noqa: F401

    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_DIR = os.path.join(REPO, "ground_truth")
FIX_DIR = os.path.join(REPO, "fixtures")
CAPTURES = ("web-session", "mid-capture", "edge-cases", "tls-cert")

FRAME_KINDS = {
    "syn", "synack", "ack", "retransmission", "data", "fin",
    "dns_query", "dns_response", "http_request", "http_response",
    "zero_window", "out_of_order", "dup_ack",
    "tls_client_hello", "tls_server_hello", "tls_certificate",
    "noise", "orphan",
}
ANOMALY_KINDS = {"out_of_order", "missing_segment", "dup_ack", "zero_window"}
DATA_KINDS = {"data", "http_request", "http_response", "tls_client_hello",
              "tls_server_hello", "tls_certificate"}
REQUIRED_TOP = {"capture", "generator", "detection_basis", "packet_count",
                "duration_ms", "frames", "facts"}
REQUIRED_FACTS = {"conversations", "handshakes", "retransmissions", "dns",
                  "http_transactions", "tcp_anomalies"}


class Checker:
    def __init__(self, name):
        self.name = name
        self.errors = []

    def check(self, cond, msg):
        if not cond:
            self.errors.append(msg)
        return bool(cond)

    def done(self):
        if self.errors:
            print(f"FAIL {self.name}")
            for e in self.errors:
                print(f"  - {e}")
            return False
        print(f"PASS {self.name}")
        return True


def _same_stream(tup, conv):
    if not tup:
        return False
    fwd = ((tup.get("src"), tup.get("sport"), tup.get("dst"), tup.get("dport"))
           == (conv["src"], conv["sport"], conv["dst"], conv["dport"]))
    rev = ((tup.get("src"), tup.get("sport"), tup.get("dst"), tup.get("dport"))
           == (conv["dst"], conv["dport"], conv["src"], conv["sport"]))
    return fwd or rev


def validate_gt(path):
    name = os.path.basename(path)
    c = Checker(name)
    try:
        with open(path, encoding="utf-8") as f:
            gt = json.load(f)
    except Exception as e:  # noqa: BLE001
        c.check(False, f"json load error: {e}")
        return c.done()

    c.check(REQUIRED_TOP <= set(gt), f"missing top-level keys: {sorted(REQUIRED_TOP - set(gt))}")
    c.check(gt.get("generator") == "generate.py", "generator != 'generate.py'")
    c.check(gt.get("detection_basis") == "generator_intent",
            "detection_basis != 'generator_intent'")
    c.check(gt.get("capture") == name[:-len(".gt.json")],
            f"capture {gt.get('capture')!r} != filename stem")
    c.check(isinstance(gt.get("packet_count"), int) and gt["packet_count"] > 0,
            "bad packet_count")
    c.check(isinstance(gt.get("duration_ms"), (int, float)) and gt["duration_ms"] >= 0,
            "bad duration_ms")

    frames = gt.get("frames", [])
    facts = gt.get("facts", {})
    n = gt.get("packet_count", -1)
    c.check(len(frames) == n, f"frames length {len(frames)} != packet_count {n}")
    c.check(isinstance(facts, dict) and REQUIRED_FACTS <= set(facts),
            f"missing facts keys: {sorted(REQUIRED_FACTS - set(facts))}")
    if not (len(frames) == n and isinstance(facts, dict) and REQUIRED_FACTS <= set(facts)):
        return c.done()

    t0 = min(fr["t_ms"] for fr in frames)
    by_frame = {}
    for i, fr in enumerate(frames):
        c.check(fr.get("frame") == i + 1, f"frames[{i}].frame != {i + 1}")
        c.check(fr.get("kind") in FRAME_KINDS, f"frame {fr.get('frame')}: bad kind {fr.get('kind')!r}")
        c.check(isinstance(fr.get("t_ms"), (int, float)), f"frame {fr.get('frame')}: bad t_ms")
        c.check(isinstance(fr.get("tuple"), (dict, type(None))), f"frame {fr.get('frame')}: bad tuple")
        by_frame[fr.get("frame")] = fr

    # --- conversations ---
    conv_ids, conv_of_frame = set(), {}
    for conv in facts["conversations"]:
        cid = conv.get("id")
        c.check(cid and cid not in conv_ids, f"bad/duplicate conversation id {cid!r}")
        conv_ids.add(cid)
        for k in ("proto", "src", "sport", "dst", "dport"):
            c.check(k in conv, f"conv {cid}: missing {k}")
        fs = conv.get("frames", [])
        c.check(bool(fs) and fs == sorted(fs), f"conv {cid}: frames empty or not ascending")
        c.check(all(isinstance(x, int) and 1 <= x <= n for x in fs),
                f"conv {cid}: frame number out of [1, {n}]")
        first = by_frame.get(fs[0], {})
        c.check(first.get("conv") == cid,
                f"conv {cid}: first frame {fs[0]} labeled {first.get('conv')!r}")
        c.check(abs(conv.get("start_ms", -1) - (first.get("t_ms", 0) - t0)) < 1e-9,
                f"conv {cid}: start_ms {conv.get('start_ms')} != first-frame relative t "
                f"{first.get('t_ms', 0) - t0}")
        c.check(all(_same_stream(by_frame[x].get("tuple"), conv) for x in fs),
                f"conv {cid}: some frame tuple does not match conversation endpoints")
        for x in fs:
            c.check(x not in conv_of_frame, f"frame {x} listed in two conversations")
            conv_of_frame[x] = cid
    for fr in frames:
        cv = fr.get("conv")
        if cv is not None:
            c.check(cv in conv_ids, f"frame {fr['frame']}: conv {cv!r} not in conversations")
            c.check(conv_of_frame.get(fr["frame"]) == cv,
                    f"frame {fr['frame']}: not listed under its conv {cv}")
        else:
            c.check(fr["frame"] not in conv_of_frame,
                    f"frame {fr['frame']}: no conv label but listed in a conversation")

    # --- handshakes ---
    for hs in facts["handshakes"]:
        cv = hs.get("conv")
        c.check(cv in conv_ids, f"handshake conv {cv!r} unknown")
        sf, saf, af = hs.get("syn_frame"), hs.get("synack_frame"), hs.get("ack_frame")
        triple_ok = all(isinstance(x, int) and x in by_frame for x in (sf, saf, af))
        c.check(triple_ok, f"handshake {cv}: bad frame numbers {sf}/{saf}/{af}")
        if not triple_ok:
            continue
        c.check(by_frame[sf]["kind"] == "syn", f"handshake {cv}: syn_frame {sf} kind != syn")
        c.check(by_frame[saf]["kind"] == "synack", f"handshake {cv}: synack_frame {saf} kind != synack")
        c.check(by_frame[af]["kind"] == "ack", f"handshake {cv}: ack_frame {af} kind != ack")
        c.check(sf < saf < af, f"handshake {cv}: frames not strictly increasing")
        c.check(all(by_frame[x]["conv"] == cv for x in (sf, saf, af)),
                f"handshake {cv}: triple conv mismatch")
        want = by_frame[af]["t_ms"] - by_frame[sf]["t_ms"]
        c.check(abs(hs.get("handshake_ms", -999) - want) < 1e-9,
                f"handshake {cv}: handshake_ms != t(ack)-t(syn) = {want}")
        syn, synack, ackf = by_frame[sf], by_frame[saf], by_frame[af]
        if "isn" in syn and "ack" in synack:
            c.check(synack["ack"] == syn["isn"] + 1,
                    f"handshake {cv}: synack.ack != syn.isn+1 (三元组不可关联)")
        if "isn" in synack and "ack" in ackf:
            c.check(ackf["ack"] == synack["isn"] + 1,
                    f"handshake {cv}: ack.ack != synack.isn+1 (三元组不可关联)")

    # --- retransmissions ---
    for r in facts["retransmissions"]:
        fr = by_frame.get(r.get("frame"), {})
        c.check(fr.get("kind") == "retransmission",
                f"retrans frame {r.get('frame')} kind != retransmission")
        cv = r.get("conv")
        c.check(fr.get("conv") == cv, f"retrans frame {r.get('frame')} conv mismatch")
        c.check(r.get("direction") in ("c2s", "s2c"),
                f"retrans frame {r.get('frame')}: bad direction {r.get('direction')!r}")
        of = r.get("of_frame")
        if of is None:
            c.check(r.get("note"), f"retrans frame {r.get('frame')}: of_frame=null requires note")
        else:
            c.check(isinstance(of, int) and 1 <= of < r.get("frame", 0),
                    f"retrans frame {r.get('frame')}: of_frame {of} invalid (须为更早的有效帧)")
            ofr = by_frame.get(of, {})
            c.check(ofr.get("kind") in DATA_KINDS,
                    f"retrans of_frame {of}: original kind {ofr.get('kind')!r} not data-bearing")
            c.check(ofr.get("conv") == cv, f"retrans frame {r.get('frame')}: of_frame conv mismatch")
            c.check(fr.get("tuple") == ofr.get("tuple"),
                    f"retrans frame {r.get('frame')}: tuple != of_frame tuple")
    rt_frames = {r.get("frame") for r in facts["retransmissions"]}
    for fr in frames:
        if fr.get("kind") == "retransmission":
            c.check(fr["frame"] in rt_frames,
                    f"frame {fr['frame']} kind=retransmission missing from facts.retransmissions")

    # --- dns ---
    for d in facts["dns"]:
        qf = by_frame.get(d.get("query_frame"), {})
        rf = by_frame.get(d.get("response_frame"), {})
        c.check(qf.get("kind") == "dns_query", f"dns {d.get('qname')!r}: query_frame kind != dns_query")
        c.check(rf.get("kind") == "dns_response",
                f"dns {d.get('qname')!r}: response_frame kind != dns_response")
        c.check(qf.get("qname") == rf.get("qname") == d.get("qname"),
                f"dns {d.get('qname')!r}: qname mismatch across query/response/fact")
        c.check(qf.get("conv") == rf.get("conv"), f"dns {d.get('qname')!r}: conv mismatch")
        c.check(isinstance(d.get("rcode"), int), f"dns {d.get('qname')!r}: bad rcode")
        c.check(rf.get("rcode") == d.get("rcode"), f"dns {d.get('qname')!r}: rcode mismatch")
        c.check(d.get("ttl") is None or isinstance(d.get("ttl"), int),
                f"dns {d.get('qname')!r}: bad ttl")
        c.check(rf.get("ttl", "absent") == d.get("ttl"), f"dns {d.get('qname')!r}: ttl mismatch")

    # --- http_transactions ---
    for h in facts["http_transactions"]:
        req = by_frame.get(h.get("request_frame"), {})
        c.check(req.get("kind") == "http_request", f"http txn: request_frame kind != http_request")
        rfs = h.get("response_frames", [])
        c.check(bool(rfs), f"http txn (frame {h.get('request_frame')}): empty response_frames")
        c.check(h.get("response_frame") == (rfs[0] if rfs else None),
                "http txn: response_frame != first of response_frames")
        for x in rfs:
            resp = by_frame.get(x, {})
            c.check(resp.get("kind") == "http_response", f"http txn: frame {x} kind != http_response")
            c.check(resp.get("conv") == req.get("conv"), f"http txn: frame {x} conv mismatch")
            c.check(resp.get("status") == h.get("status"), f"http txn: frame {x} status mismatch")
        if rfs:
            parts = [by_frame[x].get("part") for x in rfs]
            c.check(parts == sorted(parts) and parts == list(range(1, len(parts) + 1)),
                    f"http txn: response parts not 1..n in order: {parts}")
        for k in ("method", "host", "uri"):
            c.check(req.get(k) == h.get(k), f"http txn: {k} mismatch between request frame and fact")
        c.check(isinstance(h.get("status"), int), "http txn: bad status")

    # --- tcp_anomalies ---
    anom = facts["tcp_anomalies"]
    frames_seq = [a.get("frame") for a in anom]
    c.check(frames_seq == sorted(frames_seq), "tcp_anomalies not sorted by frame")
    listed = {(a.get("kind"), a.get("frame")) for a in anom}
    for a in anom:
        c.check(a.get("kind") in ANOMALY_KINDS, f"anomaly bad kind {a.get('kind')!r}")
        fr = by_frame.get(a.get("frame"), {})
        c.check(fr.get("conv") == a.get("conv"), f"anomaly frame {a.get('frame')} conv mismatch")
        c.check(a.get("detail"), f"anomaly frame {a.get('frame')} ({a.get('kind')}): empty detail")
        c.check(fr.get("kind") != "retransmission",
                f"anomaly frame {a.get('frame')}: retransmission 不应进入 tcp_anomalies")
        if a.get("kind") in ("out_of_order", "dup_ack", "zero_window"):
            c.check(fr.get("kind") == a.get("kind"),
                    f"anomaly {a.get('kind')} frame {a.get('frame')} kind is {fr.get('kind')!r}")
    for fr in frames:
        k = fr.get("kind")
        if k in ("out_of_order", "dup_ack", "zero_window"):
            c.check((k, fr["frame"]) in listed,
                    f"frame {fr['frame']} kind={k} missing from tcp_anomalies")

    # --- duration ---
    want = max(fr["t_ms"] for fr in frames) - t0
    c.check(abs(gt["duration_ms"] - want) < 1e-9, f"duration_ms {gt['duration_ms']} != {want}")

    return c.done()


# ---------------- scapy spotcheck ----------------

def _payload_tcp(p):
    return bytes(p[TCP].payload)


def verify_frame(gt, pkts, fr):
    """按 kind 用 scapy 读回帧做物理一致性验证；返回 None 表示通过，否则返回原因。"""
    n, kind = fr["frame"], fr["kind"]
    p = pkts[n - 1]

    def fail(msg):
        return f"{gt['capture']} frame {n} ({kind}): {msg}"

    if kind == "syn":
        if int(p[TCP].flags) != 0x02:
            return fail(f"flags={p[TCP].flags!r} 不是纯 SYN")
    elif kind == "synack":
        if int(p[TCP].flags) != 0x12:
            return fail(f"flags={p[TCP].flags!r} 不是 SYN+ACK")
    elif kind in ("ack", "dup_ack"):
        if int(p[TCP].flags) != 0x10:
            return fail(f"flags={p[TCP].flags!r} 不是纯 ACK")
        if _payload_tcp(p):
            return fail("纯 ACK 帧携带了负载")
        if kind == "dup_ack" and "ack" in fr and p[TCP].ack != fr["ack"]:
            return fail(f"ack={p[TCP].ack} != intent 声明 {fr['ack']}")
    elif kind == "fin":
        if not int(p[TCP].flags) & 0x01:
            return fail("无 FIN 标志")
    elif kind in DATA_KINDS | {"retransmission", "out_of_order"}:
        if not _payload_tcp(p):
            return fail("无负载")
        if kind == "retransmission":
            of = fr.get("of_frame")
            if of is not None:
                q = pkts[of - 1]
                if (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport) != \
                        (q[IP].src, q[TCP].sport, q[IP].dst, q[TCP].dport):
                    return fail(f"五元组与 of_frame {of} 不一致")
                if p[TCP].seq != q[TCP].seq:
                    return fail(f"seq={p[TCP].seq} != of_frame {of} 的 seq={q[TCP].seq}")
                if _payload_tcp(p) != _payload_tcp(q):
                    return fail(f"负载与 of_frame {of} 不一致")
            elif "seq" in fr and p[TCP].seq != fr["seq"]:
                return fail(f"seq={p[TCP].seq} != intent 声明 {fr['seq']}")
        if kind == "http_request":
            want = (fr.get("method", "") + " " + fr.get("uri", "")).encode()
            if not _payload_tcp(p).startswith(want):
                return fail(f"负载不以 {want!r} 开头")
            if ("Host: " + fr.get("host", "")).encode() not in _payload_tcp(p):
                return fail(f"Host 头与 {fr.get('host')!r} 不符")
        if kind == "http_response":
            txn = next((t for t in gt["facts"]["http_transactions"]
                        if n in t["response_frames"]), None)
            if txn is None:
                return fail("未找到所属 http_transaction")
            joined = b"".join(_payload_tcp(pkts[x - 1]) for x in txn["response_frames"])
            want = f"HTTP/1.1 {fr.get('status')}".encode()
            if not joined.startswith(want):
                return fail(f"重组负载不以 {want!r} 开头")
        if kind == "tls_client_hello":
            b = _payload_tcp(p)
            if not (b[:1] == b"\x16" and b[1:3] == b"\x03\x03" and b[5:6] == b"\x01"):
                return fail("不是 TLS handshake ClientHello 记录")
        if kind == "tls_server_hello":
            b = _payload_tcp(p)
            if not (b[:1] == b"\x16" and b[1:3] == b"\x03\x03" and b[5:6] == b"\x02"):
                return fail("不是 TLS ServerHello 记录")
        if kind == "tls_certificate":
            b = _payload_tcp(p)
            if not (b[:1] == b"\x16" and b[1:3] == b"\x03\x03" and b[5:6] == b"\x0b"):
                return fail("不是 TLS Certificate 记录")
            if b"fixture.example.test" not in b:
                return fail("负载中未找到 CN=fixture.example.test")
        if kind == "out_of_order":
            plen = len(_payload_tcp(p))
            src_key = (p[IP].src, p[TCP].sport)

            def same_dir(q):
                return IP in q and TCP in q and (q[IP].src, q[TCP].sport) == src_key \
                    and len(bytes(q[TCP].payload)) > 0

            if fr.get("role") == "early":
                okk = any(i + 1 > n and q[TCP].seq < p[TCP].seq
                          for i, q in enumerate(pkts) if same_dir(q))
                if not okk:
                    return fail("之后不存在同方向更低 seq 的带载帧，无法佐证早到")
            else:
                okk = any(i + 1 < n and q[TCP].seq >= p[TCP].seq + plen
                          for i, q in enumerate(pkts) if same_dir(q))
                if not okk:
                    return fail("之前不存在同方向 seq>=seq+len 的带载帧，无法佐证迟到")
    elif kind == "zero_window":
        if p[TCP].window != 0:
            return fail(f"window={p[TCP].window} != 0")
    elif kind in ("dns_query", "dns_response"):
        if UDP not in p or DNS not in p:
            return fail("不是 UDP/DNS 包")
        d = p[DNS]
        qname = d.qd.qname.rstrip(b".") if d.qd is not None else None
        if qname is None or qname.decode() != fr.get("qname"):
            return fail(f"qname={qname!r} != intent 声明 {fr.get('qname')!r}")
        if kind == "dns_query":
            if d.qr != 0:
                return fail("qr != 0")
        else:
            if d.qr != 1:
                return fail("qr != 1")
            if d.rcode != fr.get("rcode"):
                return fail(f"rcode={d.rcode} != intent 声明 {fr.get('rcode')}")
            ttl = fr.get("ttl")
            answers = d.an if isinstance(d.an, list) else ([d.an] if d.an else [])
            if ttl is None:
                if d.ancount != 0 or answers:
                    return fail("intent 声明无应答记录，但包内有 answer")
            else:
                if not answers or answers[0].ttl != ttl:
                    return fail(f"ttl={answers[0].ttl if answers else None} != intent 声明 {ttl}")
    elif kind in ("noise", "orphan"):
        if IP not in p or UDP not in p:
            return fail("预期是 UDP 噪声/孤立包")
    return None


def spotcheck(num, seed):
    if not HAVE_SCAPY:
        print("spotcheck 需要 scapy：请用 /tmp/scapy-venv/bin/python 运行（见 README 开发节）")
        return False
    caps = []
    for name in CAPTURES:
        gt_path = os.path.join(GT_DIR, f"{name}.gt.json")
        pcap_path = os.path.join(FIX_DIR, f"{name}.pcap")
        if not (os.path.exists(gt_path) and os.path.exists(pcap_path)):
            print(f"FAIL spotcheck: missing {gt_path} or {pcap_path}")
            return False
        with open(gt_path, encoding="utf-8") as f:
            caps.append((json.load(f), rdpcap(pcap_path)))

    pool = [(gt, pkts, fr) for gt, pkts in caps for fr in gt["frames"] if fr.get("kind")]
    rng = random.Random(seed)
    samples = rng.sample(pool, min(num, len(pool)))
    print(f"spotcheck: sampled {len(samples)} intents from {len(pool)} (seed={seed})")

    failures = []
    for gt, pkts, fr in samples:
        reason = verify_frame(gt, pkts, fr)
        status = "PASS" if reason is None else "FAIL"
        extra = {k: v for k, v in fr.items()
                 if k in ("of_frame", "qname", "rcode", "ttl", "method", "host", "uri",
                          "status", "role", "ack", "isn", "dup_index", "part")}
        print(f"  [{status}] {gt['capture']} frame {fr['frame']:>3} kind={fr['kind']:<18} {extra}")
        if reason:
            failures.append(reason)

    # 重传全量复核（数量少，逐条做物理验证）
    print("spotcheck: full sweep of facts.retransmissions")
    for gt, pkts in caps:
        for r in gt["facts"]["retransmissions"]:
            fr = next(f for f in gt["frames"] if f["frame"] == r["frame"])
            reason = verify_frame(gt, pkts, fr)
            status = "PASS" if reason is None else "FAIL"
            print(f"  [{status}] {gt['capture']} frame {r['frame']:>3} retransmission "
                  f"of_frame={r['of_frame']} direction={r['direction']}")
            if reason:
                failures.append(reason)

    if failures:
        for x in failures:
            print(f"  FAIL {x}")
        return False
    print("spotcheck: all verified")
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--spotcheck", type=int, default=0, metavar="N",
                    help="随机抽 N 个帧级 intent 做 pcap 读回物理验证（需 scapy）")
    ap.add_argument("--seed", type=int, default=None, help="抽查随机种子（可复现）")
    args = ap.parse_args()

    ok = True
    results = []
    for name in CAPTURES:
        path = os.path.join(GT_DIR, f"{name}.gt.json")
        if not os.path.exists(path):
            print(f"FAIL {name}.gt.json: file not found")
            ok = False
            continue
        results.append(validate_gt(path))
    ok = all(results) and ok
    if args.spotcheck:
        ok = spotcheck(args.spotcheck, args.seed) and ok
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
