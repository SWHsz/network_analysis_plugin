import { describe, expect, it } from "vitest";
import { executeQuery } from "../src/query/engine.js";
import { validateQuery, QueryValidationError, MAX_LIMIT } from "../src/query/ast.js";
import type { Conversation, TrafficEvent } from "../src/types.js";
import { shapeAggregateEvidence, renderRows, renderEnvelope, AGGREGATE_FRAME_CAP } from "../src/shaper.js";

function conv(id: string, over: Partial<Conversation> = {}): Conversation {
  return {
    conversation_id: id,
    transport: "tcp",
    initiator: { ip: "10.0.0.1", port: 1000 },
    responder: { ip: "10.0.0.2", port: 443 },
    start_ms: 0,
    duration_ms: 100,
    packets: { forward: 1, reverse: 1 },
    bytes: { forward: 10, reverse: 10 },
    metrics: {
      retransmission_count: 0,
      dns_query_count: 0,
      tls_handshake_count: 0,
      tcp_handshake_ms: null,
      tls_handshake_ms: null,
    },
    protocol_tags: ["tcp"],
    ...over,
  };
}

function evt(id: string, over: Partial<TrafficEvent> = {}): TrafficEvent {
  return {
    event_id: id,
    conversation_id: "conv:tcp:0",
    type: "tcp_retransmission",
    time_ms: 10,
    direction: "initiator_to_responder",
    attributes: {},
    detection: "tshark_tcp_analysis",
    evidence: { kind: "frame", frame_number: 5 },
    ...over,
  };
}

const conversations = [
  conv("conv:tcp:0", { bytes: { forward: 100, reverse: 900 }, metrics: { retransmission_count: 3, dns_query_count: 0, tls_handshake_count: 1, tcp_handshake_ms: 70, tls_handshake_ms: 145 }, protocol_tags: ["tcp", "tls"] }),
  conv("conv:tcp:1", { bytes: { forward: 50, reverse: 50 }, metrics: { retransmission_count: 1, dns_query_count: 0, tls_handshake_count: 0, tcp_handshake_ms: null, tls_handshake_ms: null } }),
  conv("conv:udp:0", { transport: "udp", metrics: { retransmission_count: 0, dns_query_count: 2, tls_handshake_count: 0, tcp_handshake_ms: null, tls_handshake_ms: null }, protocol_tags: ["udp", "dns"] }),
];

const events = [
  evt("evt:1", { type: "tls_client_hello", time_ms: 75, evidence: { kind: "frame", frame_number: 4 } }),
  evt("evt:2", { time_ms: 340, evidence: { kind: "frame", frame_number: 8 } }),
  evt("evt:3", { type: "dns_query", time_ms: 50, conversation_id: "conv:udp:0", detection: "tshark_dns_dissector" }),
  evt("evt:4", { type: "dns_response", time_ms: 95, conversation_id: "conv:udp:0", detection: "tshark_dns_dissector" }),
];

describe("validateQuery", () => {
  it("rejects unknown fields with the allowed list", () => {
    expect(() => validateQuery({ scope: "conversation", where: [{ field: "bogus", op: "eq", value: 1 }] })).toThrow(
      /unknown field 'bogus'.*Allowed:/s,
    );
  });

  it("rejects numeric ops on string fields and non-array in", () => {
    expect(() => validateQuery({ scope: "conversation", where: [{ field: "transport", op: "gt", value: 1 }] })).toThrow(/numeric/);
    expect(() => validateQuery({ scope: "event", where: [{ field: "type", op: "in", value: "tcp_retransmission" }] })).toThrow(/array/);
  });

  it("rejects unknown ops instead of silently matching nothing (v0.3.1)", () => {
    expect(() =>
      validateQuery({ scope: "event", where: [{ field: "type", op: "like", value: "tls%" }] }),
    ).toThrow(/unknown op 'like'/);
    expect(() =>
      validateQuery({ scope: "conversation", where: [{ field: "bytes_total", op: "regex", value: ".*" }] }),
    ).toThrow(/unknown op 'regex'/);
  });

  it("rejects unknown event types and bad transport values with valid lists", () => {
    expect(() =>
      validateQuery({
        scope: "event",
        where: [{ field: "type", op: "in", value: ["tls_certificate_authority", "tls_server_hello"] }],
      }),
    ).toThrow(/unknown event type\(s\): tls_certificate_authority.*Valid types:/s);
    expect(() =>
      validateQuery({ scope: "conversation", where: [{ field: "transport", op: "eq", value: "sctp" }] }),
    ).toThrow(/transport must be "tcp" or "udp"/);
  });

  it("rejects out-of-range limit", () => {
    expect(() => validateQuery({ scope: "conversation", limit: MAX_LIMIT + 1 })).toThrow(/limit/);
    expect(() => validateQuery({ scope: "conversation", limit: 0 })).toThrow(/limit/);
  });

  it("accepts a well-formed query", () => {
    expect(() =>
      validateQuery({
        scope: "conversation",
        where: [{ field: "retransmission_count", op: "gt", value: 0 }],
        order_by: [{ field: "retransmission_count", direction: "desc" }],
        limit: 10,
      }),
    ).not.toThrow();
  });
});

describe("executeQuery", () => {
  it("filters, sorts, paginates and projects", () => {
    const r = executeQuery(
      {
        scope: "conversation",
        where: [{ field: "transport", op: "eq", value: "tcp" }],
        select: ["conversation_id", "bytes_total", "retransmission_count"],
        order_by: [{ field: "bytes_total", direction: "desc" }],
        limit: 1,
      },
      conversations,
      events,
    );
    expect(r.total).toBe(2);
    expect(r.returned).toBe(1);
    expect(r.truncated).toBe(true);
    expect(r.items[0]).toEqual({ conversation_id: "conv:tcp:0", bytes_total: 1000, retransmission_count: 3 });
  });

  it("combines conditions with AND semantics", () => {
    const r = executeQuery(
      {
        scope: "conversation",
        where: [
          { field: "transport", op: "eq", value: "udp" },
          { field: "dns_query_count", op: "gte", value: 1 },
        ],
      },
      conversations,
      events,
    );
    expect(r.items.map((i) => i.conversation_id)).toEqual(["conv:udp:0"]);
  });

  it("supports in / contains / ne", () => {
    expect(
      executeQuery({ scope: "conversation", where: [{ field: "transport", op: "in", value: ["udp"] }] }, conversations, events).total,
    ).toBe(1);
    expect(
      executeQuery({ scope: "conversation", where: [{ field: "protocol_tags", op: "contains", value: "tls" }] }, conversations, events).total,
    ).toBe(1);
    expect(
      executeQuery({ scope: "conversation", where: [{ field: "transport", op: "ne", value: "tcp" }] }, conversations, events).total,
    ).toBe(1);
  });

  it("null metrics only match ne", () => {
    const r = executeQuery(
      { scope: "conversation", where: [{ field: "tcp_handshake_ms", op: "ne", value: 0 }] },
      conversations,
      events,
    );
    // tcp:0 有值(70)，tcp:1/udp:0 为 null —— null 参与 ne
    expect(r.total).toBe(3);
    const gt = executeQuery(
      { scope: "conversation", where: [{ field: "tcp_handshake_ms", op: "gt", value: -1 }] },
      conversations,
      events,
    );
    expect(gt.total).toBe(1); // 数值比较对 null 为假
  });

  it("events scope filters by type and conversation, ordered by time", () => {
    const r = executeQuery(
      {
        scope: "event",
        where: [{ field: "conversation_id", op: "eq", value: "conv:udp:0" }],
        order_by: [{ field: "time_ms", direction: "asc" }],
      },
      conversations,
      events,
    );
    expect(r.items.map((i) => i.type)).toEqual(["dns_query", "dns_response"]);
    expect(r.items[0]!.frame_number).toBe(5); // 无 select 时输出全部默认字段
  });

  it("offset pagination keeps stable order", () => {
    const r = executeQuery(
      { scope: "event", order_by: [{ field: "time_ms", direction: "asc" }], limit: 2, offset: 2 },
      conversations,
      events,
    );
    expect(r.items.map((i) => i.event_id)).toEqual(["evt:4", "evt:2"]);
    expect(r.offset).toBe(2);
  });
});

describe("shaper", () => {
  it("caps aggregate evidence frames", () => {
    const many = Array.from({ length: AGGREGATE_FRAME_CAP + 250 }, (_, i) => i + 1);
    const shaped = shapeAggregateEvidence(many);
    expect(shaped.truncated).toBe(true);
    expect(shaped.frame_count).toBe(AGGREGATE_FRAME_CAP + 250);
    expect(shaped.frames).toHaveLength(AGGREGATE_FRAME_CAP);
    expect(shapeAggregateEvidence([3, 1, 2]).truncated).toBe(false);
  });

  it("renders compact tables and envelopes", () => {
    const table = renderRows([{ a: 1, b: "x" }, { a: 22, b: "yy" }]);
    expect(table.split("\n")).toHaveLength(4); // 表头 + 分隔 + 2 行
    expect(renderEnvelope({ returned: 5, total: 100, offset: 0, truncated: true })).toContain("TRUNCATED");
    expect(renderEnvelope({ returned: 5, total: 5, offset: 0, truncated: false })).not.toContain("TRUNCATED");
  });
});
