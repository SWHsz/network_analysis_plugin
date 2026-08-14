export type {
  AggregateEvidence,
  AuditMetadata,
  BoundedResult,
  Capture,
  Conversation,
  ConversationMetrics,
  Endpoint,
  EventDetection,
  EventDirection,
  EventEvidence,
  EventType,
  TrafficEvent,
  Transport,
} from "./types.js";
export { TrafficSession, type SessionOptions, type OverviewResult, type InspectResult, type QueryResult, type TimelineOptions, type EvidenceOptions, type EvidenceResult, type TimeseriesMetric, type TimeseriesResult, type TimeseriesBin } from "./session.js";
export type {
  CompareOp,
  Condition,
  OrderBy,
  QueryScope,
  TrafficQuery,
} from "./query/ast.js";
export { validateQuery, QueryValidationError, CONVERSATION_FIELDS, EVENT_FIELDS, DEFAULT_SELECT, DEFAULT_LIMIT, MAX_LIMIT } from "./query/ast.js";
export { executeQuery } from "./query/engine.js";
export { EVENT_REGISTRY, EXTRACTION_FIELDS, EVENT_ATTR_FIELDS, BASE_FIELDS, type EventSpec, type AttrFieldSpec } from "./events/registry.js";
export {
  FRAMES_FIELDS,
  FrameTableBuilder,
  framesArgs,
  parseFrameLine,
  type FrameRecord,
  type FrameTable,
} from "./frames.js";
export {
  TsharkBackend,
  BackendUnavailableError,
  DOWNLOAD_MANIFEST,
  PINNED_TSHARK_VERSION,
  type BackendConfig,
  type ResolvedBackend,
} from "./backend/provider.js";

export { BackendTimeoutError, BackendSpawnError } from "./backend/spawn.js";
export { shapeAggregateEvidence, renderEnvelope, renderRows, applyRenderBudget, DEFAULT_RENDER_MAX_CHARS, AGGREGATE_FRAME_CAP } from "./shaper.js";
export { resolveCacheRoot } from "./cachedir.js";
export { parseCapinfosTsv, parseZStats, type LightIndex } from "./indexer.js";
export { PLUGIN_VERSION } from "./util.js";
