"use strict";

const form = document.getElementById("guided-form");
const fields = document.getElementById("workflow-fields");
const investigateButton = document.getElementById("investigate");
const cancelButton = document.getElementById("cancel");
const remediationButton = document.getElementById("remediate");
const remediationNote = document.getElementById("remediation-note");
const statusRegion = document.getElementById("status");
const guidance = document.getElementById("readiness-guidance");
const results = document.getElementById("results");
const resultsTitle = document.getElementById("results-title");
const structured = document.getElementById("structured-result");
const raw = document.getElementById("raw-result");
const scannerState = document.getElementById("scanner-state");
const aiState = document.getElementById("ai-state");
const remediationState = document.getElementById("remediation-state");
const previewState = document.getElementById("preview-state");

let scannerReady = false;
let activeRequest = null;
let investigationComplete = false;

function addClass(element, name) {
  element.classList.add(name);
  return element;
}

function valueText(value) {
  if (value === null || value === undefined || value === "") return "Unavailable";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value);
}

function addDefinition(section, label, value) {
  const term = document.createElement("dt");
  term.textContent = label;
  const description = addClass(document.createElement("dd"), "user-data");
  description.textContent = valueText(value);
  section.append(term, description);
}

function definitionSection(title, values, style) {
  const section = addClass(document.createElement("section"), "result-section");
  if (style) section.classList.add(style);
  const heading = document.createElement("h3");
  heading.textContent = title;
  const list = document.createElement("dl");
  for (const [label, value] of values) addDefinition(list, label, value);
  section.append(heading, list);
  structured.append(section);
}

function listSection(title, values, style) {
  const section = addClass(document.createElement("section"), "result-section");
  if (style) section.classList.add(style);
  const heading = document.createElement("h3");
  heading.textContent = title;
  const list = document.createElement("ul");
  const items = values.length ? values : ["None reported in this artifact view."];
  for (const value of items) {
    const item = addClass(document.createElement("li"), "user-data");
    item.textContent = valueText(value);
    list.append(item);
  }
  section.append(heading, list);
  structured.append(section);
}

function entryTexts(entries, category) {
  if (!Array.isArray(entries)) return [];
  return entries
    .filter((entry) => entry && entry.category === category && typeof entry.text === "string")
    .map((entry) => entry.text);
}

function uniqueSupportIds(entries) {
  const values = [];
  if (Array.isArray(entries)) {
    for (const entry of entries) {
      if (entry && Array.isArray(entry.support_ids)) values.push(...entry.support_ids);
    }
  }
  return [...new Set(values.filter((value) => typeof value === "string"))].sort();
}

function coverageLines(coverage) {
  if (!coverage || typeof coverage !== "object") return ["Coverage details are unavailable."];
  return Object.entries(coverage).map(([key, value]) => `${key}: ${valueText(value)}`);
}

function updateAiFromReport(investigation) {
  if (!investigation || typeof investigation.status !== "string") return;
  if (investigation.status === "disabled") {
    aiState.textContent = "Off";
    return;
  }
  if (["completed", "incomplete_input"].includes(investigation.status)) {
    aiState.textContent = "Configured";
    return;
  }
  aiState.textContent = "Unavailable";
}

function renderReport(report) {
  structured.replaceChildren();
  const entries = Array.isArray(report.entries) ? report.entries : [];
  const repository = report.repository && typeof report.repository === "object" ? report.repository : {};
  const advisory = report.advisory && typeof report.advisory === "object" ? report.advisory : {};
  const scanner = report.scanner && typeof report.scanner === "object" ? report.scanner : {};
  const investigation = report.investigation && typeof report.investigation === "object" ? report.investigation : {};
  const claims = Array.isArray(investigation.claims)
    ? investigation.claims.map((claim) => claim && claim.summary).filter((value) => typeof value === "string")
    : [];
  const validationActions = [
    ...entryTexts(entries, "validation_action"),
    ...(Array.isArray(investigation.validation_actions) ? investigation.validation_actions : [])
  ];
  const limitations = [
    ...entryTexts(entries, "assumption"),
    ...entryTexts(entries, "coverage_gap"),
    "Lexical and package evidence does not establish runtime reachability, exploitability, deployment exposure, or affected/not-affected status."
  ];

  definitionSection("Status", [
    ["Report", report.status],
    ["Advisory", advisory.primary_id],
    ["Scanner complete", scanner.completed],
    ["Scanner version", scanner.tool_version]
  ]);
  definitionSection("Exact snapshot", [
    ["Repository", repository.canonical_url],
    ["Resolved ref", repository.resolved_ref],
    ["Commit", repository.commit_sha],
    ["Archive digest", repository.archive_sha256]
  ]);
  listSection("Dependency findings", [
    ...entryTexts(entries, "target_metadata"),
    ...entryTexts(entries, "deterministic_fact")
  ]);
  listSection("Evidence", uniqueSupportIds(entries), "wide");
  listSection("Model synthesis", [
    ...entryTexts(entries, "model_inference"),
    ...claims
  ], "inference");
  listSection("Coverage gaps", [
    ...entryTexts(entries, "coverage_gap"),
    ...coverageLines(report.coverage)
  ], "warning");
  listSection("Limitations", limitations, "warning");
  listSection("Validation actions", validationActions);
  updateAiFromReport(investigation);
}

function renderRemediation(plan) {
  structured.replaceChildren();
  const snapshot = plan.snapshot && typeof plan.snapshot === "object" ? plan.snapshot : {};
  const candidates = Array.isArray(plan.candidates) ? plan.candidates : [];
  const candidateLines = candidates.map((candidate) => {
    const coordinate = candidate && candidate.current_coordinate ? candidate.current_coordinate : {};
    return `${valueText(coordinate.ecosystem)} ${valueText(coordinate.name)} ${valueText(coordinate.version)} → ${valueText(candidate.raw_source_reported_target)}`;
  });
  definitionSection("Status", [
    ["Plan", plan.status],
    ["Advisory", plan.advisory_id],
    ["Partial", plan.partial]
  ]);
  definitionSection("Exact snapshot", [
    ["Repository", snapshot.repository_url],
    ["Commit", snapshot.commit_sha],
    ["Archive digest", snapshot.archive_sha256]
  ]);
  listSection("Remediation candidates", candidateLines);
  listSection("Evidence", candidates.flatMap((candidate) => Array.isArray(candidate.dependency_evidence_ids) ? candidate.dependency_evidence_ids : []), "wide");
  listSection("Coverage gaps", [
    ...coverageLines(plan.coverage),
    ...(Array.isArray(plan.warnings) ? plan.warnings : []),
    ...(Array.isArray(plan.conflicts) ? plan.conflicts : [])
  ], "warning");
  listSection("Limitations", [
    plan.no_change_statement,
    "Candidate availability, compatibility, deployment applicability, generated artifacts, testing, and remediation completeness remain unverified."
  ], "warning");
  listSection("Validation actions", Array.isArray(plan.validation_actions) ? plan.validation_actions : []);
}

function renderNonJson(kind) {
  structured.replaceChildren();
  listSection(
    kind === "remediation" ? "Remediation plan" : "Investigation report",
    ["Structured sections require JSON format. The unchanged canonical Markdown artifact remains available below."],
    "wide"
  );
}

function requestPayload() {
  const ref = document.getElementById("ref").value;
  return {
    advisory_id: document.getElementById("advisory").value,
    repository_url: document.getElementById("repository").value,
    ref: ref === "" ? null : ref,
    view: document.getElementById("view").value,
    format: document.getElementById("format").value
  };
}

function setBusy(busy) {
  fields.disabled = busy;
  remediationButton.disabled = busy;
  cancelButton.hidden = !busy;
  if (!busy) investigateButton.disabled = !scannerReady;
}

function fixedFailure(status, scannerUnavailable) {
  if (scannerUnavailable) return "The scanner is unavailable. Run watchdog doctor, then restart the UI.";
  if (status === 400) return "Check the advisory ID, public GitHub URL, and optional advanced values.";
  if (status === 413) return "The local request exceeded its fixed size limit.";
  if (status === 503) return "An upstream source or local workflow was unavailable. No negative finding was produced.";
  return "The workflow did not produce a validated artifact. No result was inferred.";
}

async function runWorkflow(endpoint, kind) {
  const payload = requestPayload();
  activeRequest = new AbortController();
  setBusy(true);
  statusRegion.textContent = kind === "remediation"
    ? "Reviewing source-reported candidates. Nothing is being applied."
    : "Resolving the exact snapshot and building a bounded report. Results appear when complete.";
  if (kind === "investigation") {
    results.hidden = true;
    investigationComplete = false;
    remediationButton.hidden = true;
    remediationNote.hidden = true;
  }
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: {"Content-Type": "application/json", "X-Watchdog-Local-Request": "1"},
      body: JSON.stringify(payload),
      signal: activeRequest.signal
    });
    const body = await response.text();
    if (!response.ok) {
      statusRegion.textContent = fixedFailure(response.status, response.status === 503 && body.includes("scanner_unavailable"));
      return;
    }
    raw.textContent = body;
    results.hidden = false;
    resultsTitle.textContent = kind === "remediation" ? "Remediation candidate review" : "Investigation summary";
    const contentType = response.headers.get("content-type") || "";
    if (contentType.startsWith("application/json")) {
      const parsed = JSON.parse(body);
      if (kind === "remediation") renderRemediation(parsed);
      else renderReport(parsed);
    } else {
      renderNonJson(kind);
    }
    if (kind === "investigation") {
      investigationComplete = true;
      remediationButton.hidden = false;
      remediationNote.hidden = false;
      statusRegion.textContent = "Investigation complete. Review evidence, coverage gaps, and limitations.";
    } else {
      statusRegion.textContent = "Candidate review complete. Nothing was applied or written.";
    }
    resultsTitle.focus();
  } catch (error) {
    statusRegion.textContent = error && error.name === "AbortError"
      ? "Request cancelled. Repository cleanup is being verified."
      : "The local request failed. No result was inferred.";
  } finally {
    activeRequest = null;
    setBusy(false);
    if (investigationComplete) {
      remediationButton.hidden = false;
      remediationNote.hidden = false;
    }
  }
}

async function loadReadiness() {
  try {
    const response = await fetch("/api/v1/readiness", {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: {"X-Watchdog-Local-Request": "1"}
    });
    if (!response.ok) throw new Error("readiness unavailable");
    const state = await response.json();
    scannerReady = state.scanner === "ready";
    scannerState.textContent = scannerReady ? "Ready" : "Unavailable";
    aiState.textContent = state.ai === "configured" ? "Configured" : state.ai === "unavailable" ? "Unavailable" : "Off";
    remediationState.textContent = state.remediation === "enabled" ? "Enabled" : "Unavailable";
    previewState.textContent = state.previews === "enabled" ? "Enabled" : "Off";
    investigateButton.disabled = !scannerReady;
    guidance.hidden = scannerReady;
    statusRegion.textContent = scannerReady
      ? "Ready for one local investigation."
      : "Investigation is disabled until the pinned scanner is ready.";
  } catch (_error) {
    scannerReady = false;
    scannerState.textContent = "Unavailable";
    aiState.textContent = "Unavailable";
    remediationState.textContent = "Unavailable";
    previewState.textContent = "Unavailable";
    guidance.hidden = false;
    investigateButton.disabled = true;
    statusRegion.textContent = "Local readiness could not be verified.";
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  if (scannerReady && activeRequest === null) runWorkflow("/api/v1/investigations", "investigation");
});

remediationButton.addEventListener("click", () => {
  if (investigationComplete && activeRequest === null) runWorkflow("/api/v1/remediations", "remediation");
});

cancelButton.addEventListener("click", () => {
  if (activeRequest !== null) activeRequest.abort();
});

loadReadiness();
