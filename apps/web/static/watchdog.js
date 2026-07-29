"use strict";

const form = document.getElementById("investigation-form");
const statusRegion = document.getElementById("status");
const resultRegion = document.getElementById("result");
const disclaimer = document.getElementById("disclaimer");
const metadata = document.getElementById("metadata");
const reportId = document.getElementById("report-id");
const reportStatus = document.getElementById("report-status");
const commit = document.getElementById("commit");
const scannerVersion = document.getElementById("scanner-version");
const download = document.getElementById("download");
let currentBody = null;
let currentType = null;
let currentId = null;

function clearResult() {
  currentBody = null;
  currentType = null;
  currentId = null;
  resultRegion.textContent = "";
  reportId.textContent = "";
  reportStatus.textContent = "";
  commit.textContent = "";
  scannerVersion.textContent = "";
  disclaimer.hidden = true;
  metadata.hidden = true;
  download.disabled = true;
}

form.addEventListener("reset", () => {
  clearResult();
  statusRegion.textContent = "No investigation has run.";
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearResult();
  statusRegion.textContent = "Investigation in progress.";
  const ref = document.getElementById("ref").value;
  const payload = {
    advisory_id: document.getElementById("advisory").value,
    repository_url: document.getElementById("repository").value,
    ref: ref === "" ? null : ref,
    view: document.getElementById("view").value,
    format: document.getElementById("format").value
  };
  try {
    const response = await fetch("/api/v1/investigations", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: {"Content-Type": "application/json", "X-Watchdog-Local-Request": "1"},
      body: JSON.stringify(payload)
    });
    const text = await response.text();
    if (!response.ok) {
      statusRegion.textContent = "The investigation did not produce a report.";
      resultRegion.textContent = text;
      return;
    }
    currentBody = text;
    currentType = response.headers.get("content-type") || "text/plain";
    const responseReportId = response.headers.get("x-watchdog-report-id");
    currentId = responseReportId && /^report:sha256:[0-9a-f]{64}$/.test(responseReportId) ? responseReportId : null;
    resultRegion.textContent = text;
    disclaimer.hidden = false;
    statusRegion.textContent = "Investigation complete. Review all coverage limitations.";
    if (currentType.startsWith("application/json")) {
      const parsed = JSON.parse(text);
      reportId.textContent = currentId || "Unavailable";
      reportStatus.textContent = typeof parsed.status === "string" ? parsed.status : "Unavailable";
      commit.textContent = parsed.repository && typeof parsed.repository.commit_sha === "string" ? parsed.repository.commit_sha : "Unavailable";
      scannerVersion.textContent = parsed.scanner && typeof parsed.scanner.tool_version === "string" ? parsed.scanner.tool_version : "Unavailable";
      metadata.hidden = false;
    } else {
      reportId.textContent = currentId || "Unavailable";
      reportStatus.textContent = response.headers.get("x-watchdog-report-status") || "Unavailable";
      commit.textContent = "See rendered report";
      scannerVersion.textContent = "See rendered report";
      metadata.hidden = false;
    }
    download.disabled = false;
  } catch (_error) {
    statusRegion.textContent = "The local request failed.";
  }
});

download.addEventListener("click", () => {
  if (currentBody === null) return;
  const extension = currentType && currentType.startsWith("application/json") ? "json" : "md";
  const safeId = currentId && /^report:sha256:[0-9a-f]{64}$/.test(currentId) ? currentId.slice(-64) : "investigation";
  const url = URL.createObjectURL(new Blob([currentBody], {type: currentType || "text/plain"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = `watchdog-${safeId}.${extension}`;
  link.click();
  URL.revokeObjectURL(url);
});
