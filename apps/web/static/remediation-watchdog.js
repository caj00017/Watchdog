"use strict";

const form = document.getElementById("workflow-form");
const statusRegion = document.getElementById("status");
const resultRegion = document.getElementById("result");
const disclaimer = document.getElementById("disclaimer");
const metadata = document.getElementById("metadata");
const artifactId = document.getElementById("artifact-id");
const artifactStatus = document.getElementById("artifact-status");
const commit = document.getElementById("commit");

function clearResult() {
  resultRegion.textContent = "";
  artifactId.textContent = "";
  artifactStatus.textContent = "";
  commit.textContent = "";
  disclaimer.hidden = true;
  metadata.hidden = true;
}

form.addEventListener("reset", () => {
  clearResult();
  statusRegion.textContent = "No workflow has run.";
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearResult();
  statusRegion.textContent = "Workflow in progress.";
  const mode = document.getElementById("mode").value;
  const endpoint = mode === "remediate" ? "/api/v1/remediations" : "/api/v1/investigations";
  const ref = document.getElementById("ref").value;
  const payload = {
    advisory_id: document.getElementById("advisory").value,
    repository_url: document.getElementById("repository").value,
    ref: ref === "" ? null : ref,
    view: document.getElementById("view").value,
    format: document.getElementById("format").value
  };
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: {"Content-Type": "application/json", "X-Watchdog-Local-Request": "1"},
      body: JSON.stringify(payload)
    });
    const text = await response.text();
    resultRegion.textContent = text;
    if (!response.ok) {
      statusRegion.textContent = "The workflow did not produce an artifact.";
      return;
    }
    const remediation = mode === "remediate";
    const idHeader = remediation ? "x-watchdog-remediation-plan-id" : "x-watchdog-report-id";
    const statusHeader = remediation ? "x-watchdog-remediation-status" : "x-watchdog-report-status";
    artifactId.textContent = response.headers.get(idHeader) || "Unavailable";
    artifactStatus.textContent = response.headers.get(statusHeader) || "Unavailable";
    if ((response.headers.get("content-type") || "").startsWith("application/json")) {
      const parsed = JSON.parse(text);
      commit.textContent = parsed.snapshot && typeof parsed.snapshot.commit_sha === "string"
        ? parsed.snapshot.commit_sha
        : parsed.repository && typeof parsed.repository.commit_sha === "string"
          ? parsed.repository.commit_sha
          : "Unavailable";
    } else {
      commit.textContent = "See rendered artifact";
    }
    disclaimer.hidden = false;
    metadata.hidden = false;
    statusRegion.textContent = "Workflow complete. Review all coverage limitations.";
  } catch (_error) {
    statusRegion.textContent = "The local request failed.";
  }
});
