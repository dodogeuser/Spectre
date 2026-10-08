"use strict";
(() => {
  let epoch = 0;
  const el = id => document.getElementById(id);
  window.resetAI = () => {
    epoch++;
    el("ai-panel").hidden = true;
    el("ai-answer").replaceChildren();
    el("ai-question").value = "";
    el("ai-status").textContent = "";
    el("ai-ask").disabled = false;
  };
  el("ai-open").onclick = async () => {
    const token = epoch, caseId = selectedCase.id;
    try {
      const status = await api(`/api/cases/${caseId}/ai/status`);
      if (token !== epoch || selectedCase.id !== caseId) return;
      el("ai-panel").hidden = false;
      el("ai-status").textContent = status.configured
        ? `${status.provider} / ${status.model}. Local model must be running.`
        : "AI is not configured. The investigation workspace remains fully available.";
    } catch (error) { if (token === epoch) showError(error); }
  };
  el("ai-form").onsubmit = async event => {
    event.preventDefault();
    const token = epoch, caseId = selectedCase.id;
    el("ai-ask").disabled = true;
    el("ai-answer").textContent = "Preparing a read-only answer from stored case records…";
    try {
      const answer = await api(`/api/cases/${caseId}/ai/questions`, "POST", {question: el("ai-question").value});
      if (token !== epoch || selectedCase.id !== caseId) return;
      el("ai-answer").replaceChildren();
      const message = document.createElement("p");
      message.textContent = answer.message;
      el("ai-answer").append(message);
      for (const claim of answer.claims) {
        const section = document.createElement("section"), category = document.createElement("h4"), text = document.createElement("p");
        category.textContent = claim.category.replaceAll("_", " ");
        text.textContent = claim.text;
        section.append(category, text);
        for (const id of claim.evidence_ids) section.append(domainEvidenceLink(id, caseId));
        // Navigation uses server-owned record identifiers, never model-generated URLs.
        for (const record of claim.records) {
          if (!["finding", "entity", "relationship"].includes(record.type) || !Number.isSafeInteger(record.id)) continue;
          const link = document.createElement("a");
          link.textContent = `${record.type} #${record.id}`;
          link.href = `/api/cases/${caseId}/${record.type === "entity" ? "entities" : record.type === "relationship" ? "relationships" : "findings"}/${record.id}${record.type === "entity" ? "/detail" : ""}`;
          // Relationships have a case-scoped list API rather than a detail route.
          if (record.type === "relationship") link.href = `/api/cases/${caseId}/relationships`;
          link.target = "_blank"; link.rel = "noopener"; section.append(link);
        }
        el("ai-answer").append(section);
      }
      if (answer.truncated) {
        const note = document.createElement("p"); note.textContent = "Context was bounded. This answer does not cover every stored record."; el("ai-answer").append(note);
      }
    } catch (error) { if (token === epoch && selectedCase.id === caseId) el("ai-answer").textContent = error.message; }
    finally { if (token === epoch) el("ai-ask").disabled = false; }
  };
})();
