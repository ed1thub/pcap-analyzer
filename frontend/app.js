const uploadBtn = document.getElementById("uploadBtn");
const fileInput = document.getElementById("pcapFile");
const statusDiv = document.getElementById("status");
const resultsDiv = document.getElementById("results");
const totalPacketsEl = document.getElementById("totalPackets");
const tcpPercentageEl = document.getElementById("tcpPercentage");
const udpPercentageEl = document.getElementById("udpPercentage");
const internalToExternalEl = document.getElementById("internalToExternal");
const externalToInternalEl = document.getElementById("externalToInternal");
const multicastBroadcastEl = document.getElementById("multicastBroadcast");
const packetSizeSummaryEl = document.getElementById("packetSizeSummary");
const analystSummaryEl = document.getElementById("analystSummary");
const detailProtocolEl = document.getElementById("detailProtocol");
const detailSourceEl = document.getElementById("detailSource");
const detailDestinationEl = document.getElementById("detailDestination");
const detailUnusualPortsEl = document.getElementById("detailUnusualPorts");
const detailRiskNoteEl = document.getElementById("detailRiskNote");
const riskLevelEl = document.getElementById("riskLevel");
const topProtocolEl = document.getElementById("topProtocol");
const dominantPortEl = document.getElementById("dominantPort");
const topPortsTable = document.getElementById("topPortsTable");
const flaggedPortsTable = document.getElementById("flaggedPortsTable");
const ipDrilldownTitleEl = document.getElementById("ipDrilldownTitle");
const ipDrilldownTableEl = document.getElementById("ipDrilldownTable");
const conversationsCardEl = document.getElementById("conversationsCard");
const conversationsTableEl = document.getElementById("conversationsTable");
const portClassTableEl = document.getElementById("portClassTable");
const destinationPairsTableEl = document.getElementById("destinationPairsTable");
const protocolButtons = document.querySelectorAll(".filter-btn");
const ipSearchInput = document.getElementById("ipSearch");
const showConversationsToggle = document.getElementById("showConversations");
const downloadJsonBtn = document.getElementById("downloadJsonBtn");
const exportHtmlBtn = document.getElementById("exportHtmlBtn");
const exportPdfBtn = document.getElementById("exportPdfBtn");

let protocolChartInstance = null;
let sourceIpChartInstance = null;
let destinationIpChartInstance = null;
let currentAnalysis = null;
let currentFilename = "analysis";
let selectedProtocol = "ALL";
let selectedIp = null;

const apiBaseUrl = window.location.port === "8000" ? "" : "http://127.0.0.1:8000";

uploadBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];

  if (!file) {
    setStatus("error", "Please select a .pcap or .pcapng file first.");
    return;
  }

  if (!file.name.toLowerCase().endsWith(".pcap") && !file.name.toLowerCase().endsWith(".pcapng")) {
    setStatus("error", "Unsupported file type. Use a .pcap or .pcapng capture.");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  setLoading(true);
  setExportAvailability(false);
  setStatus("loading", "Uploading and analyzing capture. This may take a moment.");
  resultsDiv.classList.add("hidden");

  try {
    const response = await fetch(`${apiBaseUrl}/upload`, {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      setStatus("error", data.detail || "Analysis failed.");
      return;
    }

    currentAnalysis = data.analysis;
    currentFilename = sanitizeFilename(data.filename || "analysis");
    selectedProtocol = "ALL";
    selectedIp = null;
    ipSearchInput.value = "";
    updateFilterButtons();
    updateDashboardView();

    setStatus("success", `Analysis complete: ${data.filename}`);
    setExportAvailability(true);
    resultsDiv.classList.remove("hidden");
  } catch (error) {
    setStatus("error", "Could not connect to backend.");
    console.error(error);
  } finally {
    setLoading(false);
  }
});

downloadJsonBtn.addEventListener("click", () => {
  if (!currentAnalysis) {
    return;
  }

  const payload = {
    generated_at: new Date().toISOString(),
    source_file: currentFilename,
    analysis: currentAnalysis
  };

  downloadFile(
    `${currentFilename}-analysis.json`,
    JSON.stringify(payload, null, 2),
    "application/json"
  );
});

exportHtmlBtn.addEventListener("click", () => {
  if (!currentAnalysis) {
    return;
  }

  const reportHtml = buildReportHtml(currentAnalysis, currentFilename);
  downloadFile(`${currentFilename}-report.html`, reportHtml, "text/html");
});

exportPdfBtn.addEventListener("click", () => {
  if (!currentAnalysis) {
    return;
  }

  if (!window.jspdf || !window.jspdf.jsPDF) {
    setStatus("error", "PDF library failed to load. Refresh and try again.");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const left = 40;
  const maxLineWidth = pageWidth - (left * 2);
  let y = 46;

  const line = (text, options = {}) => {
    const size = options.size || 11;
    const weight = options.bold ? "bold" : "normal";
    doc.setFont("helvetica", weight);
    doc.setFontSize(size);
    const lines = doc.splitTextToSize(String(text), maxLineWidth);
    doc.text(lines, left, y);
    y += (lines.length * (size + 3)) + (options.gap || 2);
  };

  const section = (title) => {
    y += 6;
    line(title, { size: 13, bold: true, gap: 4 });
  };

  const scope = currentAnalysis.ip_scope_breakdown || {};
  const packet = currentAnalysis.packet_size_stats || {};

  line("PCAP Analysis Report", { size: 18, bold: true, gap: 8 });
  line(`Source file: ${currentFilename}`);
  line(`Generated: ${new Date().toLocaleString()}`);

  section("Core Metrics");
  line(`Total packets: ${currentAnalysis.total_packets || 0}`);
  line(`TCP / UDP share: ${currentAnalysis.tcp_percentage || 0}% / ${currentAnalysis.udp_percentage || 0}%`);
  line(`Internal -> External: ${scope.internal_to_external || 0}`);
  line(`External -> Internal: ${scope.external_to_internal || 0}`);
  line(`Multicast / Broadcast: ${currentAnalysis.multicast_packets || 0} / ${currentAnalysis.broadcast_packets || 0}`);
  line(`Packet size (avg / p95): ${packet.avg || 0} / ${packet.p95 || 0} bytes`);

  section("Top Ports");
  (currentAnalysis.top_ports || []).slice(0, 8).forEach(item => {
    line(`- ${item.port}: ${item.count} (${item.label || "Unknown"})`);
  });

  section("Flagged Ports");
  const flagged = currentAnalysis.flagged_ports || [];
  if (!flagged.length) {
    line("No flagged ports detected.");
  } else {
    flagged.slice(0, 8).forEach(item => {
      line(`- ${item.port}: ${item.count} (${item.label || "N/A"}, ${item.severity || "low"})`);
    });
  }

  section("Top Destination Pairs");
  const pairs = currentAnalysis.top_destination_pairs || [];
  if (!pairs.length) {
    line("No destination pair data available.");
  } else {
    pairs.slice(0, 8).forEach(item => {
      line(`- ${item.src} -> ${item.dst}: ${item.count}`);
    });
  }

  doc.save(`${currentFilename}-report.pdf`);
});

protocolButtons.forEach(button => {
  button.addEventListener("click", () => {
    selectedProtocol = button.dataset.protocol || "ALL";
    selectedIp = null;
    updateFilterButtons();
    updateDashboardView();
  });
});

ipSearchInput.addEventListener("input", () => {
  updateDashboardView();
});

showConversationsToggle.addEventListener("change", () => {
  updateDashboardView();
});

function updateDashboardView() {
  if (!currentAnalysis) {
    return;
  }

  totalPacketsEl.textContent = currentAnalysis.total_packets;
  tcpPercentageEl.textContent = `${currentAnalysis.tcp_percentage ?? 0}%`;
  udpPercentageEl.textContent = `${currentAnalysis.udp_percentage ?? 0}%`;

  const protocolData = getProtocolData(selectedProtocol);
  const searchTerm = ipSearchInput.value.trim().toLowerCase();

  const filteredSourceIps = filterIps(protocolData.topSourceIps, searchTerm);
  const filteredDestinationIps = filterIps(protocolData.topDestinationIps, searchTerm);
  const filteredConversations = filterConversations(protocolData.conversations, searchTerm);

  renderTopPorts(protocolData.topPorts || []);
  renderFlaggedPorts(protocolData.flaggedPorts || []);
  renderConversations(filteredConversations);
  renderIpDrilldown(protocolData.ipRelatedPorts || {});
  renderAdvancedMetrics(currentAnalysis);
  renderPortClassDistribution(currentAnalysis.port_class_distribution || {});
  renderTopDestinationPairs(currentAnalysis.top_destination_pairs || []);
  renderAnalystSummary(currentAnalysis, protocolData, filteredSourceIps, filteredDestinationIps);

  renderProtocolChart(currentAnalysis.protocol_distribution || []);
  renderSourceIpChart(filteredSourceIps || []);
  renderDestinationIpChart(filteredDestinationIps || []);

  conversationsCardEl.classList.toggle("hidden", !showConversationsToggle.checked);
}

function getProtocolData(protocol) {
  const drilldown = currentAnalysis.drilldown || {};

  return {
    topSourceIps: (drilldown.top_source_ips_by_protocol || {})[protocol] || currentAnalysis.top_source_ips || [],
    topDestinationIps: (drilldown.top_destination_ips_by_protocol || {})[protocol] || currentAnalysis.top_destination_ips || [],
    topPorts: (drilldown.top_ports_by_protocol || {})[protocol] || currentAnalysis.top_ports || [],
    flaggedPorts: (drilldown.flagged_ports_by_protocol || {})[protocol] || currentAnalysis.flagged_ports || [],
    conversations: (drilldown.conversations_by_protocol || {})[protocol] || [],
    ipRelatedPorts: (drilldown.ip_related_ports_by_protocol || {})[protocol] || {}
  };
}

function setLoading(isLoading) {
  uploadBtn.disabled = isLoading;
  uploadBtn.classList.toggle("is-loading", isLoading);
  uploadBtn.textContent = isLoading ? "Analyzing..." : "Analyze Capture";
}

function setExportAvailability(isEnabled) {
  downloadJsonBtn.disabled = !isEnabled;
  exportHtmlBtn.disabled = !isEnabled;
  exportPdfBtn.disabled = !isEnabled;
}

function setStatus(type, message) {
  statusDiv.className = `status status-${type}`;
  statusDiv.textContent = message;
}

function updateFilterButtons() {
  protocolButtons.forEach(button => {
    button.classList.toggle("active", button.dataset.protocol === selectedProtocol);
  });
}

function filterIps(items, searchTerm) {
  if (!searchTerm) {
    return items;
  }

  return items.filter(item => item.ip.toLowerCase().includes(searchTerm));
}

function filterConversations(items, searchTerm) {
  if (!searchTerm) {
    return items;
  }

  return items.filter(item => {
    return (
      item.src.toLowerCase().includes(searchTerm) ||
      item.dst.toLowerCase().includes(searchTerm) ||
      item.conversation.toLowerCase().includes(searchTerm)
    );
  });
}

function renderTopPorts(data) {
  topPortsTable.innerHTML = "";

  if (!data.length) {
    topPortsTable.innerHTML = '<tr><td colspan="3" class="table-muted">No port data available.</td></tr>';
    return;
  }

  data.forEach(item => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.port}</td>
      <td>${item.count}</td>
      <td>${item.label || "Unknown"}</td>
    `;
    topPortsTable.appendChild(row);
  });
}

function renderFlaggedPorts(data) {
  flaggedPortsTable.innerHTML = "";

  if (!data.length) {
    flaggedPortsTable.innerHTML = '<tr><td colspan="4" class="table-muted">No suspicious ports detected.</td></tr>';
    return;
  }

  data.forEach(item => {
    const severity = (item.severity || "low").toLowerCase();
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.port}</td>
      <td>${item.count}</td>
      <td>${item.label || "N/A"}</td>
      <td><span class="severity-badge severity-${severity}">${capitalize(severity)}</span></td>
    `;
    flaggedPortsTable.appendChild(row);
  });
}

function renderConversations(data) {
  conversationsTableEl.innerHTML = "";

  if (!data.length) {
    conversationsTableEl.innerHTML = '<tr><td colspan="3" class="table-muted">No conversation data available.</td></tr>';
    return;
  }

  data.forEach(item => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.src}</td>
      <td>${item.dst}</td>
      <td>${item.count}</td>
    `;
    conversationsTableEl.appendChild(row);
  });
}

function renderAdvancedMetrics(analysis) {
  const scope = analysis.ip_scope_breakdown || {};
  const packet = analysis.packet_size_stats || {};

  internalToExternalEl.textContent = scope.internal_to_external || 0;
  externalToInternalEl.textContent = scope.external_to_internal || 0;
  multicastBroadcastEl.textContent = `${analysis.multicast_packets || 0} / ${analysis.broadcast_packets || 0}`;
  packetSizeSummaryEl.textContent = `${packet.avg || 0} / ${packet.p95 || 0} B`;
}

function sanitizeFilename(name) {
  return String(name)
    .replace(/\.[^/.]+$/, "")
    .replace(/[^a-zA-Z0-9-_]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    || "analysis";
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function buildReportHtml(analysis, filename) {
  const now = new Date();
  const generated = now.toLocaleString();

  const portClasses = analysis.port_class_distribution || {};
  const scope = analysis.ip_scope_breakdown || {};
  const packet = analysis.packet_size_stats || {};

  const topPortsRows = (analysis.top_ports || []).map(item =>
    `<tr><td>${escapeHtml(item.port)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.label || "Unknown")}</td></tr>`
  ).join("");

  const flaggedRows = (analysis.flagged_ports || []).map(item =>
    `<tr><td>${escapeHtml(item.port)}</td><td>${escapeHtml(item.count)}</td><td>${escapeHtml(item.label || "N/A")}</td><td>${escapeHtml(item.severity || "low")}</td></tr>`
  ).join("");

  const pairRows = (analysis.top_destination_pairs || []).map(item =>
    `<tr><td>${escapeHtml(item.src)}</td><td>${escapeHtml(item.dst)}</td><td>${escapeHtml(item.count)}</td></tr>`
  ).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PCAP Analysis Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #0f172a; }
    h1, h2 { margin: 0 0 10px; }
    .meta { margin-bottom: 18px; color: #334155; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(240px, 1fr)); gap: 12px; margin-bottom: 18px; }
    .card { border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
    th, td { border: 1px solid #cbd5e1; padding: 8px; text-align: left; }
    th { background: #f1f5f9; }
    @media print { body { margin: 10mm; } }
  </style>
</head>
<body>
  <h1>PCAP Analysis Report</h1>
  <div class="meta">Source file: ${escapeHtml(filename)} | Generated: ${escapeHtml(generated)}</div>

  <div class="grid">
    <div class="card"><strong>Total Packets:</strong> ${escapeHtml(analysis.total_packets || 0)}</div>
    <div class="card"><strong>TCP / UDP:</strong> ${escapeHtml(analysis.tcp_percentage || 0)}% / ${escapeHtml(analysis.udp_percentage || 0)}%</div>
    <div class="card"><strong>Internal -> External:</strong> ${escapeHtml(scope.internal_to_external || 0)}</div>
    <div class="card"><strong>External -> Internal:</strong> ${escapeHtml(scope.external_to_internal || 0)}</div>
    <div class="card"><strong>Multicast / Broadcast:</strong> ${escapeHtml(analysis.multicast_packets || 0)} / ${escapeHtml(analysis.broadcast_packets || 0)}</div>
    <div class="card"><strong>Packet Size Avg / P95:</strong> ${escapeHtml(packet.avg || 0)} / ${escapeHtml(packet.p95 || 0)} bytes</div>
  </div>

  <h2>Port Class Distribution</h2>
  <table>
    <tr><th>Class</th><th>Count</th></tr>
    <tr><td>Well-known (0-1023)</td><td>${escapeHtml(portClasses.well_known || 0)}</td></tr>
    <tr><td>Registered (1024-49151)</td><td>${escapeHtml(portClasses.registered || 0)}</td></tr>
    <tr><td>Dynamic (49152-65535)</td><td>${escapeHtml(portClasses.dynamic || 0)}</td></tr>
    <tr><td>Unknown</td><td>${escapeHtml(portClasses.unknown || 0)}</td></tr>
  </table>

  <h2>Top Ports</h2>
  <table>
    <tr><th>Port</th><th>Count</th><th>Service</th></tr>
    ${topPortsRows || '<tr><td colspan="3">No data</td></tr>'}
  </table>

  <h2>Flagged Ports</h2>
  <table>
    <tr><th>Port</th><th>Count</th><th>Context</th><th>Severity</th></tr>
    ${flaggedRows || '<tr><td colspan="4">No data</td></tr>'}
  </table>

  <h2>Top Destination Pairs</h2>
  <table>
    <tr><th>Source</th><th>Destination</th><th>Count</th></tr>
    ${pairRows || '<tr><td colspan="3">No data</td></tr>'}
  </table>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderPortClassDistribution(distribution) {
  portClassTableEl.innerHTML = "";

  const rows = [
    { name: "Well-known (0-1023)", count: distribution.well_known || 0 },
    { name: "Registered (1024-49151)", count: distribution.registered || 0 },
    { name: "Dynamic (49152-65535)", count: distribution.dynamic || 0 },
    { name: "Unknown", count: distribution.unknown || 0 }
  ];

  rows.forEach(item => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.name}</td>
      <td>${item.count}</td>
    `;
    portClassTableEl.appendChild(row);
  });
}

function renderTopDestinationPairs(pairs) {
  destinationPairsTableEl.innerHTML = "";

  if (!pairs.length) {
    destinationPairsTableEl.innerHTML = '<tr><td colspan="3" class="table-muted">No destination pair data available.</td></tr>';
    return;
  }

  pairs.forEach(item => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.src}</td>
      <td>${item.dst}</td>
      <td>${item.count}</td>
    `;
    destinationPairsTableEl.appendChild(row);
  });
}

function renderIpDrilldown(ipRelatedPorts) {
  ipDrilldownTableEl.innerHTML = "";

  if (!selectedIp) {
    ipDrilldownTitleEl.textContent = "Click a top source or destination IP bar to inspect related ports.";
    ipDrilldownTableEl.innerHTML = '<tr><td colspan="3" class="table-muted">No IP selected yet.</td></tr>';
    return;
  }

  const related = ipRelatedPorts[selectedIp] || [];
  ipDrilldownTitleEl.textContent = `Related ports for ${selectedIp} (${selectedProtocol})`;

  if (!related.length) {
    ipDrilldownTableEl.innerHTML = '<tr><td colspan="3" class="table-muted">No related port data for this host.</td></tr>';
    return;
  }

  related.forEach(item => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item.port}</td>
      <td>${item.count}</td>
      <td>${item.label || "Unknown"}</td>
    `;
    ipDrilldownTableEl.appendChild(row);
  });
}

function renderAnalystSummary(allAnalysis, protocolData, sourceIps, destinationIps) {
  const topProtocol = getTopItem(allAnalysis.protocol_distribution, "protocol");
  const dominantPort = getTopItem(protocolData.topPorts, "port");
  const topSource = getTopItem(sourceIps, "ip");
  const topDestination = getTopItem(destinationIps, "ip");
  const flagged = protocolData.flaggedPorts || [];
  const highFindings = flagged.filter(item => item.severity === "high").length;
  const risk = highFindings > 0 ? "High" : flagged.length > 0 ? "Medium" : "Low";
  const unusualObserved = flagged.length > 0;
  const unusualPortsPreview = flagged.slice(0, 3).map(item => item.port).join(", ");

  const riskNote =
    risk === "High"
      ? "Multiple high-severity indicators were detected. Prioritize host and service validation."
      : risk === "Medium"
        ? "Some unusual service behavior is present. Review exposed services and traffic intent."
        : "No obvious high-risk port anomalies were detected in this capture.";

  analystSummaryEl.textContent =
    `Filtered view: ${selectedProtocol} traffic. Top talkers are ${topSource.value} (source) and ${topDestination.value} (destination).`;

  detailProtocolEl.textContent = `Dominant protocol overall: ${topProtocol.value} (${topProtocol.count} packets).`;
  detailSourceEl.textContent = `Busiest source host (${selectedProtocol}): ${topSource.value} (${topSource.count} packets).`;
  detailDestinationEl.textContent = `Busiest destination host (${selectedProtocol}): ${topDestination.value} (${topDestination.count} packets).`;
  detailUnusualPortsEl.textContent = unusualObserved
    ? `Unusual ports observed (${selectedProtocol}): Yes (${flagged.length} flagged). Examples: ${unusualPortsPreview}.`
    : `Unusual ports observed (${selectedProtocol}): No obvious unusual ports flagged.`;
  detailRiskNoteEl.textContent = `Quick risk note: ${riskNote}`;

  riskLevelEl.textContent = `Risk: ${risk}`;
  topProtocolEl.textContent = `Top Protocol: ${selectedProtocol}`;
  dominantPortEl.textContent = `Dominant Port: ${dominantPort.value}`;
  riskLevelEl.dataset.risk = risk.toLowerCase();
}

function getTopItem(items = [], key) {
  if (!items.length) {
    return { value: "N/A", count: 0 };
  }

  const top = items[0];
  return {
    value: top[key],
    count: top.count || 0
  };
}

function capitalize(value) {
  if (!value) {
    return "Low";
  }

  return value.charAt(0).toUpperCase() + value.slice(1);
}

function renderProtocolChart(data) {
  const ctx = document.getElementById("protocolChart").getContext("2d");

  if (protocolChartInstance) protocolChartInstance.destroy();

  protocolChartInstance = new Chart(ctx, {
    type: "pie",
    data: {
      labels: data.map(item => item.protocol),
      datasets: [{
        data: data.map(item => item.count),
        backgroundColor: ["#0f766e", "#0ea5e9", "#f59e0b", "#64748b"],
        borderColor: "#ffffff",
        borderWidth: 2
      }]
    },
    options: {
      plugins: {
        legend: {
          position: "bottom"
        }
      }
    }
  });
}

function renderSourceIpChart(data) {
  const ctx = document.getElementById("sourceIpChart").getContext("2d");

  if (sourceIpChartInstance) sourceIpChartInstance.destroy();

  sourceIpChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.map(item => item.ip),
      datasets: [{
        label: "Packets",
        data: data.map(item => item.count),
        backgroundColor: "#0ea5e9"
      }]
    },
    options: {
      responsive: true,
      onClick: (_event, elements) => {
        if (!elements.length) {
          return;
        }
        selectedIp = data[elements[0].index].ip;
        updateDashboardView();
      },
      plugins: {
        legend: {
          display: false
        }
      },
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

function renderDestinationIpChart(data) {
  const ctx = document.getElementById("destinationIpChart").getContext("2d");

  if (destinationIpChartInstance) destinationIpChartInstance.destroy();

  destinationIpChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.map(item => item.ip),
      datasets: [{
        label: "Packets",
        data: data.map(item => item.count),
        backgroundColor: "#14b8a6"
      }]
    },
    options: {
      responsive: true,
      onClick: (_event, elements) => {
        if (!elements.length) {
          return;
        }
        selectedIp = data[elements[0].index].ip;
        updateDashboardView();
      },
      plugins: {
        legend: {
          display: false
        }
      },
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}
