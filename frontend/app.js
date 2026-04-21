const uploadBtn = document.getElementById("uploadBtn");
const fileInput = document.getElementById("pcapFile");
const statusDiv = document.getElementById("status");
const resultsDiv = document.getElementById("results");
const totalPacketsEl = document.getElementById("totalPackets");
const tcpPercentageEl = document.getElementById("tcpPercentage");
const udpPercentageEl = document.getElementById("udpPercentage");
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

let protocolChartInstance = null;
let sourceIpChartInstance = null;
let destinationIpChartInstance = null;

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

    setStatus("success", `Analysis complete: ${data.filename}`);
    renderResults(data.analysis);
    resultsDiv.classList.remove("hidden");
  } catch (error) {
    setStatus("error", "Could not connect to backend.");
    console.error(error);
  } finally {
    setLoading(false);
  }
});

function renderResults(analysis) {
  totalPacketsEl.textContent = analysis.total_packets;
  tcpPercentageEl.textContent = `${analysis.tcp_percentage ?? 0}%`;
  udpPercentageEl.textContent = `${analysis.udp_percentage ?? 0}%`;

  renderTopPorts(analysis.top_ports || []);
  renderFlaggedPorts(analysis.flagged_ports || []);
  renderAnalystSummary(analysis);

  renderProtocolChart(analysis.protocol_distribution);
  renderSourceIpChart(analysis.top_source_ips);
  renderDestinationIpChart(analysis.top_destination_ips);
}

function setLoading(isLoading) {
  uploadBtn.disabled = isLoading;
  uploadBtn.classList.toggle("is-loading", isLoading);
  uploadBtn.textContent = isLoading ? "Analyzing..." : "Analyze Capture";
}

function setStatus(type, message) {
  statusDiv.className = `status status-${type}`;
  statusDiv.textContent = message;
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

function renderAnalystSummary(analysis) {
  const topProtocol = getTopItem(analysis.protocol_distribution, "protocol");
  const dominantPort = getTopItem(analysis.top_ports, "port");
  const topSource = getTopItem(analysis.top_source_ips, "ip");
  const topDestination = getTopItem(analysis.top_destination_ips, "ip");
  const flagged = analysis.flagged_ports || [];
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
    `This capture is mostly ${topProtocol.value} traffic with ${topProtocol.count} packets. ` +
    `Top talkers are ${topSource.value} (source) and ${topDestination.value} (destination).`;

  detailProtocolEl.textContent = `Dominant protocol: ${topProtocol.value} (${topProtocol.count} packets).`;
  detailSourceEl.textContent = `Busiest source host: ${topSource.value} (${topSource.count} packets).`;
  detailDestinationEl.textContent = `Busiest destination host: ${topDestination.value} (${topDestination.count} packets).`;
  detailUnusualPortsEl.textContent = unusualObserved
    ? `Unusual ports observed: Yes (${flagged.length} flagged). Examples: ${unusualPortsPreview}.`
    : "Unusual ports observed: No obvious unusual ports flagged.";
  detailRiskNoteEl.textContent = `Quick risk note: ${riskNote}`;

  riskLevelEl.textContent = `Risk: ${risk}`;
  topProtocolEl.textContent = `Top Protocol: ${topProtocol.value}`;
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