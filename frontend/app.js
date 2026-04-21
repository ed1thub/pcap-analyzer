const uploadBtn = document.getElementById("uploadBtn");
const fileInput = document.getElementById("pcapFile");
const statusDiv = document.getElementById("status");
const resultsDiv = document.getElementById("results");
const totalPacketsEl = document.getElementById("totalPackets");
const topPortsTable = document.getElementById("topPortsTable");
const flaggedPortsTable = document.getElementById("flaggedPortsTable");

let protocolChartInstance = null;
let sourceIpChartInstance = null;
let destinationIpChartInstance = null;

uploadBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];

  if (!file) {
    statusDiv.textContent = "Please select a .pcap file first.";
    return;
  }

  const formData = new FormData();
  formData.append("file", file);

  statusDiv.textContent = "Uploading and analyzing...";
  resultsDiv.classList.add("hidden");

  try {
    const response = await fetch("http://localhost:8000/upload", {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      statusDiv.textContent = data.detail || "Analysis failed.";
      return;
    }

    statusDiv.textContent = `Analysis complete: ${data.filename}`;
    renderResults(data.analysis);
    resultsDiv.classList.remove("hidden");
  } catch (error) {
    statusDiv.textContent = "Could not connect to backend.";
    console.error(error);
  }
});

function renderResults(analysis) {
  totalPacketsEl.textContent = analysis.total_packets;

  renderTable(topPortsTable, analysis.top_ports, "port");
  renderTable(flaggedPortsTable, analysis.flagged_ports, "port");

  renderProtocolChart(analysis.protocol_distribution);
  renderSourceIpChart(analysis.top_source_ips);
  renderDestinationIpChart(analysis.top_destination_ips);
}

function renderTable(tableBody, data, keyName) {
  tableBody.innerHTML = "";

  data.forEach(item => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${item[keyName]}</td>
      <td>${item.count}</td>
    `;
    tableBody.appendChild(row);
  });
}

function renderProtocolChart(data) {
  const ctx = document.getElementById("protocolChart").getContext("2d");

  if (protocolChartInstance) protocolChartInstance.destroy();

  protocolChartInstance = new Chart(ctx, {
    type: "pie",
    data: {
      labels: data.map(item => item.protocol),
      datasets: [{
        data: data.map(item => item.count)
      }]
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
        data: data.map(item => item.count)
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: false
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
        data: data.map(item => item.count)
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: false
        }
      }
    }
  });
}