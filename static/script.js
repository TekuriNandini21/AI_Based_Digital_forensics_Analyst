/* ==========================================================
   script.js
   Renders all dashboard Plotly charts from the STATS object
   injected into the page by dashboard.html.
   ========================================================== */

(function () {
  if (typeof STATS === "undefined" || typeof Plotly === "undefined") return;

  const layoutBase = {
    paper_bgcolor: "transparent",
    plot_bgcolor: "transparent",
    font: { color: "#8a93a8", size: 11 },
    margin: { l: 40, r: 20, t: 10, b: 40 },
    showlegend: false,
  };

  const config = { displayModeBar: false, responsive: true };

  // --------- Severity Distribution (Pie) ---------
  const sevLabels = ["Critical", "High", "Medium", "Low"];
  const sevValues = [
    STATS.critical_alerts, STATS.high_risk, STATS.medium_risk, STATS.low_risk
  ];
  const sevColors = ["#ef4444", "#f97316", "#eab308", "#22c55e"];

  Plotly.newPlot("severityChart", [{
    labels: sevLabels,
    values: sevValues,
    type: "pie",
    hole: 0.55,
    marker: { colors: sevColors, line: { color: "#0d1424", width: 2 } },
    textfont: { color: "#e6ecf7", size: 11 },
  }], { ...layoutBase, margin: { l: 10, r: 10, t: 10, b: 10 } }, config);

  // --------- Event Distribution (Bar) ---------
  const eventDist = STATS.event_distribution || [];
  Plotly.newPlot("eventChart", [{
    x: eventDist.map(e => e.c),
    y: eventDist.map(e => e.category),
    type: "bar",
    orientation: "h",
    marker: { color: "#2f6fed" },
  }], {
    ...layoutBase,
    xaxis: { gridcolor: "#1c2740", zeroline: false },
    yaxis: { automargin: true },
  }, config);

  // --------- Top Source IPs ---------
  const topSrc = STATS.top_source_ips || [];
  Plotly.newPlot("sourceIpChart", [{
    x: topSrc.map(e => e.source_ip),
    y: topSrc.map(e => e.c),
    type: "bar",
    marker: { color: "#ef4444" },
  }], {
    ...layoutBase,
    xaxis: { tickangle: -30 },
    yaxis: { gridcolor: "#1c2740" },
  }, config);

  // --------- Top Destination IPs ---------
  const topDst = STATS.top_destination_ips || [];
  Plotly.newPlot("destIpChart", [{
    x: topDst.map(e => e.destination_ip),
    y: topDst.map(e => e.c),
    type: "bar",
    marker: { color: "#f97316" },
  }], {
    ...layoutBase,
    xaxis: { tickangle: -30 },
    yaxis: { gridcolor: "#1c2740" },
  }, config);

  // --------- Top Users ---------
  const topUsers = STATS.top_users || [];
  Plotly.newPlot("usersChart", [{
    x: topUsers.map(e => e.username),
    y: topUsers.map(e => e.c),
    type: "bar",
    marker: { color: "#22d3ee" },
  }], {
    ...layoutBase,
    xaxis: { tickangle: -30 },
    yaxis: { gridcolor: "#1c2740" },
  }, config);

  // --------- Recent Activity Timeline (Scatter) ---------
  const activities = (STATS.recent_activities || []).slice().reverse();
  const severityToY = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const severityToColor = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#22c55e" };

  Plotly.newPlot("timelineChart", [{
    x: activities.map(a => a.timestamp),
    y: activities.map(a => severityToY[a.severity] || 1),
    mode: "markers",
    type: "scatter",
    text: activities.map(a => `${a.category}: ${a.description || ""}`),
    hoverinfo: "text+x",
    marker: {
      size: 12,
      color: activities.map(a => severityToColor[a.severity] || "#2f6fed"),
      line: { color: "#0d1424", width: 1 },
    },
  }], {
    ...layoutBase,
    xaxis: { gridcolor: "#1c2740", title: "" },
    yaxis: {
      gridcolor: "#1c2740",
      tickvals: [1, 2, 3, 4],
      ticktext: ["Low", "Medium", "High", "Critical"],
      range: [0.5, 4.5],
    },
  }, config);

  window.addEventListener("resize", () => {
    ["timelineChart", "severityChart", "eventChart", "sourceIpChart", "destIpChart", "usersChart"]
      .forEach(id => { try { Plotly.Plots.resize(document.getElementById(id)); } catch (e) {} });
  });
})();
