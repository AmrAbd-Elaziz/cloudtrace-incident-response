"use strict";

const DATA_URL = "data.json";

const attackStages = [
  {
    number: "01",
    title: "Discovery",
    description:
      "Identity, IAM permissions and cloud storage were enumerated.",
    events: [
      "GetCallerIdentity",
      "ListUsers",
      "ListBuckets",
      "GetAccountAuthorizationDetails",
    ],
  },
  {
    number: "02",
    title: "Persistence",
    description:
      "A secondary IAM identity and access key were created.",
    events: [
      "CreateUser",
      "CreateAccessKey",
    ],
  },
  {
    number: "03",
    title: "Privilege Escalation",
    description:
      "AdministratorAccess was attached to the new identity.",
    events: [
      "AttachUserPolicy",
    ],
  },
  {
    number: "04",
    title: "Defense Evasion",
    description:
      "CloudTrail logging was stopped and deletion was attempted.",
    events: [
      "StopLogging",
      "DeleteTrail",
    ],
  },
  {
    number: "05",
    title: "Collection",
    description:
      "S3 configuration and objects were inspected and accessed.",
    events: [
      "GetBucketEncryption",
      "ListObjects",
      "GetObject",
    ],
  },
];

let dashboardData = null;
let allFindings = [];

function getElement(id) {
  const element = document.getElementById(id);

  if (!element) {
    throw new Error(`Missing dashboard element: ${id}`);
  }

  return element;
}

function createElement(tag, className, text) {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  if (text !== undefined) {
    element.textContent = text;
  }

  return element;
}

function setText(id, value) {
  getElement(id).textContent = String(value);
}

function formatAssessmentDate(value) {
  const date = new Date(`${value}T00:00:00Z`);

  return new Intl.DateTimeFormat(
    "en-US",
    {
      month: "short",
      day: "numeric",
      year: "numeric",
      timeZone: "UTC",
    },
  ).format(date);
}

function formatTimestamp(value) {
  return value
    .replace("T", " ")
    .replace("Z", " UTC");
}

function formatShortTime(value) {
  const date = new Date(value);

  return new Intl.DateTimeFormat(
    "en-GB",
    {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      timeZone: "UTC",
    },
  ).format(date);
}

function formatDuration(totalSeconds) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  return `${minutes}m ${seconds}s`;
}

function severityClass(severity) {
  return `badge-${severity.toLowerCase()}`;
}

function renderOverview(data) {
  const { incident, metrics } = data;

  setText(
    "assessment-date",
    formatAssessmentDate(data.assessment_date),
  );
  setText(
    "incident-severity",
    incident.classification,
  );
  setText(
    "affected-identity",
    incident.affected_identity,
  );
  setText(
    "created-identity",
    incident.created_identity,
  );
  setText(
    "target-resource",
    incident.target_resource,
  );
  setText(
    "incident-window",
    `${formatShortTime(incident.start_time)}–` +
      `${formatShortTime(incident.end_time)} UTC`,
  );

  setText(
    "critical-findings",
    metrics.critical_findings,
  );
  setText(
    "events-analyzed",
    metrics.events_analyzed,
  );
  setText(
    "detection-findings",
    metrics.detection_findings,
  );
  setText(
    "sigma-rule-count",
    metrics.sigma_rules,
  );
  setText(
    "incident-duration",
    formatDuration(incident.duration_seconds),
  );

  const tacticCount = Object.values(
    data.mitre_tactics,
  ).filter((count) => count > 0).length;

  setText("attack-tactics", tacticCount);
}

function renderAttackPath(timeline) {
  const container = getElement(
    "attack-path-container",
  );

  container.replaceChildren();

  for (const stage of attackStages) {
    const stageEvents = timeline.filter(
      (event) => stage.events.includes(event.event_name),
    );

    const card = createElement(
      "article",
      "attack-stage",
    );

    const numberRow = createElement(
      "div",
      "attack-stage-number",
    );
    numberRow.append(
      createElement("span", "", `STAGE ${stage.number}`),
      createElement("span"),
    );

    const title = createElement(
      "h3",
      "",
      stage.title,
    );

    const description = createElement(
      "p",
      "",
      stage.description,
    );

    const eventLabel = createElement(
      "span",
      "attack-stage-events",
      stageEvents
        .map((event) => event.event_name)
        .join(" · "),
    );

    card.append(
      numberRow,
      title,
      description,
      eventLabel,
    );

    container.append(card);
  }
}

function renderBarChart(
  containerId,
  values,
  useSeverityColors = false,
) {
  const container = getElement(containerId);
  const entries = Object.entries(values);
  const maximum = Math.max(
    ...entries.map(([, value]) => value),
    1,
  );

  container.replaceChildren();

  for (const [label, value] of entries) {
    const row = createElement("div", "chart-row");
    const labelElement = createElement(
      "span",
      "chart-label",
      label,
    );
    const track = createElement(
      "div",
      "chart-track",
    );

    const colorClass = useSeverityColors
      ? label.toLowerCase()
      : "";

    const fill = createElement(
      "div",
      `chart-fill ${colorClass}`.trim(),
    );

    fill.style.width = value
      ? `${Math.max((value / maximum) * 100, 3)}%`
      : "0";

    fill.setAttribute(
      "aria-label",
      `${label}: ${value}`,
    );

    track.append(fill);

    const count = createElement(
      "span",
      "chart-value",
      value,
    );

    row.append(
      labelElement,
      track,
      count,
    );

    container.append(row);
  }
}

function createBadge(value, className) {
  return createElement(
    "span",
    `badge ${className}`,
    value,
  );
}

function renderFindings(findings) {
  const body = getElement(
    "findings-table-body",
  );
  const emptyState = getElement("empty-state");

  body.replaceChildren();

  for (const finding of findings) {
    const row = document.createElement("tr");

    const idCell = createElement(
      "td",
      "event-code",
      finding.finding_id,
    );

    const titleCell = createElement(
      "td",
      "finding-title",
      finding.title,
    );

    const eventCell = createElement("td");
    eventCell.append(
      createElement(
        "code",
        "event-code",
        finding.event_name,
      ),
    );

    const tacticCell = createElement(
      "td",
      "",
      finding.mitre_tactic,
    );

    const severityCell = createElement("td");
    severityCell.append(
      createBadge(
        finding.severity,
        severityClass(finding.severity),
      ),
    );

    const outcomeCell = createElement("td");
    outcomeCell.append(
      createBadge(
        finding.outcome,
        finding.outcome === "Success"
          ? "badge-success"
          : "badge-failed",
      ),
    );

    const timeCell = createElement(
      "td",
      "event-code",
      formatShortTime(finding.event_time),
    );

    row.append(
      idCell,
      titleCell,
      eventCell,
      tacticCell,
      severityCell,
      outcomeCell,
      timeCell,
    );

    body.append(row);
  }

  setText(
    "visible-findings",
    `${findings.length} of ${allFindings.length} findings`,
  );

  emptyState.hidden = findings.length !== 0;
}

function applyFindingFilters() {
  const query = getElement(
    "finding-search",
  ).value.trim().toLowerCase();

  const severity = getElement(
    "severity-filter",
  ).value;

  const outcome = getElement(
    "outcome-filter",
  ).value;

  const filtered = allFindings.filter(
    (finding) => {
      const searchableText = [
        finding.finding_id,
        finding.title,
        finding.event_name,
        finding.mitre_tactic,
        finding.mitre_technique,
        finding.resource,
        finding.actor,
        finding.source_ip,
      ]
        .join(" ")
        .toLowerCase();

      const matchesSearch =
        !query || searchableText.includes(query);

      const matchesSeverity =
        severity === "all" ||
        finding.severity === severity;

      const matchesOutcome =
        outcome === "all" ||
        finding.outcome === outcome;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesOutcome
      );
    },
  );

  renderFindings(filtered);
}

function configureFilters() {
  getElement("finding-search").addEventListener(
    "input",
    applyFindingFilters,
  );

  getElement("severity-filter").addEventListener(
    "change",
    applyFindingFilters,
  );

  getElement("outcome-filter").addEventListener(
    "change",
    applyFindingFilters,
  );
}

function addIndicator(
  container,
  label,
  values,
) {
  const item = createElement(
    "div",
    "indicator-item",
  );

  const labelElement = createElement(
    "span",
    "",
    label,
  );

  const valueElement = createElement(
    "code",
    "",
    values.length ? values.join(", ") : "None",
  );

  item.append(
    labelElement,
    valueElement,
  );

  container.append(item);
}

function renderIndicators(indicators) {
  const container = getElement("indicator-list");

  container.replaceChildren();

  addIndicator(
    container,
    "Source IP",
    indicators.source_ip_addresses,
  );
  addIndicator(
    container,
    "Observed actor",
    indicators.observed_actors,
  );
  addIndicator(
    container,
    "Created identity",
    indicators.created_users,
  );
  addIndicator(
    container,
    "Accessed bucket",
    indicators.accessed_s3_buckets,
  );
}

function renderSigmaRules(rules) {
  const container = getElement("sigma-rule-list");

  container.replaceChildren();

  for (const rule of rules) {
    const item = createElement(
      "article",
      "sigma-item",
    );

    const content = createElement("div");
    content.append(
      createElement("h3", "", rule.title),
      createElement("p", "", rule.file),
    );

    const metadata = createElement(
      "div",
      "rule-meta",
    );

    metadata.append(
      createBadge(
        rule.level,
        severityClass(rule.level),
      ),
      createBadge(
        rule.status,
        "badge-success",
      ),
    );

    item.append(content, metadata);
    container.append(item);
  }
}

function renderDashboard(data) {
  dashboardData = data;
  allFindings = [...data.findings];

  renderOverview(data);
  renderAttackPath(data.timeline);

  renderBarChart(
    "severity-chart",
    data.severity_distribution,
    true,
  );

  renderBarChart(
    "tactic-chart",
    data.mitre_tactics,
  );

  renderFindings(allFindings);
  renderIndicators(data.indicators);
  renderSigmaRules(data.sigma_rules);
  configureFilters();
}

function renderLoadError(error) {
  console.error(error);

  const containers = [
    "attack-path-container",
    "severity-chart",
    "tactic-chart",
    "indicator-list",
    "sigma-rule-list",
  ];

  for (const id of containers) {
    const container = getElement(id);
    container.replaceChildren(
      createElement(
        "p",
        "error-message",
        "Unable to load dashboard evidence.",
      ),
    );
  }

  const body = getElement(
    "findings-table-body",
  );
  body.replaceChildren();

  setText(
    "visible-findings",
    "Evidence loading failed",
  );
}

async function loadDashboard() {
  try {
    const response = await fetch(
      DATA_URL,
      {
        cache: "no-store",
      },
    );

    if (!response.ok) {
      throw new Error(
        `Dashboard data request failed: ${response.status}`,
      );
    }

    const data = await response.json();

    renderDashboard(data);
  } catch (error) {
    renderLoadError(error);
  }
}

document.addEventListener(
  "DOMContentLoaded",
  loadDashboard,
);