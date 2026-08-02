/**
 * UMaT Zero Trust Access Monitoring Dashboard
 * University of Mines and Technology — Tarkwa & Takoradi Campuses
 *
 * This application implements a contextual access control evaluation engine
 * grounded in the NIST Special Publication 800-207 Zero Trust Architecture.
 *
 * The core Subject → PEP → PDP (Policy Engine + Policy Administrator) → Resource
 * pipeline is modelled after NIST 800-207, Section 3 (Logical Components).
 * Trust scores are computed per-request using six weighted context signals,
 * including a custom cross-campus geographic signal unique to UMaT's dual-campus
 * topology (Tarkwa ↔ Takoradi, ~90 km apart via fiber link).
 *
 * Reference: NIST SP 800-207 — "Zero Trust Architecture" (August 2020)
 *            https://doi.org/10.6028/NIST.SP.800-207
 *
 * Author:  Naphtalie A
 * Date:    2026
 */

// Simulated Mock Data — represents identities from UMaT's directory services
const USERS = [
  // Tarkwa Campus Users
  { id: "student.tarkwa.kwame", name: "Kwame Mensah", role: "Student", homeCampus: "Tarkwa", trusted: true },
  { id: "lecturer.tarkwa.mensah", name: "Dr. Mensah", role: "Lecturer", homeCampus: "Tarkwa", trusted: true },
  { id: "staff.tarkwa.finance", name: "Kofi Owusu", role: "Finance Officer", homeCampus: "Tarkwa", trusted: true },
  { id: "admin.root.tarkwa", name: "Root Admin", role: "Domain Admin", homeCampus: "Tarkwa", trusted: true, privileged: true },
  { id: "svc.tarkwa.backup", name: "Backup Service", role: "Service Account", homeCampus: "Tarkwa", trusted: true, privileged: true },

  // Takoradi Campus Users
  { id: "student.takoradi.ama", name: "Ama Serwaa", role: "Student", homeCampus: "Takoradi", trusted: true },
  { id: "lecturer.takoradi.owusu", name: "Dr. Owusu", role: "Lecturer", homeCampus: "Takoradi", trusted: true },
  { id: "staff.takoradi.hr", name: "Esi HR", role: "HR Officer", homeCampus: "Takoradi", trusted: true },
  { id: "eng.takoradi.tech", name: "Abena Tech", role: "IT Engineer", homeCampus: "Takoradi", trusted: true },

  // External / Untrusted Accounts
  { id: "contractor.vpn", name: "External Vendor", role: "Contractor", homeCampus: "Off-Campus", trusted: false },
  { id: "guest.byod", name: "Guest User", role: "Guest", homeCampus: "Off-Campus", trusted: false }
];

const DEVICES = [
  // Tarkwa Devices
  { name: "Tarkwa-Chromebook", os: "ChromeOS", campus: "Tarkwa", compliant: true, type: "Managed" },
  { name: "Tarkwa-Library-PC", os: "Windows 10", campus: "Tarkwa", compliant: true, type: "Managed" },
  { name: "Tarkwa-Lab-Desktop", os: "Windows 11", campus: "Tarkwa", compliant: true, type: "MDM Enrolled" },
  { name: "Tarkwa-Staff-Laptop", os: "macOS", campus: "Tarkwa", compliant: true, type: "MDM Enrolled" },
  { name: "Tarkwa-Student-iPad", os: "iPadOS", campus: "Tarkwa", compliant: true, type: "MDM Enrolled" },

  // Takoradi Devices
  { name: "Takoradi-Chromebook", os: "ChromeOS", campus: "Takoradi", compliant: true, type: "Managed" },
  { name: "Takoradi-Library-PC", os: "Windows 10", campus: "Takoradi", compliant: true, type: "Managed" },
  { name: "Takoradi-Lab-Desktop", os: "Windows 11", campus: "Takoradi", compliant: true, type: "MDM Enrolled" },
  { name: "Takoradi-Staff-Laptop", os: "macOS", campus: "Takoradi", compliant: true, type: "MDM Enrolled" },
  { name: "Takoradi-Student-iPad", os: "iPadOS", campus: "Takoradi", compliant: true, type: "MDM Enrolled" },

  // Unmanaged Endpoints
  { name: "Personal-Phone", os: "Android", campus: "Off-Campus", compliant: false, type: "Unmanaged" },
  { name: "Unregistered-Laptop", os: "Windows 10", campus: "Off-Campus", compliant: false, type: "Unmanaged" }
];

// Resources are classified using a 3-tier sensitivity model:
//   Tier 1 (Low)  — Public-facing or low-risk systems (e.g. library catalog)
//   Tier 2 (Med)  — Internal systems requiring authentication (e.g. LMS, exam portal)
//   Tier 3 (High) — Privileged admin or PII systems (e.g. student records, AD)
// Resource hosting indicates whether data resides centrally or on a specific campus.
const RESOURCES = [
  // Central Shared Systems
  { name: "Student-Records", tier: 3, hosting: "Central", desc: "Transcripts & Student Database" },
  { name: "LMS/Moodle", tier: 2, hosting: "Central", desc: "E-Learning Portal" },
  { name: "Exam-System", tier: 2, hosting: "Central", desc: "Online Examination System" },
  { name: "Student-Email", tier: 1, hosting: "Central", desc: "University Webmail" },
  { name: "Admin-Console", tier: 3, hosting: "Central", desc: "Active Directory Controller" },

  // Campus-Local Systems
  { name: "Tarkwa-Library-Catalog", tier: 1, hosting: "Tarkwa", desc: "Tarkwa Main Library" },
  { name: "Tarkwa-Computer-Lab", tier: 2, hosting: "Tarkwa", desc: "Tarkwa HPC Cluster" },
  { name: "Tarkwa-Class-Materials", tier: 1, hosting: "Tarkwa", desc: "Tarkwa Course Files" },
  { name: "Takoradi-Library-Catalog", tier: 1, hosting: "Takoradi", desc: "Takoradi Branch Library" },
  { name: "Takoradi-Computer-Lab", tier: 2, hosting: "Takoradi", desc: "Takoradi CAD Lab" },
  { name: "Takoradi-Class-Materials", tier: 1, hosting: "Takoradi", desc: "Takoradi Course Files" }
];

// Locations model the network origin of each request.
// On-campus networks (Tarkwa, Takoradi) are inherently more trusted than external
// origins. Untrusted origins include known high-risk geolocations and anonymising
// proxies, which receive a trust penalty per NIST 800-207 §2.1 (implicit trust zones).
const LOCATIONS = [
  // On-Campus Networks
  { place: "Tarkwa Main Campus", city: "Tarkwa", campus: "Tarkwa", trusted: true },
  { place: "Takoradi Campus", city: "Takoradi", campus: "Takoradi", trusted: true },

  // Ghanaian Off-Campus
  { place: "Accra City", city: "Accra", campus: "Off-Campus", trusted: true },
  { place: "Kumasi City", city: "Kumasi", campus: "Off-Campus", trusted: true },
  { place: "Takoradi Town", city: "Takoradi", campus: "Off-Campus", trusted: true },

  // Untrusted Origins
  { place: "Lagos NG", city: "Lagos", campus: "Off-Campus", trusted: false },
  { place: "Moscow RU", city: "Moscow", campus: "Off-Campus", trusted: false },
  { place: "Beijing CN", city: "Beijing", campus: "Off-Campus", trusted: false },
  { place: "Tor Exit Node", city: "Anon", campus: "Off-Campus", trusted: false }
];

// App State
let currentCampusFilter = "BOTH";
let isPaused = false;
let streamTimer = null;
let requestHistory = [];
let activeAlerts = [];

let allTelemetry = {
  BOTH: { total: 0, allow: 0, mfa: 0, deny: 0 },
  Tarkwa: { total: 0, allow: 0, mfa: 0, deny: 0 },
  Takoradi: { total: 0, allow: 0, mfa: 0, deny: 0 }
};

let rpsHistory = new Array(60).fill(0);
let rpsTimer = null;
let currentSecondRequests = 0;

/**
 * Core Policy Engine — Policy Decision Point (PDP)
 *
 * Implements the trust evaluation logic described in NIST SP 800-207, §3.
 * The PDP receives context about the subject (user), device posture, resource
 * sensitivity, network location, and MFA status. It computes a composite trust
 * score (0–100) by summing weighted context signals.
 *
 * The scoring model uses six signal categories:
 *   1. Device Posture       — Is the endpoint managed and compliant? (§3.3)
 *   2. Network Location     — Is the request from a trusted campus network? (§2.1)
 *   3. User Identity        — Is the subject a verified directory user? (§3.1)
 *   4. MFA Status           — Has the subject completed step-up authentication? (§3.2)
 *   5. Resource Sensitivity — What data classification tier is being accessed? (§2.2)
 *   6. Cross-Campus Context — Novel signal: does the user's home campus match
 *                             the request origin and resource hosting? This accounts
 *                             for UMaT's geographic separation between Tarkwa and Takoradi.
 *
 * Verdict thresholds:
 *   Score >= 70  → ALLOW   (sufficient trust for direct access)
 *   Score 45–69  → STEP-UP MFA (conditional access, require additional verification)
 *   Score <  45  → DENY    (insufficient trust, block the request)
 *
 * @param {Object} userObj      — Subject identity from the user directory
 * @param {Object} deviceObj    — Endpoint posture and compliance status
 * @param {Object} resourceObj  — Target resource with sensitivity tier
 * @param {Object} locationObj  — Network origin and campus association
 * @param {boolean} mfaSatisfied — Whether multi-factor authentication was completed
 * @returns {Object} { score, verdict, factors }
 */
function evaluateTrustScore(userObj, deviceObj, resourceObj, locationObj, mfaSatisfied) {
  let score = 50; // Every request starts with a neutral baseline of 50 points
  const factors = [
    { label: "Baseline System Trust", pts: 50, isPositive: true }
  ];

  // Signal 1: Device Posture (NIST 800-207 §3.3 — Device Health Assessment)
  if (deviceObj.compliant) {
    score += 20;
    factors.push({ label: `Managed Device (${deviceObj.name})`, pts: +20, isPositive: true });
  } else {
    score -= 25;
    factors.push({ label: `Unmanaged Device (${deviceObj.name})`, pts: -25, isPositive: false });
  }

  // Signal 2: Network Location (NIST 800-207 §2.1 — Implicit Trust Zones)
  if (locationObj.trusted) {
    score += 15;
    factors.push({ label: `Trusted Location (${locationObj.place})`, pts: +15, isPositive: true });
  } else {
    score -= 30;
    factors.push({ label: `Untrusted Origin (${locationObj.place})`, pts: -30, isPositive: false });
  }

  // Signal 3: User Identity (NIST 800-207 §3.1 — Subject Identification)
  if (userObj.trusted) {
    score += 15;
    factors.push({ label: `Verified Directory User (${userObj.role})`, pts: +15, isPositive: true });
  } else {
    score -= 20;
    factors.push({ label: `Guest / Untrusted Account (${userObj.role})`, pts: -20, isPositive: false });
  }

  // Signal 4: Multi-Factor Authentication (NIST 800-207 §3.2 — Continuous Verification)
  if (mfaSatisfied) {
    score += 15;
    factors.push({ label: "MFA Challenge Verified", pts: +15, isPositive: true });
  } else {
    score -= 15;
    factors.push({ label: "MFA Missing", pts: -15, isPositive: false });
  }

  // Signal 5: Resource Sensitivity Tier (NIST 800-207 §2.2 — Data Classification)
  if (resourceObj.tier === 1) {
    factors.push({ label: "Low Sensitivity Resource (Tier 1)", pts: 0, isPositive: true });
  } else if (resourceObj.tier === 2) {
    score -= 10;
    factors.push({ label: "Medium Sensitivity Resource (Tier 2)", pts: -10, isPositive: false });
  } else if (resourceObj.tier === 3) {
    score -= 25;
    factors.push({ label: "High Sensitivity Resource (Tier 3)", pts: -25, isPositive: false });
  }

  // Signal 6: Cross-Campus Context — UMaT-specific extension
  // This is not part of the standard NIST framework. It penalises requests where
  // a user's home campus does not match their current location or the campus
  // hosting the target resource. This captures the trust gap created by UMaT's
  // geographic separation (~90 km Tarkwa ↔ Takoradi).
  const userHome = userObj.homeCampus;
  const locCampus = locationObj.campus;
  const resHosting = resourceObj.hosting;

  if (locCampus !== "Off-Campus") {
    if (locCampus === userHome) {
      score += 10;
      factors.push({ label: `Home Campus Match (${userHome})`, pts: +10, isPositive: true });
    } else if (userHome !== "Off-Campus") {
      score -= 15;
      factors.push({ label: `Cross-Campus Mismatch (Home: ${userHome}, Current: ${locCampus})`, pts: -15, isCampusPenalty: true });
    }
  }

  if (resHosting === "Central") {
    factors.push({ label: "Central Shared Resource", pts: 0, isPositive: true });
  } else {
    if (resHosting === userHome) {
      score += 5;
      factors.push({ label: `Local Resource Match (${resHosting})`, pts: +5, isPositive: true });
    } else {
      score -= 20;
      factors.push({ label: `Cross-Campus Local Resource Attempt (${userHome} → ${resHosting})`, pts: -20, isCampusPenalty: true });
    }
  }

  const finalScore = Math.min(100, Math.max(0, score));

  let verdict = "DENY";
  if (finalScore >= 70) verdict = "ALLOW";
  else if (finalScore >= 45) verdict = "STEP-UP MFA";
  else verdict = "DENY";

  return {
    score: finalScore,
    verdict: verdict,
    factors: factors
  };
}

// Lifecycle Initialization
window.addEventListener("DOMContentLoaded", () => {
  populateTesterDropdowns();
  renderDevicePosture();
  initCanvasCharts();
  startStreamSimulation();
  runTesterEvaluation();
});

function setCampusFilter(campusName) {
  currentCampusFilter = campusName;

  document.getElementById("btnFilterBoth").className = `campus-pill ${campusName === 'BOTH' ? 'active' : ''}`;
  document.getElementById("btnFilterTarkwa").className = `campus-pill ${campusName === 'Tarkwa' ? 'active' : ''}`;
  document.getElementById("btnFilterTakoradi").className = `campus-pill ${campusName === 'Takoradi' ? 'active' : ''}`;

  document.getElementById("filterStatusInfo").textContent = 
    campusName === "BOTH" ? "Combined Telemetry (Tarkwa + Takoradi)" :
    `Scope: ${campusName} Campus Only`;

  updateKpiUI();
  renderStreamTableFiltered();
  renderDevicePosture();
  renderAlertsUI();
}

function populateTesterDropdowns() {
  const uSel = document.getElementById("selectUser");
  const dSel = document.getElementById("selectDevice");
  const rSel = document.getElementById("selectResource");
  const lSel = document.getElementById("selectLocation");

  if (!uSel || !dSel || !rSel || !lSel) return;

  USERS.forEach((u, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = `${u.name} (${u.role} - Home: ${u.homeCampus})`;
    uSel.appendChild(opt);
  });

  DEVICES.forEach((d, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = `${d.name} [${d.campus} - ${d.compliant ? "Compliant" : "Non-compliant"}]`;
    dSel.appendChild(opt);
  });

  RESOURCES.forEach((r, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = `${r.name} (Tier ${r.tier} - ${r.hosting})`;
    rSel.appendChild(opt);
  });

  LOCATIONS.forEach((l, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = `${l.place} [${l.campus}] (${l.trusted ? "Trusted" : "Untrusted"})`;
    lSel.appendChild(opt);
  });
}

function renderDevicePosture() {
  const container = document.getElementById("postureContainer");
  if (!container) return;

  container.innerHTML = "";
  const campuses = currentCampusFilter === "BOTH" ? ["Tarkwa", "Takoradi", "Off-Campus"] : [currentCampusFilter];

  campuses.forEach(camp => {
    const campDevices = DEVICES.filter(d => d.campus === camp);
    if (campDevices.length === 0) return;

    const groupHeader = document.createElement("div");
    groupHeader.className = "posture-group-title";
    groupHeader.textContent = camp === "Off-Campus" ? "External Endpoints" : `${camp} Campus Endpoints`;
    container.appendChild(groupHeader);

    const listDiv = document.createElement("div");
    listDiv.className = "posture-list";

    campDevices.forEach(dev => {
      const item = document.createElement("div");
      item.className = "posture-item";

      const score = dev.compliant ? 100 : 35;
      const barColor = dev.compliant ? "#10b981" : "#ef4444";
      const statusText = dev.compliant ? "Managed & Compliant" : "Non-Compliant";

      item.innerHTML = `
        <div class="posture-meta">
          <span class="posture-name">${dev.name} <span style="font-size: 10px; color: #64748b;">(${dev.os})</span></span>
          <span class="posture-status" style="color: ${barColor}; font-weight: 700;">${statusText}</span>
        </div>
        <div class="posture-bar-bg">
          <div class="posture-bar-fill" style="width: ${score}%; background-color: ${barColor};"></div>
        </div>
      `;
      listDiv.appendChild(item);
    });

    container.appendChild(listDiv);
  });
}

function startStreamSimulation() {
  scheduleNextRequest();

  rpsTimer = setInterval(() => {
    rpsHistory.shift();
    rpsHistory.push(currentSecondRequests);
    currentSecondRequests = 0;

    const currentRps = (rpsHistory.reduce((a, b) => a + b, 0) / 60).toFixed(1);
    const counterEl = document.getElementById("rpsCounter");
    if (counterEl) counterEl.textContent = `${currentRps} req/sec avg`;
    drawRpsChart();
  }, 1000);
}

let trafficMultiplier = 0.90; // Reduced traffic volume by 10%

function scheduleNextRequest() {
  if (streamTimer) clearTimeout(streamTimer);

  const baseDelay = Math.floor(Math.random() * 1000) + 1100;
  const delay = Math.round(baseDelay / trafficMultiplier);

  streamTimer = setTimeout(() => {
    if (!isPaused) {
      generateRandomAccessRequest();
    }
    scheduleNextRequest();
  }, delay);
}

function generateRandomAccessRequest(overrideData = null) {
  let u, d, r, l, mfa;

  if (overrideData) {
    u = overrideData.user;
    d = overrideData.device;
    r = overrideData.resource;
    l = overrideData.location;
    mfa = overrideData.mfa;
  } else {
    u = USERS[Math.floor(Math.random() * USERS.length)];
    d = DEVICES[Math.floor(Math.random() * DEVICES.length)];
    r = RESOURCES[Math.floor(Math.random() * RESOURCES.length)];
    l = LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)];
    mfa = Math.random() > 0.35;
  }

  const evalResult = evaluateTrustScore(u, d, r, l, mfa);
  const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });

  let primaryCampus = "Tarkwa";
  if (l.campus === "Takoradi" || u.homeCampus === "Takoradi") {
    primaryCampus = "Takoradi";
  }

  const isCrossCampus = (u.homeCampus !== "Off-Campus" && l.campus !== "Off-Campus" && u.homeCampus !== l.campus) ||
                       (r.hosting !== "Central" && u.homeCampus !== "Off-Campus" && u.homeCampus !== r.hosting);

  const reqObj = {
    id: "REQ-" + Math.floor(100000 + Math.random() * 900000),
    time: timestamp,
    timestampMs: Date.now(),
    user: u,
    device: d,
    resource: r,
    location: l,
    mfa: mfa,
    primaryCampus: primaryCampus,
    isCrossCampus: isCrossCampus,
    score: evalResult.score,
    verdict: evalResult.verdict,
    factors: evalResult.factors
  };

  requestHistory.unshift(reqObj);
  if (requestHistory.length > 100) requestHistory.pop();

  updateTelemetryCounters(reqObj);
  currentSecondRequests++;

  updateKpiUI();
  renderStreamTableFiltered();
  animateNistPipeline(reqObj);
  evaluateSecurityAlerts(reqObj);
}

function updateTelemetryCounters(req) {
  const camp = req.primaryCampus;

  allTelemetry.BOTH.total++;
  if (req.verdict === "ALLOW") allTelemetry.BOTH.allow++;
  else if (req.verdict === "STEP-UP MFA") allTelemetry.BOTH.mfa++;
  else allTelemetry.BOTH.deny++;

  if (allTelemetry[camp]) {
    allTelemetry[camp].total++;
    if (req.verdict === "ALLOW") allTelemetry[camp].allow++;
    else if (req.verdict === "STEP-UP MFA") allTelemetry[camp].mfa++;
    else allTelemetry[camp].deny++;
  }
}

function updateKpiUI() {
  const stats = allTelemetry[currentCampusFilter];

  const totalEl = document.getElementById("kpiTotalReq");
  const allowEl = document.getElementById("kpiAllowed");
  const mfaEl = document.getElementById("kpiMfa");
  const denyEl = document.getElementById("kpiDenied");

  if (!totalEl) return;

  totalEl.textContent = stats.total;
  allowEl.textContent = stats.allow;
  mfaEl.textContent = stats.mfa;
  denyEl.textContent = stats.deny;

  const total = stats.total || 1;
  document.getElementById("kpiAllowPct").textContent = `${Math.round((stats.allow / total) * 100)}%`;
  document.getElementById("kpiMfaPct").textContent = `${Math.round((stats.mfa / total) * 100)}%`;
  document.getElementById("kpiDenyPct").textContent = `${Math.round((stats.deny / total) * 100)}%`;

  const breakDivs = ['breakdownTotal', 'breakdownAllow', 'breakdownMfa', 'breakdownDeny'];
  const keys = ['total', 'allow', 'mfa', 'deny'];

  breakDivs.forEach((divId, index) => {
    const div = document.getElementById(divId);
    if (!div) return;
    if (currentCampusFilter === "BOTH") {
      div.style.display = "flex";
      div.children[0].textContent = `Tarkwa: ${allTelemetry.Tarkwa[keys[index]]}`;
      div.children[1].textContent = `Takoradi: ${allTelemetry.Takoradi[keys[index]]}`;
    } else {
      div.style.display = "none";
    }
  });
}

function renderStreamTableFiltered() {
  const tbody = document.getElementById("streamTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const filtered = requestHistory.filter(r => {
    if (currentCampusFilter === "BOTH") return true;
    return r.primaryCampus === currentCampusFilter || r.user.homeCampus === currentCampusFilter || r.resource.hosting === currentCampusFilter;
  }).slice(0, 20);

  filtered.forEach((req, idx) => {
    const tr = document.createElement("tr");
    if (idx === 0) tr.className = "new-row";
    if (req.isCrossCampus) tr.classList.add("cross-campus-row");

    let badgeClass = "badge-deny";
    if (req.verdict === "ALLOW") badgeClass = "badge-allow";
    else if (req.verdict === "STEP-UP MFA") badgeClass = "badge-mfa";

    const userCampShort = req.user.homeCampus.replace(" Campus", "");
    const resCampShort = req.resource.hosting;
    const vectorStr = req.isCrossCampus ? 
      `<span class="badge badge-cross">${userCampShort} → ${resCampShort}</span>` :
      `<span style="font-size: 11px; color: #94a3b8;">${userCampShort}</span>`;

    tr.innerHTML = `
      <td class="mono text-muted">${req.time}</td>
      <td><strong>${req.user.id}</strong> <span style="font-size: 10px; color: #64748b;">(${userCampShort})</span></td>
      <td>${req.device.name} ${req.device.compliant ? "✓" : "⚠️"}</td>
      <td>${req.resource.name} <span class="mono" style="font-size: 10px; color: #64748b;">[${resCampShort}]</span></td>
      <td>${vectorStr}</td>
      <td><span class="score-chip">${req.score}</span></td>
      <td><span class="badge ${badgeClass}">${req.verdict}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function animateNistPipeline(req) {
  const tag = document.getElementById("pipelineActiveTag");
  const subjDetail = document.getElementById("nodeSubjectDetail");
  const resDetail = document.getElementById("nodeResourceDetail");

  if (!tag || !subjDetail || !resDetail) return;

  subjDetail.textContent = `${req.user.id} (${req.user.homeCampus})`;
  resDetail.textContent = `${req.resource.name} [${req.resource.hosting}]`;

  tag.textContent = `PDP Eval: ${req.user.id} → ${req.verdict}`;
  if (req.verdict === "ALLOW") {
    tag.style.color = "#34d399";
    tag.style.borderColor = "rgba(16, 185, 129, 0.4)";
  } else if (req.verdict === "STEP-UP MFA") {
    tag.style.color = "#fbbf24";
    tag.style.borderColor = "rgba(245, 158, 11, 0.4)";
  } else {
    tag.style.color = "#f87171";
    tag.style.borderColor = "rgba(239, 68, 68, 0.4)";
  }

  const pepNode = document.getElementById("nodePEP");
  if (pepNode) {
    pepNode.style.borderColor = req.verdict === "ALLOW" ? "#10b981" : (req.verdict === "STEP-UP MFA" ? "#f59e0b" : "#ef4444");
    setTimeout(() => {
      pepNode.style.borderColor = "#334155";
    }, 700);
  }
}

function evaluateSecurityAlerts(latestReq) {
  // Impossible travel check
  const previousUserReq = requestHistory.find(r => 
    r !== latestReq &&
    r.user.id === latestReq.user.id &&
    (Date.now() - r.timestampMs) < 60000 &&
    r.location.campus !== "Off-Campus" &&
    latestReq.location.campus !== "Off-Campus" &&
    r.location.campus !== latestReq.location.campus
  );

  if (previousUserReq) {
    addAlert({
      type: "IMPOSSIBLE_TRAVEL",
      title: "Inter-Campus Travel Anomaly (~90km)",
      desc: `User [${latestReq.user.id}] authenticated from ${previousUserReq.location.place} and ${latestReq.location.place} within 60s.`,
      action: "Enforced DENY & Triggered SOC Alert",
      severity: "danger"
    });
  }

  // Cross-campus resource check
  if (latestReq.resource.hosting !== "Central" && 
      latestReq.user.homeCampus !== "Off-Campus" && 
      latestReq.user.homeCampus !== latestReq.resource.hosting) {
    addAlert({
      type: "CROSS_CAMPUS_ACCESS",
      title: "Cross-Campus Resource Access",
      desc: `${latestReq.user.homeCampus} user [${latestReq.user.id}] accessed ${latestReq.resource.hosting}-local system [${latestReq.resource.name}].`,
      action: `Applied -20 pt Cross-Campus Penalty (${latestReq.verdict})`,
      severity: "cross-campus"
    });
  }

  // Brute force threshold check
  const recentUserDenies = requestHistory.filter(r => 
    r.user.id === latestReq.user.id &&
    (Date.now() - r.timestampMs) < 120000 &&
    r.verdict === "DENY"
  ).length;

  if (recentUserDenies >= 3 && latestReq.verdict === "DENY") {
    addAlert({
      type: "BRUTE_FORCE",
      title: "Repeated Deny Threshold Exceeded",
      desc: `User [${latestReq.user.id}] accumulated ${recentUserDenies} DENY decisions within 2 minutes.`,
      action: "Triggered temporary account cooldown",
      severity: "danger"
    });
  }

  // Unmanaged device accessing sensitive resource
  if (!latestReq.device.compliant && latestReq.resource.tier >= 2) {
    addAlert({
      type: "NON_COMPLIANT_ACCESS",
      title: "Unmanaged Device Access",
      desc: `Unmanaged device [${latestReq.device.name}] requested Tier ${latestReq.resource.tier} resource [${latestReq.resource.name}].`,
      action: `Verdict: ${latestReq.verdict} (Score: ${latestReq.score})`,
      severity: latestReq.resource.tier === 3 ? "danger" : "warning"
    });
  }

  // Privileged identity anomaly
  if (latestReq.user.privileged && (!latestReq.location.trusted || !latestReq.device.compliant)) {
    addAlert({
      type: "PRIVILEGED_ANOMALY",
      title: "Privileged Identity Anomaly",
      desc: `Privileged account [${latestReq.user.id}] initiated request from unverified context (${latestReq.location.place}).`,
      action: "Enforced Step-Up MFA & Audit Log",
      severity: "warning"
    });
  }
}

function addAlert(alertObj) {
  const isDup = activeAlerts.slice(0, 5).some(a => a.title === alertObj.title && a.desc === alertObj.desc);
  if (isDup) return;

  alertObj.time = new Date().toLocaleTimeString('en-US', { hour12: false });
  activeAlerts.unshift(alertObj);
  if (activeAlerts.length > 20) activeAlerts.pop();

  renderAlertsUI();
}

function renderAlertsUI() {
  const container = document.getElementById("alertsList");
  const countBadge = document.getElementById("alertCountBadge");
  if (!container || !countBadge) return;

  countBadge.textContent = `${activeAlerts.length} Active`;

  if (activeAlerts.length === 0) {
    container.innerHTML = `<div class="text-muted" style="font-size: 12px; text-align: center; padding: 20px;">No security anomalies detected.</div>`;
    return;
  }

  container.innerHTML = "";
  activeAlerts.slice(0, 10).forEach(alert => {
    const div = document.createElement("div");
    div.className = `alert-card ${alert.severity}`;

    let icon = "•";
    if (alert.severity === "warning") icon = "!";
    else if (alert.severity === "danger") icon = "×";

    div.innerHTML = `
      <div class="alert-icon">${icon}</div>
      <div class="alert-content">
        <div class="alert-title">
          <span>${alert.title}</span>
          <span class="alert-time">${alert.time}</span>
        </div>
        <div class="alert-desc">${alert.desc}</div>
        <div class="alert-action">Action: ${alert.action}</div>
      </div>
    `;
    container.appendChild(div);
  });
}

let chartCanvas, chartCtx;

function initCanvasCharts() {
  chartCanvas = document.getElementById("rpsChart");
  if (!chartCanvas) return;

  chartCtx = chartCanvas.getContext("2d");
  resizeCanvas();
  window.addEventListener("resize", resizeCanvas);
  drawRpsChart();
}

function resizeCanvas() {
  if (!chartCanvas || !chartCanvas.parentElement) return;
  const rect = chartCanvas.parentElement.getBoundingClientRect();
  chartCanvas.width = rect.width * window.devicePixelRatio;
  chartCanvas.height = rect.height * window.devicePixelRatio;
  chartCtx.scale(window.devicePixelRatio, window.devicePixelRatio);
}

function drawRpsChart() {
  if (!chartCanvas || !chartCtx || !chartCanvas.parentElement) return;
  const w = chartCanvas.parentElement.clientWidth;
  const h = chartCanvas.parentElement.clientHeight;

  chartCtx.clearRect(0, 0, w, h);

  chartCtx.strokeStyle = "#1e293b";
  chartCtx.lineWidth = 1;

  for (let y = 20; y < h; y += 40) {
    chartCtx.beginPath();
    chartCtx.moveTo(0, y);
    chartCtx.lineTo(w, y);
    chartCtx.stroke();
  }

  const maxVal = Math.max(5, Math.max(...rpsHistory) + 2);
  const stepX = w / (rpsHistory.length - 1);

  chartCtx.beginPath();
  chartCtx.strokeStyle = "#38bdf8";
  chartCtx.lineWidth = 2;

  for (let i = 0; i < rpsHistory.length; i++) {
    const x = i * stepX;
    const y = h - ((rpsHistory[i] / maxVal) * (h - 30)) - 15;
    if (i === 0) chartCtx.moveTo(x, y);
    else chartCtx.lineTo(x, y);
  }
  chartCtx.stroke();

  chartCtx.lineTo(w, h);
  chartCtx.lineTo(0, h);
  chartCtx.closePath();

  const grad = chartCtx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, "rgba(56, 189, 248, 0.2)");
  grad.addColorStop(1, "rgba(56, 189, 248, 0.0)");
  chartCtx.fillStyle = grad;
  chartCtx.fill();
}

function runTesterEvaluation() {
  const uSel = document.getElementById("selectUser");
  const dSel = document.getElementById("selectDevice");
  const rSel = document.getElementById("selectResource");
  const lSel = document.getElementById("selectLocation");
  const chkMfa = document.getElementById("chkMfa");

  if (!uSel || !dSel || !rSel || !lSel || !chkMfa) return;

  const userObj = USERS[uSel.value];
  const deviceObj = DEVICES[dSel.value];
  const resourceObj = RESOURCES[rSel.value];
  const locationObj = LOCATIONS[lSel.value];

  const result = evaluateTrustScore(userObj, deviceObj, resourceObj, locationObj, chkMfa.checked);

  const resultBox = document.getElementById("testerResultBox");
  const scoreVal = document.getElementById("testerScoreVal");
  const badge = document.getElementById("testerVerdictBadge");
  const factorList = document.getElementById("testerFactorList");

  if (!resultBox) return;

  resultBox.style.display = "block";
  scoreVal.textContent = result.score;

  if (result.verdict === "ALLOW") {
    scoreVal.style.color = "#34d399";
    badge.textContent = "VERDICT: ALLOW";
    badge.className = "verdict-tag badge-allow";
  } else if (result.verdict === "STEP-UP MFA") {
    scoreVal.style.color = "#fbbf24";
    badge.textContent = "VERDICT: STEP-UP MFA";
    badge.className = "verdict-tag badge-mfa";
  } else {
    scoreVal.style.color = "#f87171";
    badge.textContent = "VERDICT: DENY";
    badge.className = "verdict-tag badge-deny";
  }

  factorList.innerHTML = "";
  result.factors.forEach(f => {
    const item = document.createElement("div");
    item.className = "factor-item";

    const sign = f.pts > 0 ? `+${f.pts}` : `${f.pts}`;
    let ptsClass = f.isPositive ? "factor-positive" : (f.pts < 0 ? "factor-negative" : "text-muted");
    if (f.isCampusPenalty) ptsClass = "factor-campus-penalty";

    item.innerHTML = `
      <span>${f.label}</span>
      <span class="factor-pts ${ptsClass}">${sign} pts</span>
    `;
    factorList.appendChild(item);
  });
}

function togglePause() {
  isPaused = !isPaused;
  const btn = document.getElementById("btnTogglePause");
  const dot = document.getElementById("liveDot");
  const text = document.getElementById("liveStatusText");

  if (!btn || !dot || !text) return;

  if (isPaused) {
    btn.textContent = "Resume Stream";
    text.textContent = "Stream Paused";
    dot.style.backgroundColor = "#f59e0b";
    dot.style.boxShadow = "0 0 8px #f59e0b";
  } else {
    btn.textContent = "Pause Stream";
    text.textContent = "Live Stream";
    dot.style.backgroundColor = "#10b981";
    dot.style.boxShadow = "0 0 8px #10b981";
  }
}

function triggerAttackScenario() {
  if (isPaused) togglePause();

  const tarkwaStudent = USERS.find(u => u.id === "student.tarkwa.kwame") || USERS[0];
  const takoradiResource = RESOURCES.find(r => r.name === "Takoradi-Computer-Lab") || RESOURCES[9];

  generateRandomAccessRequest({
    user: tarkwaStudent,
    device: DEVICES.find(d => d.name === "Tarkwa-Chromebook"),
    resource: RESOURCES.find(r => r.name === "Student-Email"),
    location: LOCATIONS.find(l => l.place === "Tarkwa Main Campus"),
    mfa: true
  });

  setTimeout(() => {
    generateRandomAccessRequest({
      user: tarkwaStudent,
      device: DEVICES.find(d => d.name === "Personal-Phone"),
      resource: takoradiResource,
      location: LOCATIONS.find(l => l.place === "Takoradi Campus"),
      mfa: false
    });
  }, 300);

  setTimeout(() => {
    generateRandomAccessRequest({
      user: tarkwaStudent,
      device: DEVICES.find(d => d.name === "Unregistered-Laptop"),
      resource: takoradiResource,
      location: LOCATIONS.find(l => l.place === "Takoradi Campus"),
      mfa: false
    });
  }, 600);

  setTimeout(() => {
    generateRandomAccessRequest({
      user: USERS.find(u => u.id === "contractor.vpn"),
      device: DEVICES.find(d => d.name === "Personal-Phone"),
      resource: RESOURCES.find(r => r.name === "Admin-Console"),
      location: LOCATIONS.find(l => l.place === "Tor Exit Node"),
      mfa: false
    });
  }, 900);
}

function switchTab(tabId) {
  const tabMonitor = document.getElementById("tabMonitor");
  const tabSimulator = document.getElementById("tabSimulator");
  const btnMonitor = document.getElementById("tabBtnMonitor");
  const btnSimulator = document.getElementById("tabBtnSimulator");

  if (!tabMonitor || !tabSimulator || !btnMonitor || !btnSimulator) return;

  if (tabId === "monitor") {
    tabMonitor.style.display = "block";
    tabSimulator.style.display = "none";
    btnMonitor.classList.add("active");
    btnSimulator.classList.remove("active");
    setTimeout(() => {
      resizeCanvas();
      drawRpsChart();
    }, 50);
  } else if (tabId === "simulator") {
    tabMonitor.style.display = "none";
    tabSimulator.style.display = "block";
    btnMonitor.classList.remove("active");
    btnSimulator.classList.add("active");
  }
}

/**
 * Toggles the visibility of the About modal overlay.
 */
function toggleAboutModal() {
  const modal = document.getElementById("aboutModal");
  if (modal) {
    modal.classList.toggle("visible");
  }
}
