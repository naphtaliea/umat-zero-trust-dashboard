# UMaT Zero Trust Access Monitoring Dashboard

A self-contained Zero Trust Access Monitoring Dashboard built for the **University of Mines and Technology (UMaT)**, modelling real-time access control across its **Tarkwa (Main)** and **Takoradi** campuses.

The system is grounded in the **NIST Special Publication 800-207 — Zero Trust Architecture** (August 2020). It demonstrates how continuous, per-request risk evaluation can replace traditional perimeter-based network trust in a multi-campus university environment.

> **Reference**: Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero Trust Architecture*. NIST SP 800-207. https://doi.org/10.6028/NIST.SP.800-207

---

## Architecture & NIST SP 800-207 Grounding

The dashboard implements the **Subject → PEP → PDP → Resource** logical architecture described in NIST 800-207, Section 3:

```
[ Subject: User + Endpoint ]
            │
            ▼
[ Policy Enforcement Point (PEP) ] ── (Intercepts & gates every request)
            │
            ▼
┌─────────────────────────────────────────────────────────┐
│            Policy Decision Point (PDP)                  │
│  ┌─────────────────────────┐   ┌─────────────────────┐  │
│  │   Policy Engine (PE)    │   │ Policy Administrator│  │
│  │ (Evaluates Context Score│ ─►│        (PA)         │  │
│  │         0-100)          │   │  (Issues Decision)  │  │
│  └─────────────────────────┘   └─────────────────────┘  │
└─────────────────────────────────────────────────────────┘
            │
            ▼
   [ Target Resource ] (Central or Campus-Local)
```

The PDP evaluates each access request by computing a **composite trust score (0–100)** from six weighted context signals. The resulting verdict determines whether the request is allowed, requires step-up MFA, or is denied outright.

---

## Why Zero Trust for UMaT?

Traditional perimeter-based security assumes that users inside the campus network can be trusted. Zero Trust rejects this assumption entirely — every request is evaluated independently, regardless of where it originates.

UMaT presents a particularly interesting case study because it operates across **two campuses separated by approximately 90 km** (Tarkwa and Takoradi), connected by a fiber backbone. This geographic separation creates unique trust evaluation challenges:

- A student registered at Tarkwa accessing resources from the Takoradi campus network represents a legitimate but anomalous pattern that warrants additional scrutiny.
- Campus-local resources (e.g., Tarkwa Library Catalog) should not be freely accessible from the opposite campus without elevated trust verification.
- Central shared systems (e.g., Student Records, LMS) should remain campus-agnostic.

This dashboard models all of these scenarios through a **cross-campus context signal** — an extension to the standard NIST framework that treats geographic and administrative campus separation as a first-class trust dimension.

---

## Trust Scoring Engine (0–100)

Every access request starts with a neutral baseline of **50 points**. Six context signals are then applied:

| # | Signal | NIST Reference | Positive | Negative |
|---|--------|---------------|----------|----------|
| 1 | **Device Posture** — Is the endpoint managed and compliant? | §3.3 | +20 (MDM enrolled) | −25 (unmanaged) |
| 2 | **Network Location** — Is the request from a trusted network? | §2.1 | +15 (campus network) | −30 (untrusted origin) |
| 3 | **User Identity** — Is the subject a verified directory user? | §3.1 | +15 (known identity) | −20 (guest/untrusted) |
| 4 | **MFA Status** — Has step-up authentication been completed? | §3.2 | +15 (MFA verified) | −15 (MFA missing) |
| 5 | **Resource Sensitivity** — What tier is the target resource? | §2.2 | 0 (Tier 1) | −10 (Tier 2), −25 (Tier 3) |
| 6 | **Cross-Campus Context** — Does campus alignment match? | *Custom* | +10 (home match), +5 (local resource) | −15 (campus mismatch), −20 (cross-campus local) |

### Verdict Thresholds

| Score Range | Verdict | Action |
|------------|---------|--------|
| **70–100** | ALLOW | Direct access granted |
| **45–69** | STEP-UP MFA | Conditional access — additional verification required |
| **0–44** | DENY | Request blocked |

---

## Two-Campus Data Model

Every entity in the system carries a campus dimension:

- **Users**: Home campus assignment (`Tarkwa`, `Takoradi`, or `Off-Campus`)
- **Devices**: Endpoint registration and compliance status per campus
- **Locations**: Network origin mapped to campus or external geolocation
- **Resources**: Classified as `Central` (shared) or campus-local (`Tarkwa` / `Takoradi`)

---

## Getting Started

### Prerequisites
- Any modern web browser (Chrome, Firefox, Edge, Safari).
- *Optional*: Python 3.x for serving via HTTP.

### Running the Dashboard

**Option 1 — Direct File Launch (Zero Setup)**
Double-click `index.html` or drag it into your browser. No terminal, server, or build step required.

**Option 2 — Python HTTP Server**
```bash
python -m http.server 3000
```
Then open `http://localhost:3000` in your browser.

---

## Project Structure

```
zero-trust-dashboard/
├── index.html          # Semantic HTML layout and page structure
├── css/
│   └── styles.css      # Design system, layout, and component styles
├── js/
│   └── app.js          # Zero Trust policy engine, simulation, and UI logic
└── README.md           # Architecture documentation and usage guide
```

---

## Technology Stack
- **Vanilla HTML5, CSS3, and ES6+ JavaScript** — no frameworks or external dependencies
- **HTML5 Canvas API** — custom line chart for rolling 60-second RPS visualisation
- **Zero build step** — open `index.html` directly in any browser

---

## Author

**Naphtalie A**
University of Mines and Technology, Tarkwa
© 2026

---

## License
This project is open-source and intended for academic demonstration and cybersecurity education.
