# UMaT Zero Trust Access Monitoring Dashboard 🛡️

A lightweight, self-contained Zero Trust Access Monitoring Dashboard designed for the **University of Mines and Technology (UMaT)**, modeling its **Tarkwa (Main)** and **Takoradi** campuses.

Grounded in the **NIST SP 800-207 Zero Trust Architecture**, this project demonstrates continuous risk evaluation, dynamic policy decision enforcement, and real-time security operations monitoring without relying on traditional network location trust.

---

## 🏛️ Architecture & NIST SP 800-207 Grounding

The system implements the core NIST SP 800-207 pipeline:

```
[ Subject: User + Endpoint ]
            │
            ▼
[ Policy Enforcement Point (PEP) ] ── (Interdicts & Gates Access)
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

---

## 🎓 Defining Feature: Two-Campus Context (Tarkwa & Takoradi)

Every entity carries a campus dimension, making cross-campus context a first-class trust signal in evaluation:

1. **Users**: Home campus assignment (`Tarkwa`, `Takoradi`, or `Off-Campus`).
2. **Devices**: Endpoint registration (`Tarkwa`, `Takoradi`, or `Off-Campus`).
3. **Locations**: Physical network origin (`Tarkwa Main Campus`, `Takoradi Campus`, Off-Campus Ghana cities, or Untrusted Foreign/Anon origins).
4. **Resources**: Central shared systems (`Student-Records`, `LMS/Moodle`, `Admin-Console`) vs. Campus-local systems (`Tarkwa-Library-Catalog`, `Takoradi-Computer-Lab`).

### ⚖️ Trust Scoring Engine (0 – 100)
- **Baseline Score**: 50 pts
- **Device Posture**: Compliant/MDM (`+20`) vs. Unmanaged (`-25`)
- **Location Trust**: Trusted (`+15`) vs. Untrusted (`-30`)
- **Directory Identity**: Known (`+15`) vs. Untrusted/Guest (`-20`)
- **MFA Status**: Satisfied (`+15`) vs. Missing (`-15`)
- **Resource Sensitivity**: Tier 1 (`0`), Tier 2 (`-10`), Tier 3 (`-25`)
- **Campus Context Signal**:
  - **Home Campus Verification Match**: `+10 pts`
  - **Cross-Campus Physical Location Mismatch**: `-15 pts` (~90 km inter-campus travel anomaly)
  - **Cross-Campus Local Resource Attempt**: `-20 pts` (Accessing opposite campus local resource)
  - **Central Shared Resources**: `0 pts` (No campus restriction)

---

## 🚀 Getting Started

### Prerequisites
- Any modern web browser (Google Chrome, Mozilla Firefox, Microsoft Edge, Safari).
- *Optional*: Python 3.x (for serving locally via HTTP).

### Running the Dashboard

#### Option 1: Direct File Open
Simply double-click `index.html` or open it directly in your web browser.

#### Option 2: Python HTTP Server
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/umat-zero-trust-dashboard.git
cd umat-zero-trust-dashboard

# Start local server
python -m http.server 8085
```
Navigate to `http://localhost:8085` in your browser.

---

## 💡 Tech Constraints & Stack
- **Vanilla HTML5, CSS3, & ES6+ JavaScript**: Single self-contained `index.html` file.
- **Zero Dependencies**: No frameworks, build steps, or external libraries/CDNs.
- **HTML5 Canvas API**: Custom line chart rendering for rolling 60-second Requests Per Second (RPS) stream.

---

## 🛡️ License
This project is open-source and intended for academic demonstration and cybersecurity educational purposes.
