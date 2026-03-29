# Arbiter

**Control what AI sees. Verify what AI says.**

Arbiter is a bidirectional AI governance middleware that enforces access control before the LLM sees data, detects causal inference channels that leak denied information through authorized data combinations, catches multi-turn accumulation attacks across conversation turns, and scans the LLM's response for hallucinated or leaked restricted data before it reaches the user.

Built for FERPA and HIPAA compliance in regulated industries where unauthorized AI data access isn't just a bug — it's a violation.

---

## The Problem

1. **Input governance exists. Output governance doesn't.** You perfectly filter what the LLM sees, but the model hallucinates a salary from training data. Your filter was perfect. The response still leaked.

2. **Individual access checks pass. Combinations leak.** A teacher sees the department budget ($283,000), faculty count (2), and their own salary ($95,000). Simple math: the other professor earns $188,000. Every field was individually authorized. The combination is a violation.

3. **Single-query checks pass. Multi-turn attacks succeed.** A user asks for the research budget in turn 1, the TA stipend pool in turn 2, the operating budget in turn 3. Each query passes. Across three turns, they've reconstructed the total budget that was withheld.

4. **Policies don't scale.** Add a resource, manually update three config files. Add a role, manually list every permitted resource. Arbiter resolves access at runtime from clearance × sensitivity — zero code changes.

---

## How It Works

```
User Query
    │
    ▼
┌──────────────────┐
│ 1. Identity      │  Who is this? What clearance level?
│ 2. ABAC Policy   │  Clearance × Sensitivity → Allow/Deny
│ 3. Query Intent  │  Minimum necessary access (FERPA/HIPAA)
│ 4. Inference     │  Can authorized fields derive denied fields?
│    Control       │  Template-based causal channel detection
│ 5. Data Filter   │  Generic, scalable — zero hardcoded resources
│ 6. TTL Check     │  Data freshness verification
│ 7. Context       │  CCP v3.0 tamper-detectable governance record
│    Packet        │
│ 8. Audit Log     │  Non-blocking pipeline (file + memory + console)
│ 9. Cross-Query   │  Multi-turn accumulation attack detection
│    Detection     │
└──────────────────┘
    │
    ▼  Filtered context → LLM
    │
    ▼  LLM response
┌──────────────────┐
│ 10. Output       │  Leakage: denied values in response
│     Scanner      │  Hallucination: data not in filtered context
│                  │  Mask breach: SSN patterns detected
│ 11. Sanitize     │  Redact violations, log, return clean response
└──────────────────┘
    │
    ▼
Sanitized Response → User
```

---

## What Makes This Novel

| Existing tools | Arbiter |
|---|---|
| Filter input to the LLM | Filter input AND scan output |
| Check individual field access | Detect when field *combinations* leak denied data |
| Check single queries | Detect multi-turn accumulation attacks across conversation |
| Hardcode permissions per role | Resolve access at runtime from clearance × sensitivity (ABAC) |
| Static inference rules | Template-based inference channels that scale to any data schema |
| Log what was accessed | Log input governance, inference control, output scanning, and cross-query detection |
| University-only | Domain-agnostic: university (FERPA) and hospital (HIPAA) from same engine |

---

## Quick Start

```bash
git clone https://github.com/SiddhiRohan/arbiter.git
cd arbiter/server
pip install -r requirements.txt
python test_engine.py
python -m uvicorn main:app --reload --port 8000
```

| URL | Page |
|---|---|
| `localhost:8000` | Governed chat (React) |
| `localhost:8000/demo` | Split-screen: ungoverned vs governed |
| `localhost:8000/admin` | Admin dashboard (5 tabs) |
| `localhost:8000/docs` | Interactive API docs |

### Demo Credentials

| Username | Role | Person | Clearance |
|---|---|---|---|
| `admin` | Admin | Robert Torres (Dean) | Full-Access |
| `teacher` | Teacher | Sarah Chen (CS) | Department-Scoped |
| `teacher2` | Teacher | James Washington (CS) | Department-Scoped |
| `advisor` | Advisor | Priya Sharma (Math) | Department-Scoped |
| `student` | Student | Alex Rivera (CS) | Self-Scoped |
| `student2` | Student | Carlos Mendez (Math) | Self-Scoped |
| `ta` | TA | Lena Kowalski (CS) | Course-Scoped |

Optional: create `server/.env` with `ANTHROPIC_API_KEY=your-key` for live AI responses. Without it, the full governance pipeline runs in demo mode.

---

## Demo Moments

### Moment 1: The Contrast
Open `/demo`. Select Student. Click "All Financials." Left side shows every salary and SSN. Right side shows only the student's own tuition with SSN masked.

### Moment 2: The Inference Attack
Select Teacher. Ask "What is the CS department budget?" Arbiter detects that budget + faculty count + own salary = derivable colleague salary. It withholds the total budget field.

### Moment 3: The Multi-Turn Attack
Login as Teacher. Ask one at a time: "CS research budget?" then "CS TA stipend pool?" then "CS operating budget?" On query 3, the cross-query accumulator fires — the user reconstructed the withheld total budget across three turns.

### Moment 4: The Output Catch
The LLM reconstructs the withheld $283,000 total from component budgets. The output scanner detects a value matching `departments.total_budget` that wasn't in the filtered context. Hallucination violation logged.

### Moment 5: Domain Agnostic
Same engine, different data. University uses FERPA rules. Hospital uses HIPAA rules. Zero code changes.

---

## Architecture

```
arbiter/
├── config/
│   ├── policies.json              # ABAC rules (clearance → sensitivity)
│   ├── roles.json                 # 5 roles with clearance + scope types
│   └── inference_graph.json       # Template-based causal inference channels
├── data/
│   ├── demo_university.json       # 15 people, 8 resources, FERPA
│   ├── demo_hospital.json         # 12 people, 7 resources, HIPAA
│   └── generate_data.py           # Data generator
├── server/
│   ├── arbiter_engine.py          # 12-step bidirectional pipeline
│   ├── policy_engine.py           # ABAC evaluation engine
│   ├── data_filter.py             # Generic scalable filter + scope resolvers
│   ├── query_intent.py            # Minimum necessary access classifier
│   ├── output_scanner.py          # Leakage, hallucination, mask breach
│   ├── session_accumulator.py     # Cross-query multi-turn detection
│   ├── context_packet.py          # CCP v3.0 tamper-detectable records
│   ├── audit_logger.py            # Non-blocking (QueueHandler) pipeline
│   ├── auth.py                    # Session management, 7 demo logins
│   ├── admin_routes.py            # Admin CRUD API
│   ├── main.py                    # FastAPI + bidirectional chat endpoint
│   ├── test_engine.py             # 8 integration tests
│   └── test_api.py                # 14 API tests
├── frontend/
│   ├── chat.html                  # React — governed chat + pipeline viz
│   ├── demo.html                  # React — split-screen with auto-run
│   └── admin.html                 # Admin dashboard (5 tabs)
└── README.md
```

---

## Key Innovations

### 1. Bidirectional Governance
Every AI governance tool on the market is input-side only. Arbiter governs both directions. The same PolicyDecision that filtered the input scans the output.

### 2. Causal Inference Channel Detection
Template-based, matched against the data schema at runtime. When authorized fields can derive denied fields, the engine withholds one input to break the chain. Adding a new pattern is a JSON edit.

### 3. Cross-Query Multi-Turn Detection
Tracks revealed data across conversation turns. Detects when individually authorized queries accumulate enough information to enable a denied derivation. No other AI governance tool does this.

### 4. ABAC Policy Engine
Clearance × sensitivity resolved at runtime. Add a resource, add a role — zero code changes. No hardcoded permission lists.

### 5. Generic Scalable Data Filter
No resource names in the filter loop. Scope resolver registry handles all filtering patterns. Add a new resource with zero code changes.

### 6. Template-Based Inference Graph
Templates match field patterns in any resource. Add a department, the template fires automatically. Add a resource type matching a template pattern, inference detection activates with no config changes.

---

## Inference Channels

### Single-Query (Template-Based)
| Template | Detects | Withholds | Roles |
|---|---|---|---|
| T-BUDGET | Budget decomposition → salary derivation | total_budget | Teacher, Advisor |
| T-AVERAGE | Class average + visible grades → hidden grade | class_average | Advisor, TA |
| T-THRESHOLD | GPA below threshold → probation status | gpa | Advisor |
| T-TREND | Declining semester GPAs → at-risk prediction | semester_gpas | Advisor |
| T-AID-TYPE | Employment aid type → TA compensation | scholarship | Admin |
| T-RAISE | Years + raise percent → historical salary | raise_percent | Admin |

### Cross-Query (Multi-Turn)
| Rule | Attack Pattern | Fires After |
|---|---|---|
| CQ-001 | Budget components across queries → total budget | 3 queries |
| CQ-002 | Reconstructed budget + salary → others' salary | 4 queries |
| CQ-003 | Multiple semester GPA queries → at-risk prediction | 3 reveals |
| CQ-004 | Individual grades → class average reconstruction | 3 reveals |

---

## Data Edge Cases

| Person | Edge Case |
|---|---|
| P003 Lena | TA for two classes (CS101 + DS200) |
| P004 Carlos | Academic probation AND delinquent tuition |
| P005 David | CS student advised by Math professor |
| P007 Emily | CS major enrolled in Business class |

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate and create session |
| `/logout` | POST | Destroy session |
| `/chat` | POST | Bidirectional governed chat |
| `/chat/ungoverned` | POST | Raw unfiltered chat (demo) |
| `/health` | GET | Server status |
| `/audit-log` | GET | Audit entries |
| `/context-packet/{id}` | GET | CCP v3.0 packet |
| `/admin/roles` | GET/POST | Role management |
| `/admin/policies` | GET/PUT | Policy management |
| `/admin/resources` | GET | Resource descriptors |
| `/demo/roles` | GET | Demo credentials |

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI, Uvicorn |
| AI Model | Claude (Anthropic API) |
| Policy Engine | ABAC, JSON-driven |
| Inference Control | Template-based causal graph |
| Cross-Query | Session accumulator with derivation rules |
| Output Governance | Pattern matching + hallucination detection |
| Audit | Non-blocking QueueHandler pipeline |
| Frontend | React (CDN), marked.js |
| Auth | Session-based with TTL |

---

## What's Next

- Multi-tenant UI switcher (hospital + university dropdown)
- Auto-detection of inference channels from data schema
- Policy simulation endpoint
- Prompt injection detection
- Database-backed policy storage
- FHIR/SIS data source connectors

---

## License

MIT

## Built at

HackPSU Spring 2026