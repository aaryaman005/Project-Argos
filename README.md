# Project Argos — Autonomous SOC Response Engine

> *"Detection is easy. Response optimization under uncertainty is the real challenge."*

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=white)
![NetworkX](https://img.shields.io/badge/NetworkX-Graph-orange)
![CI](https://img.shields.io/badge/CI-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)

Argos is a production-grade incident response engine that automates security actions using **Decision Intelligence**. Instead of running static playbooks, it applies data-structure and algorithm–driven optimization to minimize business impact while maximizing risk reduction — deciding not just *whether* to respond, but *which* response set is optimal under cost and blast-radius constraints.

---

## Core Features

- **Decision Tree Triage** — automated classification of alert severity and confidence.
- **Max-Heap Prioritization** — real-time ranking of incidents by risk-cost efficiency.
- **Graph Blast Radius Analysis** — NetworkX-powered dependency mapping to evaluate operational impact.
- **Greedy Optimization** — cost-aware selection of the optimal response set.
- **Autonomous Execution** — simulated response actions (Block IP, Kill Process, Isolation).
- **Audit & MTTR Tracking** — decision logs and mean-time-to-respond metrics for every action.

---

## Architecture

```
Alert Stream
     │
     ▼
Decision Tree Triage  ──►  severity + confidence
     │
     ▼
Max-Heap Prioritization  ──►  risk-cost ranking
     │
     ▼
Graph Blast Radius (NetworkX)  ──►  operational impact
     │
     ▼
Greedy Optimizer  ──►  optimal response set
     │
     ▼
Response Executor  ──►  Block IP · Kill Process · Isolate
     │
     ▼
Audit / MTTR Tracker
```

---

## Tech Stack

| Layer      | Technology                                          |
| :--------- | :-------------------------------------------------- |
| Backend    | Python 3.11+, FastAPI, NetworkX, Pydantic           |
| Frontend   | React (Vite), Tailwind CSS, Lucide Icons, Recharts  |
| Operations | GitHub Actions (CI/CD), Docker support              |

---

## Project Structure

```text
Project-Argos/
├── backend/
│   ├── engine/          # [CORE] triage, priority heap, topology graph, greedy optimizer
│   ├── ingestion/       # Alert stream simulator
│   ├── response/        # Action executor
│   ├── audit/           # MTTR tracker & decision logs
│   ├── models.py        # Pydantic schemas
│   ├── api.py           # FastAPI wrapper
│   └── main.py          # Backend orchestrator
├── soc-frontend/        # React + Vite dashboard
└── .github/workflows/   # CI/CD pipeline
```

---

## Quick Start

### Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
```

### Frontend

```bash
cd soc-frontend
npm install
npm run dev
```

---

## Metrics Tracked

- **MTTR (Mean Time To Respond)** — optimized toward sub-second autonomous response.
- **ROI (Risk Reduction per Cost)** — computed via greedy selection.
- **Human Escalation Rate** — reducing alert fatigue by >80%.

---

## Testing

```bash
cd backend
pytest
```

---

## License

See repository for license details.

## Author

**Aaryaman Bhatnagar** — [GitHub](https://github.com/aaryaman005) · [LinkedIn](https://www.linkedin.com/in/aaryaman-bhatnagar-06a517283/)
