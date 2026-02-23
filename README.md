# Project Argos: Autonomous SOC Response Engine

> "Detection is easy. Response optimization under uncertainty is the real challenge."

Argos is a production-grade incident response engine that automates security actions using **Decision Intelligence**. It goes beyond static playbooks by applying DSA-based optimization to minimize business impact while maximizing risk reduction.

## 🚀 Core Features

- **Decision Tree Triage**: Automated classification of alert severity and confidence.
- **Max-Heap Prioritization**: Real-time ranking of incidents based on risk-cost efficiency.
- **Graph Blast Radius Analysis**: NetworkX-powered dependency mapping to evaluate operational impact.
- **Greedy Optimization**: Cost-aware selection of the optimal response set.
- **Autonomous Execution**: Simulated response actions (Block IP, Kill Process, Isolation).

## 🛠️ Tech Stack

- **Backend**: Python 3.11+, FastAPI, NetworkX, Pydantic
- **Frontend**: React (Vite), Tailwind CSS, Lucide Icons, Recharts
- **Operations**: GitHub Actions (CI/CD), Docker Support

## 📂 Project Structure

```bash
Project-Argos/
├── backend/
│   ├── engine/          # [CORE] Heap, Graph, Greedy logic
│   ├── ingestion/       # Alert stream simulator
│   ├── response/        # Action executor
│   ├── audit/           # MTTR tracker & decision logs
│   ├── models.py        # Pydantic schemas
│   ├── api.py           # FastAPI wrapper
│   └── main.py          # Backend orchestrator
├── frontend/            # React + Vite dashboard
└── .github/workflows/   # CI/CD pipeline
```

## 🚦 Quick Start

### Backend
```bash
pip install networkx pydantic fastapi uvicorn
python backend/main.py
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## 📊 Metrics Tracked
- **MTTR (Mean Time To Respond)**: Optimized to sub-second autonomous response.
- **ROI (Risk Reduction per Cost)**: Calculated via Greedy selection.
- **Human Escalation Rate**: Reducing alert fatigue by >80%.
