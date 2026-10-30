# SentinelLLM Frontend (v2.0.0)

React 18 + Vite UI for the SentinelLLM FastAPI backend.

## Run

```bash
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (normally `http://localhost:5173`). The backend should be running on `http://localhost:8000`.

To point the UI at another API, set `VITE_API_BASE_URL` before starting or building. Example in Windows PowerShell:

```powershell
$env:VITE_API_BASE_URL="http://127.0.0.1:8000"
npm run dev
```

The default backend CORS allowlist supports the local Vite development/preview ports. Configure `CORS_ORIGINS` on the backend for other trusted origins. The UI is a research demonstration; backend policy decisions are not a production safety guarantee.
