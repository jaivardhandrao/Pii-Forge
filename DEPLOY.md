# Deploying PII-Forge on Hugging Face Spaces

Step-by-step guide for hackathon deployment.

---

## Prerequisites

- A [Hugging Face](https://huggingface.co) account
- `git` installed on your machine
- An LLM API key (OpenAI or HF Inference API) — only needed if you're running `inference.py`

---

## Step 1: Create the Space

1. Go to [huggingface.co/new-space](https://huggingface.co/new-space)
2. Fill in:
   - **Space name:** `pii-forge` (or whatever you want)
   - **SDK:** Select **Docker**
   - **Visibility:** Public (for hackathon judges) or Private
3. Click **Create Space**

---

## Step 2: Push Your Code

```bash
# Clone the empty space repo HF just created
git clone https://huggingface.co/spaces/YOUR_USERNAME/pii-forge
cd pii-forge

# Copy your project files into this repo
# (from wherever your Pii-Forge code lives)
cp -r /path/to/Pii-Forge/* .
cp /path/to/Pii-Forge/.gitignore .

# Commit and push
git add .
git commit -m "Initial deployment"
git push
```

> After pushing, HF will automatically start building your Docker image. You can watch the build logs in the **Logs** tab on your Space page.

---

## Step 3: Set API Secrets (Only if using inference.py)

The Gradio UI + grading server work without any API keys. You only need secrets if you want to run `inference.py` (the LLM-powered baseline agent).

1. Go to your Space → **Settings** → **Repository secrets**
2. Add these secrets:

| Secret Name      | Value                          | When Needed                    |
|------------------|--------------------------------|--------------------------------|
| `HF_TOKEN`       | Your HF API token              | If using HF Inference API      |
| `OPENAI_API_KEY` | Your OpenAI key                | If using OpenAI                |
| `API_BASE_URL`   | LLM endpoint URL               | If using a custom LLM endpoint |
| `MODEL_NAME`     | e.g. `gpt-4o-mini`             | To change the default model    |

> **Never put API keys in your code or Dockerfile.** HF injects secrets as environment variables at runtime.

---

## Step 4: Verify It's Working

Once the build finishes (usually 2-3 minutes), check these URLs:

| URL                                                | What It Does          |
|----------------------------------------------------|-----------------------|
| `https://YOUR_USERNAME-pii-forge.hf.space/health`  | Should return `{"status": "healthy"}` |
| `https://YOUR_USERNAME-pii-forge.hf.space/web`     | Gradio UI — this is your main demo    |
| `https://YOUR_USERNAME-pii-forge.hf.space/docs`    | Swagger API docs (auto-generated)     |

---

## Step 5: Test the Full Flow

1. Open the `/web` URL
2. Select a difficulty (start with **easy**)
3. Click **Reset Environment** — a document should appear
4. Paste a PII detection JSON in the input, e.g.:
   ```json
   [{"pii_type": "EMAIL", "value": "john@example.com", "start": 45, "end": 63}]
   ```
5. Click **Submit Detection** — you should see a score, highlighted doc, and risk heatmap
6. Repeat for all documents in the episode

---

## What Each URL Does (for judges)

| Path     | Purpose                                        |
|----------|------------------------------------------------|
| `/web`   | Interactive Gradio UI — the main demo          |
| `/health`| Health check (HF uses this to know app is up)  |
| `/reset` | POST — starts a new PII scanning episode       |
| `/step`  | POST — submits PII detections for grading      |
| `/ws`    | WebSocket endpoint for real-time agent comms   |
| `/docs`  | Auto-generated Swagger/OpenAPI docs            |

---

## Troubleshooting

### Build fails with "openenv-core not found"
This is fine — `openenv-core` is only in `pyproject.toml` for metadata. The Dockerfile uses `server/requirements.txt` which doesn't include it. If you see this error, it means something changed the install command. Check your Dockerfile uses:
```dockerfile
RUN pip install --no-cache-dir -r requirements.txt
```

### Space shows "Building" forever
Check the **Logs** tab. Common issues:
- Dockerfile syntax error
- A dependency failed to install
- Port mismatch (must be 7860)

### App starts but Gradio UI is blank
Check browser console for errors. The Gradio app mounts at `/web`, not `/`. Going to the root URL will show the FastAPI JSON endpoints, not the UI.

### "Session not found" errors
Sessions expire after 30 minutes of inactivity. Just call `/reset` again to create a new one.

---

## If You Need to Update

```bash
# Make your changes locally, then:
git add .
git commit -m "Fix whatever"
git push
```

HF auto-rebuilds on every push. Takes ~2-3 minutes.

---

## Architecture Summary

```
Hugging Face Space (Docker, port 7860)
├── FastAPI server (REST + WebSocket)
│   ├── /reset  → creates session, loads documents
│   ├── /step   → grades PII submission, returns score
│   └── /ws     → WebSocket for real-time agents
├── Gradio UI (mounted at /web)
│   └── Interactive PII scanning interface
└── Data (in-memory)
    └── 7 JSON files with synthetic documents (~88KB)
```

- No database, no external storage — everything is in-memory
- No ML models loaded locally — inference uses remote LLM API calls
- Lightweight: runs comfortably on HF's free tier (2 vCPU, 16GB RAM)
