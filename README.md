# SmishGuard

An offline-capable SMS phishing detection API built for Ghana and West Africa. It analyzes SMS messages in real time using rule-based detection, scores them 0–100, and returns a risk level with actionable recommendations.

Built with **FastAPI** and designed to integrate with **AfricasTalking** for live SMS webhook processing.

---

## Features

- 25 detection rules (18 Ghana-specific, 7 global)
- Detects MoMo fraud, carrier impersonation, government scams, fake jobs, and more
- Risk scoring: `safe` / `suspicious` / `danger`
- API key authentication
- Rate limiting (30 req/min single, 10 req/min batch)
- Batch analysis (up to 100 messages per request)
- AfricasTalking webhook integration with optional auto-reply
- Feedback endpoint for reporting false positives/negatives
- Admin API for toggling and adjusting rules at runtime (changes persist across restarts)
- Interactive API docs at `/docs`

---

## Detection Coverage

| Category | Examples |
|---|---|
| MoMo fraud | PIN requests, fake credits, accidental transfer lures, agent impersonation |
| Carrier impersonation | MTN, Telecel/Vodafone, AirtelTigo |
| Government impersonation | GRA, Electoral Commission, NIA, MASLOC |
| Bank impersonation | GCB, Absa, Fidelity, Ecobank, Stanbic, and more |
| Delivery/customs fraud | GhanaPost, Kotoka Airport package scams |
| SIM/KYC fraud | Fake SIM re-registration, NCA deadlines |
| Job recruitment scams | Fake GNPC, Cocobod, GES, Police Service |
| Investment scams | Ponzi, fake forex/crypto returns, SSNIT fraud |
| Global patterns | Shortened URLs, urgency language, credential harvesting |
| Ghanaian slang | Twi-influenced MoMo scam phrases |

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/health` | None | Service health check |
| GET | `/docs` | None | Interactive Swagger docs |
| POST | `/api/v1/analyze` | API Key | Analyze a single SMS |
| POST | `/api/v1/analyze/batch` | API Key | Analyze up to 100 messages |
| POST | `/api/v1/feedback` | API Key | Report a wrong result |
| GET | `/api/v1/admin/rules` | Admin Token | List all rules |
| PATCH | `/api/v1/admin/rules/toggle` | Admin Token | Enable/disable a rule |
| PATCH | `/api/v1/admin/rules/weight` | Admin Token | Adjust a rule's weight |
| POST | `/webhook/sms/incoming` | None | AfricasTalking SMS webhook |

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/smishguard.git
cd smishguard
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
```

Open `.env` and set your values. Generate secure keys using:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Minimum required settings:

```env
SMISHGUARD_API_KEYS=your-generated-api-key
SMISHGUARD_ADMIN_TOKEN=your-generated-admin-key
```

### 4. Run the server

```bash
uvicorn app.main:app --reload
```

The API is now live at `http://localhost:8000`
Interactive docs at `http://localhost:8000/docs`

---

## Usage Examples

### Analyze a single message

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"text": "Please send your MoMo PIN to confirm your wallet transfer."}'
```

**Response:**

```json
{
  "score": 70,
  "level": "danger",
  "triggered_rules": [
    {
      "id": "momo_pin_request",
      "name": "MoMo PIN / wallet credential request",
      "weight": 35,
      "severity": "high",
      "region": "gh",
      "category": "MoMo fraud"
    }
  ],
  "gh_hits": 1,
  "summary": "High-risk message (score 70/100). Threats detected: MoMo fraud.",
  "recommendation": "Do NOT share your MoMo PIN or send money. Report to your network operator and call 18111 (Ghana Cybersecurity Authority).",
  "analyzed_at": "2026-01-01T10:00:00"
}
```

### Analyze a batch of messages

```bash
curl -X POST http://localhost:8000/api/v1/analyze/batch \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "messages": [
      {"id": "msg1", "text": "Your appointment is confirmed for tomorrow."},
      {"id": "msg2", "text": "You have won GHS 5000 in the MTN draw! Claim now: http://bit.ly/claim"}
    ]
  }'
```

### Report a wrong result

```bash
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "text": "Your appointment is confirmed for tomorrow.",
    "predicted_level": "suspicious",
    "correct_level": "safe",
    "notes": "This is a legitimate appointment reminder."
  }'
```

### Python example

```python
import requests

response = requests.post(
    "https://your-deployment-url/api/v1/analyze",
    headers={"X-API-Key": "your-api-key"},
    json={"text": "Send your MoMo PIN to confirm your transfer."}
)
result = response.json()
print(result["level"])        # "danger"
print(result["score"])        # 70
print(result["recommendation"])
```

### JavaScript example

```javascript
const response = await fetch("https://your-deployment-url/api/v1/analyze", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "your-api-key"
  },
  body: JSON.stringify({ text: "Send your MoMo PIN to confirm your transfer." })
});
const result = await response.json();
console.log(result.level); // "danger"
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` or `production` |
| `DEBUG` | `false` | Enable debug mode |
| `ALLOWED_ORIGINS` | `*` | Comma-separated allowed CORS origins |
| `SMISHGUARD_API_KEYS` | _(empty)_ | Comma-separated API keys. Leave empty to disable auth (dev only) |
| `SMISHGUARD_ADMIN_TOKEN` | `changeme` | Admin bearer token. **Always change this in production** |
| `AT_USERNAME` | `sandbox` | AfricasTalking username |
| `AT_API_KEY` | _(empty)_ | AfricasTalking API key |
| `AT_SHORTCODE` | _(empty)_ | AfricasTalking sender ID / shortcode |
| `AT_WEBHOOK_SECRET` | _(empty)_ | HMAC secret for webhook signature verification |
| `DANGER_THRESHOLD` | `55` | Minimum score for `danger` level |
| `SUSPICIOUS_THRESHOLD` | `25` | Minimum score for `suspicious` level |
| `ENABLE_AUTO_REPLY` | `false` | Auto-reply warning to flagged senders |

---

## Deploying to Render

1. Push your code to GitHub
2. Go to [render.com](https://render.com) → **New → Web Service**
3. Connect your GitHub repository
4. Set the following:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Add environment variables in the **Environment** tab
6. Click **Deploy**

> **Note:** Render's free tier spins down after 15 minutes of inactivity. Use [UptimeRobot](https://uptimerobot.com) to ping `/health` every 10 minutes to keep it awake.

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Risk Levels

| Level | Score Range | Meaning |
|---|---|---|
| `safe` | 0 – 24 | No significant threats detected |
| `suspicious` | 25 – 54 | Some signals present — treat with caution |
| `danger` | 55 – 100 | High-risk message — do not engage |

---

## Report a Scam

- **Ghana Cybersecurity Authority:** 292 (toll-free)
- **MTN Ghana:** 100
- **Telecel Ghana:** 200
- **AirtelTigo:** 200
- **GCA Hotline:** 18111

---

## License

MIT
