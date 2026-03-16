# 🛡️ Bastion Audit: AI Agent Security & Compliance

**Bastion Audit** is an enterprise-grade security middleware and monitoring dashboard designed for the Canadian financial sector. It provides real-time protection for autonomous AI agents, ensuring they remain compliant with **PIPEDA** and **AIDA** (Canada’s Artificial Intelligence and Data Act).

---

## 🚀 Overview

As AI agents move from simple chat interfaces to "agentic workflows" (accessing databases, executing code, handling PII), the risk of exploitation increases. **Bastion Audit** acts as a security gatekeeper between the user and the agent.

- **Real-time Interception**: Analyzes every input/output through the Lakera Guard security engine.
- **Automated Blocking**: Instantly halts malicious attempts (Jailbreaks, Prompt Injections, Data Exfiltration).
- **Compliance Logging**: Automatically records every security event with regulatory tags (PIPEDA/AIDA/OSFI) in Supabase.
- **Executive Dashboard**: A "Banking Blue" command center for security officers to monitor health scores and trigger a global kill-switch.

## 🛠️ Tech Stack

- **Frontend**: React / Next.js (Tailwind CSS)
- **Backend**: Supabase Edge Functions (TypeScript)
- **Database**: Supabase (PostgreSQL) with RLS (Row Level Security)
- **Security Engine**: [Lakera Guard](https://www.lakera.ai/)
- **Deployment**: Vercel (Canada-Central Region for Residency Compliance)

## 📦 Installation & Setup

### 1. Prerequisites
- A [Supabase](https://supabase.com/) account (Project set to `ca-central-1`).
- A [Lakera](https://lakera.ai/) account and API Key.

### 2. Environment Variables
Add the following to your `.env.local` (Local) and Vercel/Lovable Secrets:

```env
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
LAKERA_GUARD_API_KEY=your_lakera_key_here
