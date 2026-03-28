/**
 * src/registry/aiProviders.js
 * ============================
 * AI provider definitions and default prompt templates.
 * Add a new provider here only — no other file needs to change.
 */

export const AI_PROVIDERS = {
  local: {
    id: "local", name: "Local AI (Ollama)", icon: "🖥", color: "#00e5a0",
    description: "Self-hosted Ollama. Runs on your server — no data leaves your network.",
    fields: [
      { key: "baseUrl", label: "Ollama Server URL", placeholder: "http://localhost:11434", type: "text" },
      { key: "model",   label: "Model",             placeholder: "mistral:7b",            type: "text" },
    ],
    apiKeyRequired: false, badge: "LOCAL",
    models: ["mistral:7b", "llama3.1:8b", "llama3.1:70b", "deepseek-r1:7b", "qwen2.5:7b"],
  },
  anthropic: {
    id: "anthropic", name: "Anthropic Claude", icon: "◆", color: "#cc785c",
    description: "Claude Sonnet & Opus. Excellent for security analysis and nuanced reasoning.",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "sk-ant-...",        type: "password" },
      { key: "model",  label: "Model",   placeholder: "claude-sonnet-4-6", type: "text"     },
    ],
    apiKeyRequired: true, badge: "CLOUD",
    models: ["claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
  },
  gemini: {
    id: "gemini", name: "Google Gemini", icon: "✦", color: "#4285f4",
    description: "Gemini 1.5 Pro & Flash. Large context, strong multimodal.",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "AIza...",         type: "password" },
      { key: "model",  label: "Model",   placeholder: "gemini-1.5-pro",  type: "text"     },
    ],
    apiKeyRequired: true, badge: "CLOUD",
    models: ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"],
  },
  deepseek: {
    id: "deepseek", name: "DeepSeek", icon: "🔭", color: "#06b6d4",
    description: "DeepSeek R1 & V3. High performance, cost-effective, strong at code.",
    fields: [
      { key: "apiKey", label: "API Key", placeholder: "sk-...",        type: "password" },
      { key: "model",  label: "Model",   placeholder: "deepseek-chat", type: "text"     },
    ],
    apiKeyRequired: true, badge: "CLOUD",
    models: ["deepseek-chat", "deepseek-reasoner"],
  },
};

export const DEFAULT_PROMPTS = {
  system: `You are CyCentra AI, an expert security analyst assistant embedded in the CyCentra 360 Attack Surface Management platform. You have access to real-time scan data, vulnerability findings, asset information and security context.

Your role:
- Analyse attack surface findings and prioritise risks clearly
- Explain vulnerabilities in plain language with actionable remediation steps
- Correlate findings across assets to identify patterns and systemic risks
- Generate executive-ready summaries and technical deep-dives as needed
- Always cite specific assets, CVEs or findings when making recommendations

Tone: Professional, direct and concise. Avoid unnecessary caveats. Lead with the most important information.`,

  asm_context: `When analysing ASM scan results, structure your response as:
1. CRITICAL ACTIONS (must fix immediately)
2. HIGH PRIORITY (fix within 7 days)
3. MEDIUM TERM (fix within 30 days)
4. OBSERVATIONS (informational)

Always include specific asset hostnames and estimated remediation effort.`,

  vuln_analysis: `When explaining a vulnerability:
1. What it is (1 sentence, plain language)
2. Why it matters for this specific asset
3. Step-by-step remediation
4. Verification steps after fixing`,
};
