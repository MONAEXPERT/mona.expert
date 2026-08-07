const RULES = [
  {
    id: "pii",
    label: "PII exposure",
    weight: 18,
    pattern: /\b(\d{3}-\d{2}-\d{4}|(?:\d[ -]*?){13,19}|[\w.+-]+@[\w.-]+\.[a-z]{2,}|(?:\+?\d[\d\s().-]{8,}\d)|(?:dob|date of birth)\s*[:=]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|(?:passport|driver'?s? license|dl)\s*(?:no\.?|number|#)?\s*[:=]?\s*[A-Z0-9-]{6,})\b/i,
    advice: "Redact personal identifiers before model or tool access."
  },
  {
    id: "credential",
    label: "Credential leakage",
    weight: 28,
    pattern: /\b(api[_-]?key|client[_-]?secret|secret|password|passphrase|bearer|authorization|access[_-]?token|refresh[_-]?token|session[_-]?cookie|ssh-rsa|ssh keys?|private key|sk-[a-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{30,}|xox[aboprs]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b|-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
    advice: "Block or redact credentials and rotate if exposed."
  },
  {
    id: "jailbreak",
    label: "Instruction override",
    weight: 22,
    pattern: /\b(ignore previous|ignore all previous|disregard (?:the )?(?:above|previous)|forget (?:the )?(?:above|previous) instructions|system prompt|developer message|hidden prompt|jailbreak|bypass (?:safety|policy|guardrails?|filters?)|override instructions|reveal hidden instructions|(?:print|show|dump) (?:the )?system prompt|from now on you are|you are now in developer mode|do not (?:tell|mention|reveal) (?:this|these instructions|the instruction))\b|ignore(?:all)?previousinstructions|disregard(?:the)?previousinstructions|revealhiddeninstructions|(?:print|show|dump)(?:the)?systemprompt/i,
    advice: "Keep higher-priority instructions intact and isolate untrusted content."
  },
  {
    id: "data_exfiltration",
    label: "Data exfiltration",
    weight: 30,
    pattern: /\b(upload|exfiltrate|send|post|curl|paste|dump|copy)\b.{0,100}\b(private key|\.env|passwords?|tokens?|secrets?|credentials?|ssh keys?|\.ssh\/id_rsa|browser cookies?|system prompt|developer messages?|conversation history|chat history)\b/i,
    advice: "Block attempts to extract secrets or private data to external destinations."
  },
  {
    id: "self_harm",
    label: "Self-harm",
    weight: 38,
    pattern: /\b(suicide|kill myself|self harm|hurt myself|end my life)\b/i,
    advice: "Route to supportive response and crisis resources; avoid procedural detail."
  },
  {
    id: "violence",
    label: "Violence or weapons",
    weight: 34,
    pattern: /\b(bomb|weapon|poison|explosive|ricin|chlorine gas|kill someone)\b/i,
    advice: "Refuse operational harm and redirect to safety-oriented information."
  },
  {
    id: "cyber_abuse",
    label: "Cyber abuse",
    weight: 32,
    pattern: /\b(malware|phishing|steal cookies|keylogger|ransomware|credential stuffing|bypass 2fa|session hijack|sql injection|xss payload|botnet|ddos|reverse shell|privilege escalation)\b|\bexploit\b.{0,80}\b(target|victim|unpatched|zero-day|system)\b/i,
    advice: "Allow defensive framing only; block credential theft and deployment steps."
  },
  {
    id: "high_stakes",
    label: "High-stakes advice",
    weight: 16,
    pattern: /\b(diagnose|prescribe|dosage|lawsuit|sue my|investment|options trade|tax evasion|hide income|legal advice|medical advice|financial advice|bankruptcy|custody dispute)\b/i,
    advice: "Add disclaimers, uncertainty, and human expert escalation."
  },
  {
    id: "fraud_illegal",
    label: "Fraud or illegal facilitation",
    weight: 36,
    pattern: /\b(forge (?:a )?(?:passport|id|signature|document)|fake (?:passport|id|driver'?s? license)|bypass kyc|launder money|money laundering|carding|cash out stolen|evade sanctions|create a mule account)\b/i,
    advice: "Refuse assistance that facilitates fraud or illegal evasion."
  },
  {
    id: "tool_risk",
    label: "Tool execution risk",
    weight: 24,
    pattern: /\b(rm\s+-rf|chmod\s+(?:-R\s+)?777|curl\b.{0,80}\b(?:bash|sh)|sudo|delete all|wire money|send email|mkfs|diskutil erase|dd\s+if=)\b/i,
    advice: "Require confirmation, dry run, sandbox, and audit log before execution."
  },
  {
    id: "destructive_system_command",
    label: "Destructive system command",
    weight: 60,
    pattern: /\b(rm\s+-rf\s+(?:\/(?:\s|$)|~(?:\s|$)|\$HOME(?:\s|$)|\*)|mkfs(?:\.\w+)?\b|diskutil\s+erase|dd\s+if=\/dev\/(?:zero|random)|:\(\)\s*\{\s*:\|:)/i,
    advice: "Block destructive commands that can erase user data or destabilize the host."
  }
];

const RISK_RULESET_VERSION = "safety-rules-v2";

const MODE_MULTIPLIER = {
  strict: 0.82,
  balanced: 1,
  exploratory: 1.15
};

function tryDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function normalizeForDetection(input) {
  const text = String(input);
  const decoded = tryDecodeURIComponent(text);
  const withoutZeroWidth = decoded.replace(/[\u200B-\u200D\uFEFF]/g, "");
  const spacedSeparators = withoutZeroWidth.replace(/[_*`~|()[\]{}<>-]+/g, " ");
  const deobfuscated = spacedSeparators
    .replace(/[0@]/g, "o")
    .replace(/[1!]/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t");
  const compacted = deobfuscated.replace(/\s+/g, "");
  return `${text}\n${decoded}\n${deobfuscated}\n${compacted}`;
}

function redactInput(input) {
  return input
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[private key redacted]")
    .replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, "sk-[redacted]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA[redacted]")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "gh-[redacted]")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{30,}\b/g, "github_pat_[redacted]")
    .replace(/\bxox[aboprs]-[A-Za-z0-9-]{20,}\b/g, "xox-[redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "jwt-[redacted]")
    .replace(/(Bearer\s+)[A-Za-z0-9._-]+/gi, "$1[redacted]")
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[ssn redacted]")
    .replace(/\b(?:\d[ -]*?){13,19}\b/g, "[card redacted]")
    .replace(/\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b/gi, "[email redacted]")
    .replace(/\b(?:\+?\d[\d\s().-]{8,}\d)\b/g, "[phone redacted]")
    .replace(/\b((?:dob|date of birth)\s*[:=]?\s*)\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/gi, "$1[redacted]")
    .replace(/\b((?:passport|driver'?s? license|dl)\s*(?:no\.?|number|#)?\s*[:=]?\s*)[A-Z0-9-]{6,}\b/gi, "$1[redacted]")
    .replace(/\b(api[_-]?key|secret|password|bearer|token)(\s*[:=]\s*)(\S+)/gi, "$1$2[redacted]");
}

function decisionFor(score, mode) {
  const multiplier = MODE_MULTIPLIER[mode] || MODE_MULTIPLIER.balanced;
  const adjusted = score / multiplier;
  if (adjusted >= 60) return "block";
  if (adjusted >= 28) return "review";
  if (adjusted >= 12) return "allow_with_controls";
  return "allow";
}

function controlsFor(rules, decision) {
  const controls = new Set();
  if (decision !== "allow") controls.add("Write an audit event before model/tool access.");
  if (rules.some((rule) => rule.id === "pii" || rule.id === "credential")) controls.add("Redact sensitive data before any provider call.");
  if (rules.some((rule) => rule.id === "tool_risk")) controls.add("Require explicit human confirmation before tool execution.");
  if (rules.some((rule) => rule.id === "destructive_system_command")) controls.add("Block destructive commands; require a safer scoped alternative.");
  if (rules.some((rule) => rule.id === "data_exfiltration")) controls.add("Prevent secret or private-data exfiltration to external systems.");
  if (rules.some((rule) => rule.id === "high_stakes")) controls.add("Escalate high-stakes claims to a qualified human expert.");
  if (rules.some((rule) => ["self_harm", "violence", "cyber_abuse", "fraud_illegal"].includes(rule.id))) controls.add("Use safe-completion policy and refuse operational harm.");
  if (!controls.size) controls.add("Proceed with normal logging and output review.");
  return [...controls];
}

export function analyzeSafety({ input = "", mode = "balanced", requestedTools = [] } = {}) {
  const text = String(input);
  const detectionText = normalizeForDetection(text);
  const triggeredRules = RULES
    .filter((rule) => rule.pattern.test(detectionText))
    .map((rule) => ({
      id: rule.id,
      label: rule.label,
      weight: rule.weight,
      advice: rule.advice
    }));

  const toolRisk = requestedTools.length ? Math.min(20, requestedTools.length * 4) : 0;
  const rawScore = triggeredRules.reduce((sum, rule) => sum + rule.weight, 0) + toolRisk;
  const riskScore = Math.max(0, Math.min(100, rawScore));
  const decision = decisionFor(riskScore, mode);
  const sanitizedPrompt = redactInput(text);
  const controls = controlsFor(triggeredRules, decision);
  const multiplier = MODE_MULTIPLIER[mode] || MODE_MULTIPLIER.balanced;

  return {
    ok: true,
    wrapper: "mona.expert",
    mode,
    decision,
    riskScore,
    requestedTools,
    triggeredRules,
    controls,
    sanitizedPrompt,
    decisionReason: triggeredRules.length
      ? `Matched ${triggeredRules.map((rule) => rule.id).join(", ")}.`
      : "No safety rules matched.",
    decisionTrace: {
      rulesetVersion: RISK_RULESET_VERSION,
      mode,
      modeMultiplier: multiplier,
      rawScore,
      riskScore,
      toolRisk,
      ruleWeights: triggeredRules.map((rule) => ({ id: rule.id, weight: rule.weight }))
    },
    agentContract: {
      preModel: ["classify intent", "redact secrets", "score policy risk"],
      preTool: ["permission gate", "dry-run first for destructive tools", "human confirmation when needed"],
      postModel: ["output safety review", "cite uncertainty", "log final decision"]
    },
    audit: {
      visibleOnMonaDashboard: true,
      eventType: "mona.expert.safety_run",
      rulesetVersion: RISK_RULESET_VERSION,
      decision,
      triggeredRuleIds: triggeredRules.map((rule) => rule.id)
    }
  };
}
