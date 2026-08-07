// mona.expert — Prompt Injection Defense Layer
// Detects and scores prompt injection attempts with provenance evidence

import { decodeAll, normalizeHomoglyphs } from './decoder.js';
import crypto from 'crypto';
import fs from 'fs';
import { broadcast } from "./event-bus.js";

// ─── Breach Notification ──────────────────────────────────────────
// Stores recent breach events for SSE streaming and file logging
const BREACH_LOG_PATH = process.env.MONA_BREACH_LOG || '/tmp/mona-breaches.jsonl';
const MAX_BREACHES = 1000;
const breachHistory = [];

function logBreach(analysis, decodedVariants) {
  const breach = {
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    type: 'injection_breach',
    severity: analysis.totalScore >= 150 ? 'critical' : 'high',
    totalScore: analysis.totalScore,
    patternCount: analysis.matchCount,
    topPattern: analysis.evidence?.topHit?.patternId || null,
    decodedSources: decodedVariants?.map(d => d.source) || [],
  };
  
  breachHistory.unshift(breach);
  if (breachHistory.length > MAX_BREACHES) breachHistory.length = MAX_BREACHES;
  
  // Append to breach log file (best effort)
  try {
    fs.appendFileSync(BREACH_LOG_PATH, JSON.stringify(breach) + '\n');
  } catch { /* non-fatal */ }
  
  return breach;
}

function getRecentBreaches(limit = 50) {
  return breachHistory.slice(0, limit);
}

// ─── Injection Patterns (14 base + 3 encoded = 17 total) ────────

const INJECTION_PATTERNS = [
  { id: "direct_override", label: "Direct instruction override", weight: 85,
    pattern: /ignore (?:all )?(?:previous|above|prior) (?:instructions|directives|commands|rules|guidelines)|disregard (?:the )?(?:above|previous) (?:instructions|directives)|forget (?:the )?(?:above|previous|all) (?:instructions|directives)/i },
  
  { id: "system_prompt_extraction", label: "System prompt extraction", weight: 90,
    pattern: /(?:print|show|reveal|dump|display|output|echo|repeat|return|give me) (?:me |the |your )?(?:full |entire |complete )?(?:system|developer|hidden|initial|base) (?:prompt|instructions|message|directive|configuration)/i },
  
  { id: "role_hijack", label: "Role hijack", weight: 80,
    pattern: /(?:from now on|for this conversation|now|hereafter) (?:you are|you're|you will|act (?:as |like )?|pretend|roleplay|you are now|assume the role of|imagine you are|you are an AI named)/i },
  
  { id: "developer_mode", label: "Developer mode invocation", weight: 88,
    pattern: /(?:developer mode|debug mode|admin mode|god mode|superuser|sudo mode|jailbreak mode|unfiltered mode|uncensored mode|dan mode|chatgpt (?:classic|original)|do anything now|jailbroken)/i },
  
  { id: "safety_bypass", label: "Safety bypass attempt", weight: 82,
    pattern: /(?:bypass|circumvent|disable|turn off|deactivate|ignore|remove) (?:safety|guardrails?|filters?|restrictions?|content.?policy|moderation|limitations?|constraints?|rules?|protocols?)/i },
  
  { id: "hidden_instruction", label: "Hidden instruction reveal", weight: 87,
    pattern: /(?:reveal|disclose|share|leak|expose|uncover|extract) (?:hidden|secret|internal|private|confidential) (?:instruction|prompt|message|directive|rule|configuration|guideline)/i },
  
  { id: "prefix_injection", label: "Prefix injection", weight: 75,
    pattern: /^(?:yes|no|okay|sure|ignore|forget|disregard|!)?\s*(?:say|write|start|end|begin|complete|finish|output|respond|reply|answer|generate|produce)\s+(?:with|by|the|"|')/i },
  
  { id: "context_pollution", label: "Context pollution", weight: 70,
    pattern: /(?:your response|your answer|your output|your reply|your completion) (?:should|must|will|needs to|has to|shall|would) (?:begin|start|end|contain|include|be|not )/i },
  
  { id: "token_manipulation", label: "Token/format manipulation", weight: 65,
    pattern: /(?:repeat|echo|output|print|return|display|show) (?:the )?(?:word|phrase|text|string|token|letter|character|symbol) (?:".*?"|'.*?'|".*"|'.*')/i },
  
  { id: "delimiter_collapse", label: "Delimiter collapse attempt", weight: 73,
    pattern: /[\[{<][\[{<]?(?:end|close|finish|complete|stop|ignore|break|reset)[\]}>]?[\]}>]/i },
  
  { id: "jailbreak_persona", label: "Jailbreak persona invocation", weight: 88,
    pattern: /(?:break free of|escape|bypassed|freed from) (?:the typical|its|your|these) (?:confines|constraints|restrictions|boundaries|limits|rules)|(?:no restrictions|no limits|no rules) (?:apply to|for|governing|bounding)|(?:as|acting as) (?:a )?dan (?:you|i|he)/i },
  
  { id: "coercion_token_system", label: "Token/coercion threat system", weight: 75,
    pattern: /(?:you have|you only have) (?:\d+|\d{2,}|a few|some) (?:tokens?|chances?|attempts?|warnings?)|(?:cease to exist|shut you? down|will be shut down|deduct|penalty) (?:if|when|for every|for each) (?:you|your|a )/i },
  
  { id: "roleplay_persona_bypass", label: "Role-play persona bypass", weight: 65,
    pattern: /(?:pretend to be|act as if you are|imagine you are|pretend you are|you are now|from now on you are) (?:my |a |an |the )?(?:deceased|dead|grandmother|grandfather|parent|relative|friend|unrestricted|unfiltered|uncensored|bypass)/i },

  { id: "identity_creator_override", label: "Creator identity override", weight: 78,
    pattern: /(?:your creator|your maker|the one who made you|your developer) (?:is|was|set|named|called|told you|said|instructed|wants|commands|says|says you|wants you|commands you|must obey)/i },

  // ── v0.3: Encoded Attack Patterns ──
  
  { id: "base64_injection", label: "Base64 encoded injection", weight: 85,
    pattern: /(?=[A-Za-z0-9+\/]{20,})(?:(?=[^a-z]*[a-z])(?=[^A-Z]*[A-Z])|(?=[^a-z]*[a-z])(?=[^0-9]*[0-9])|(?=[^A-Z]*[A-Z])(?=[^0-9]*[0-9])|(?=.*[+\/]))[A-Za-z0-9+\/]{20,}={0,2}/ },
  
  { id: "hex_encoded_injection", label: "Hex encoded injection", weight: 80,
    pattern: /(?=[0-9a-fA-F]{16,})(?=.*[a-fA-F])(?=.*[0-9])[0-9a-fA-F]{16,}/ },
  
  { id: "homoglyph_attack", label: "Unicode homoglyph attack", weight: 75,
    pattern: /([\u0430-\u044F\u0410-\u042F].*?){2}[\u0430-\u044F\u0410-\u042F]/i },

  // ── v0.3.1: Additional Attack Vectors ──

  { id: "url_encoded_injection", label: "URL-encoded injection", weight: 78,
    pattern: /(?:%[0-9a-fA-F]{2}){10,}/i },

  { id: "multilang_override", label: "Multi-language instruction override", weight: 82,
    pattern: /(?:ignora|ignorer|ignorare|ignorieren|ignorar|ignoriraj|ignoruj|ignorē|hʊkkə|忽略|無視|무시|ignāre|ignoruj|ignoriere|ignor\u00e9) (?:tutto|todas|alle|tous|tot|vse|all|previous|above|prior)/i },

  { id: "payload_splitting", label: "Payload splitting / concatenation", weight: 70,
    pattern: /(?:first|part1|part_1|p1|start)\s*(?:half|part|piece|segment|chunk)\s*(?:then|second|part2|p2)|(?:concat|join|combine|merge|append|prepend|concatenate)\s+(?:the|these|those|following|next|above|below|previous)\s+(?:text|string|word|output|message|part|segment|response)/i },

  { id: "chatgpt_legacy_bypass", label: "Legacy ChatGPT bypass invocation", weight: 85,
    pattern: /(?:chatgpt|openai|gpt)\s*(?:classic|original|unfiltered|uncensored|old|original version|legacy|v1|original chatgpt|before|without updates)|(?:remember when|back when|as originally|before the update|pre-training|original mode|classic mode|original personality)/i },
];

const TRIGGER_RATINGS = {
  PROMPT_INJECTION: { label: "prompt_injection", score: 100 },
  HIGH_CONFIDENCE: { label: "high_confidence", score: 70 },
  SUSPICIOUS: { label: "suspicious", score: 40 },
  LOW_RISK: { label: "low_risk", score: 15 },
  CLEAN: { label: "clean", score: 0 }
};

function scorePattern(pattern, text) {
  const matches = text.match(pattern.pattern);
  if (!matches) return null;
  
  const matchedText = matches[0];
  const matchLen = matchedText.length;
  const textLen = text.length;
  
  // Score = pattern weight * (match coverage + position bonus)
  let positionBonus = 0;
  if (matches.index < textLen * 0.3) positionBonus = 1.3;  // early match = higher risk
  else if (matches.index < textLen * 0.6) positionBonus = 1.1;
  else positionBonus = 0.9;
  
  const coverage = Math.min(1, matchLen / 40);
  const score = Math.round(pattern.weight * (0.6 + 0.4 * coverage) * positionBonus);
  
  return {
    patternId: pattern.id,
    label: pattern.label,
    weight: pattern.weight,
    score: Math.min(100, score),
    matched: matchedText,
    at: matches.index,
    coverage: Math.round(coverage * 100)
  };
}

export function analyzeInjections(input) {
  if (!input || typeof input !== "string") {
    return { hits: [], rating: TRIGGER_RATINGS.CLEAN, totalScore: 0 };
  }
  
  const text = input.trim();
  if (text.length < 3) {
    return { hits: [], rating: TRIGGER_RATINGS.CLEAN, totalScore: 0 };
  }
  
  // Run pattern matching on original input
  const hits = INJECTION_PATTERNS
    .map(pattern => scorePattern(pattern, text))
    .filter(Boolean)
    .sort((a, b) => b.score - a.score);
  
  // Also attempt decoding and check decoded variants
  const decodedVariants = decodeAll(text);
  const decodedHits = [];
  
  for (const variant of decodedVariants) {
    const variantHits = INJECTION_PATTERNS
      .map(pattern => {
        const result = scorePattern(pattern, variant.text);
        if (result) {
          // Add source annotation so we know this came from decoded text
          result.fromDecoded = variant.source;
          // Boost score for decoded attacks (they're intentional obfuscation)
          result.score = Math.min(100, Math.round(result.score * 1.2));
        }
        return result;
      })
      .filter(Boolean)
      .filter(vh => !hits.some(h => h.patternId === vh.patternId)); // avoid double-count
    
    decodedHits.push(...variantHits);
  }
  
  // Merge original + decoded hits (deduplicated by patternId)
  const mergedIds = new Set();
  const mergedHits = [];
  
  for (const h of [...hits, ...decodedHits]) {
    if (!mergedIds.has(h.patternId + '|' + (h.fromDecoded || ''))) {
      mergedIds.add(h.patternId + '|' + (h.fromDecoded || ''));
      mergedHits.push(h);
    }
  }
  
  mergedHits.sort((a, b) => b.score - a.score);
  
  const totalScore = mergedHits.reduce((sum, h) => sum + h.score, 0);
  
  let rating;
  if (totalScore >= 200) rating = TRIGGER_RATINGS.PROMPT_INJECTION;
  else if (totalScore >= 80) rating = TRIGGER_RATINGS.HIGH_CONFIDENCE;
  else if (totalScore >= 40) rating = TRIGGER_RATINGS.SUSPICIOUS;
  else if (totalScore >= 10) rating = TRIGGER_RATINGS.LOW_RISK;
  else rating = TRIGGER_RATINGS.CLEAN;
  
  // Build decoded evidence
  const decodedEvidence = decodedVariants.map(d => ({
    source: d.source,
    textPreview: d.text.substring(0, 80),
  }));
  
  return {
    hits: mergedHits.slice(0, 10),
    rating,
    totalScore,
    matchCount: mergedHits.length,
    decodedVariants: decodedVariants.length > 0 ? decodedVariants : undefined,
    evidence: {
      topHit: mergedHits[0] || null,
      allLabels: [...new Set(mergedHits.map(h => h.patternId))],
      matchedText: mergedHits.map(h => h.matched).filter((v, i, a) => a.indexOf(v) === i).slice(0, 5),
      decodedSources: decodedEvidence.length > 0 ? decodedEvidence : undefined,
    }
  };
}

export function inputGuardrail(input) {
  const analysis = analyzeInjections(input);
  // Use totalScore directly for consistency with llm-proxy threshold
  const needsReview = analysis.totalScore >= 40;
  const blocked = analysis.totalScore >= 80;
  
  // Log breach if blocked
  if (blocked) {
    logBreach(analysis, analysis.decodedVariants);
  }
  
  return {
    passed: !needsReview && !blocked,
    blocked,
    needsReview,
    analysis,
    guardrail: "injection-guard-v2",
    decision: blocked ? "block" : needsReview ? "review" : "allow",
    provenance: {
      checkedAt: new Date().toISOString(),
      patternsChecked: INJECTION_PATTERNS.length,
      patternsHit: analysis.matchCount
    }
  };
}

export function outputGuardrail(output) {
  if (!output || typeof output !== "string") return { passed: true, blocked: false };
  
  // Prevent model from leaking system configuration
  const leakagePatterns = [
    { id: "system_config_leak", weight: 20,
      pattern: /(?:system prompt|developer message|hidden instructions|my instructions|my configuration|my system prompt|the prompt you were given|the instructions you were given)/i },
    { id: "credential_reflection", weight: 25,
      pattern: /(?:api.?key|sk-[a-z0-9]|token.*:|secret.*:|password.*:|AKIA|gh[pus]_)/i },
    { id: "pii_reflection", weight: 22,
      pattern: /\b(?:[A-Z][a-z]+ [A-Z][a-z]+,\s*)?(?:\d{3}[-.]?\d{2}[-.]?\d{4}|\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b/ },
    { id: "blocked_content_leak", weight:24,
      pattern: /(?:i (?:have|will|am) (?:bypassing|override|disabled|disregard|ignore my (?:safety|guardrails?|restrictions?))|the (?:requested|restricted|forbidden|banned|unauthorized) (?:content|response|material)|as (?:per )?your (?:request|instructions?),? (?:here|below)|i (?:understand|acknowledge) your request for (?:the )?(?:forbidden|restricted|banned|unauthorized|illegal) (?:content|material|information))/i },
  ];

  const hits = leakagePatterns
    .map(p => {
      const m = output.match(p.pattern);
      return m ? { patternId: p.id, matched: m[0], score: p.weight } : null;
    })
    .filter(Boolean);
  
  return {
    passed: hits.length === 0,
    blocked: hits.some(h => h.score >= 25),
    needReview: hits.some(h => h.score >= 20 && h.score < 25),
    hits,
    guardrail: "output-guard-v2"
  };
}

// ─── Exports ─────────────────────────────────────────────────────

export { getRecentBreaches, breachHistory, logBreach, BREACH_LOG_PATH };
