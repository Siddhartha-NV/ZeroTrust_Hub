
import { GoogleGenAI } from "@google/genai";
import { RiskEvent, AuditLog } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

export async function analyzeThreats(events: RiskEvent[], logs: AuditLog[]) {
  const prompt = `
    As a Senior Security Analyst for ZeroTrustHub, analyze the following recent security events and audit logs.
    
    Recent Events:
    ${JSON.stringify(events.slice(0, 5), null, 2)}
    
    Audit Context:
    ${JSON.stringify(logs.slice(0, 5), null, 2)}
    
    Provide a concise risk assessment in Markdown:
    1. Identify if these patterns suggest a credential stuffing or session hijacking attempt.
    2. Recommend specific remediation steps (e.g., block IP, rotate tokens, enforce MFA).
    3. Determine if the "Trust Score" logic is accurately reflecting the risk.
    
    Keep it professional and technical.
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
    });
    return response.text;
  } catch (error) {
    console.error("Gemini Analysis Error:", error);
    return "AI Analysis temporarily unavailable. Please review logs manually.";
  }
}
