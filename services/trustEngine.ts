
import { User, RiskEvent } from '../types';

export const RISK_PENALTIES = {
  NEW_DEVICE: -30,
  NEW_IP: -20,
  UNUSUAL_HOUR: -25,
  FAILED_ATTEMPTS: -40,
  ANOMALY: -50,
};

export function calculateTrustScore(
  baseScore: number,
  events: RiskEvent[]
): number {
  let score = baseScore;
  events.forEach(event => {
    score += event.value;
  });
  return Math.max(0, Math.min(100, score));
}

export function checkStepUpRequired(score: number): boolean {
  return score < 50;
}

export function isUnusualHour(date: Date): boolean {
  const hour = date.getHours();
  // Unusual hours: 1 AM to 5 AM
  return hour >= 1 && hour <= 5;
}
