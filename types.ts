
export enum UserRole {
  ADMIN = 'ADMIN',
  SECURITY_ANALYST = 'SECURITY_ANALYST',
  USER = 'USER'
}

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  trustScore: number;
  lastLoginIp: string;
  lastLoginTime: string;
  deviceHash: string;
  otpRequired: boolean;
}

export interface Device {
  id: string;
  userId: string;
  deviceHash: string;
  name: string;
  firstSeen: string;
  lastSeen: string;
  trusted: boolean;
  userAgent: string;
  ip: string;
}

export interface AuditLog {
  id: string;
  userId: string;
  username: string;
  action: string;
  data: any;
  timestamp: string;
  previousHash: string;
  currentHash: string;
}

export interface RiskEvent {
  id: string;
  userId: string;
  type: 'NEW_DEVICE' | 'NEW_IP' | 'BRUTE_FORCE' | 'UNUSUAL_TIME' | 'ANOMALY' | 'AUTH_SUCCESS';
  value: number;
  metadata: any;
  timestamp: string;
}

export interface MLPrediction {
  anomaly: boolean;
  confidenceScore: number;
  reason?: string;
}
