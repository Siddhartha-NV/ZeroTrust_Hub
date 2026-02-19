
export async function sha256(message: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function generateLogHash(log: { userId: string, action: string, timestamp: string, previousHash: string }): Promise<string> {
  const payload = `${log.userId}|${log.action}|${log.timestamp}|${log.previousHash}`;
  return await sha256(payload);
}
