
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Shield, 
  Activity, 
  Users, 
  Terminal, 
  Lock, 
  User as UserIcon, 
  LayoutDashboard,
  LogOut,
  AlertTriangle,
  Smartphone,
  Fingerprint,
  RefreshCw,
  CheckCircle,
  XCircle,
  Database
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar
} from 'recharts';
import { User, UserRole, Device, AuditLog, RiskEvent } from './types';
import { generateLogHash } from './utils/crypto';
import { calculateTrustScore, RISK_PENALTIES, checkStepUpRequired } from './services/trustEngine';
import { analyzeThreats } from './services/geminiService';

// --- Mock Initial Data ---
const INITIAL_USER: User = {
  id: 'usr_1',
  username: 'admin_root',
  email: 'admin@zerotrusthub.io',
  role: UserRole.ADMIN,
  trustScore: 100,
  lastLoginIp: '192.168.1.45',
  lastLoginTime: new Date().toISOString(),
  deviceHash: 'dev_7a8b9c',
  otpRequired: false
};

const INITIAL_DEVICES: Device[] = [
  {
    id: 'd1',
    userId: 'usr_1',
    deviceHash: 'dev_7a8b9c',
    name: 'MacBook Pro 16 (Work)',
    firstSeen: '2023-12-01T10:00:00Z',
    lastSeen: new Date().toISOString(),
    trusted: true,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
    ip: '192.168.1.45'
  }
];

const App: React.FC = () => {
  const [user, setUser] = useState<User>(INITIAL_USER);
  const [devices, setDevices] = useState<Device[]>(INITIAL_DEVICES);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [riskEvents, setRiskEvents] = useState<RiskEvent[]>([]);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'threats' | 'audit' | 'users' | 'devices'>('dashboard');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isVerifyingChain, setIsVerifyingChain] = useState(false);
  const [chainValid, setChainValid] = useState<boolean | null>(null);

  // --- Helper: Add Audit Log with Hash Chain ---
  const addLog = useCallback(async (action: string, data: any) => {
    const lastLog = logs[logs.length - 1];
    const previousHash = lastLog ? lastLog.currentHash : '0'.repeat(64);
    const timestamp = new Date().toISOString();
    
    const newLogBase = {
      id: `log_${Math.random().toString(36).substr(2, 9)}`,
      userId: user.id,
      username: user.username,
      action,
      data,
      timestamp,
      previousHash
    };

    const currentHash = await generateLogHash(newLogBase);
    const fullLog: AuditLog = { ...newLogBase, currentHash };
    
    setLogs(prev => [...prev, fullLog]);
  }, [logs, user]);

  // --- Simulation: Trigger Risk Event ---
  const triggerRiskEvent = useCallback(async (type: keyof typeof RISK_PENALTIES, metadata: any = {}) => {
    const event: RiskEvent = {
      id: `evt_${Math.random().toString(36).substr(2, 9)}`,
      userId: user.id,
      type: type as any,
      value: RISK_PENALTIES[type],
      metadata,
      timestamp: new Date().toISOString()
    };
    
    setRiskEvents(prev => [...prev, event]);
    
    // Update local user trust score
    const newScore = calculateTrustScore(user.trustScore, [event]);
    setUser(prev => ({ 
      ...prev, 
      trustScore: newScore,
      otpRequired: checkStepUpRequired(newScore)
    }));

    await addLog(`RISK_EVENT_DETECTED: ${type}`, { eventId: event.id, newScore });
  }, [user, addLog]);

  // --- Verification: Check Audit Chain Integrity ---
  const verifyChain = async () => {
    setIsVerifyingChain(true);
    setChainValid(null);
    
    // Simulate processing time
    await new Promise(r => setTimeout(r, 1500));
    
    let isValid = true;
    for (let i = 1; i < logs.length; i++) {
      const current = logs[i];
      const previous = logs[i - 1];
      if (current.previousHash !== previous.currentHash) {
        isValid = false;
        break;
      }
    }
    
    setChainValid(isValid);
    setIsVerifyingChain(false);
  };

  // --- Effect: AI Intelligence Pulse ---
  useEffect(() => {
    if (riskEvents.length > 0 && riskEvents.length % 3 === 0) {
      handleAiAnalysis();
    }
  }, [riskEvents]);

  const handleAiAnalysis = async () => {
    setIsAnalyzing(true);
    const analysis = await analyzeThreats(riskEvents, logs);
    setAiAnalysis(analysis);
    setIsAnalyzing(false);
  };

  // --- UI Components ---
  const SidebarItem = ({ id, icon: Icon, label }: { id: typeof activeTab, icon: any, label: string }) => (
    <button
      onClick={() => setActiveTab(id)}
      className={`flex items-center space-x-3 w-full px-4 py-3 rounded-lg transition-all ${
        activeTab === id 
          ? 'bg-blue-600/20 text-blue-400 border-r-2 border-blue-500' 
          : 'text-slate-400 hover:bg-slate-800 hover:text-slate-100'
      }`}
    >
      <Icon size={20} />
      <span className="font-medium">{label}</span>
    </button>
  );

  const StatusCard = ({ title, value, subtext, icon: Icon, colorClass }: any) => (
    <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl flex items-start justify-between">
      <div>
        <p className="text-slate-400 text-sm font-medium mb-1 uppercase tracking-wider">{title}</p>
        <h3 className={`text-3xl font-bold ${colorClass}`}>{value}</h3>
        <p className="text-slate-500 text-xs mt-1">{subtext}</p>
      </div>
      <div className={`p-2 rounded-lg bg-slate-800 ${colorClass.replace('text', 'text')}`}>
        <Icon size={24} className={colorClass} />
      </div>
    </div>
  );

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      {/* Sidebar */}
      <aside className="w-64 border-r border-slate-800 flex flex-col">
        <div className="p-6 flex items-center space-x-3">
          <div className="bg-blue-600 p-2 rounded-lg">
            <Shield className="text-white" size={24} />
          </div>
          <h1 className="text-xl font-bold tracking-tight">ZeroTrust<span className="text-blue-500">Hub</span></h1>
        </div>

        <nav className="flex-1 px-4 py-4 space-y-1">
          <SidebarItem id="dashboard" icon={LayoutDashboard} label="Dashboard" />
          <SidebarItem id="threats" icon={Activity} label="Threat Intelligence" />
          <SidebarItem id="audit" icon={Database} label="Audit Chain" />
          <SidebarItem id="users" icon={Users} label="User Directory" />
          <SidebarItem id="devices" icon={Smartphone} label="Device Inventory" />
        </nav>

        <div className="p-4 border-t border-slate-800">
          <div className="bg-slate-900 rounded-xl p-4 flex items-center space-x-3 mb-4">
            <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center font-bold">
              {user.username[0].toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold truncate">{user.username}</p>
              <p className="text-xs text-slate-500 truncate">{user.role}</p>
            </div>
          </div>
          <button className="w-full flex items-center justify-center space-x-2 py-2 text-slate-400 hover:text-red-400 transition-colors">
            <LogOut size={16} />
            <span className="text-sm font-medium">Terminate Session</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto relative">
        {/* Top Header */}
        <header className="sticky top-0 z-10 bg-slate-950/80 backdrop-blur-md border-b border-slate-800 px-8 py-4 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold capitalize">{activeTab}</h2>
            <p className="text-xs text-slate-500">System State: <span className="text-emerald-500 font-mono">OPERATIONAL</span> | Last Heartbeat: {new Date().toLocaleTimeString()}</p>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className={`px-4 py-1.5 rounded-full border flex items-center space-x-2 transition-colors ${
              user.trustScore > 70 ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
              user.trustScore > 40 ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
              'bg-rose-500/10 border-rose-500/30 text-rose-400'
            }`}>
              <Fingerprint size={16} />
              <span className="text-sm font-bold">Trust Score: {user.trustScore}</span>
            </div>
            
            <button 
              onClick={() => triggerRiskEvent('NEW_DEVICE', { model: 'Unknown Phone', loc: 'Berlin' })}
              className="bg-slate-800 hover:bg-slate-700 text-slate-100 px-3 py-1.5 rounded-lg text-sm transition-colors border border-slate-700"
            >
              Simulate Login
            </button>
          </div>
        </header>

        {/* Content Views */}
        <div className="p-8">
          {activeTab === 'dashboard' && (
            <div className="space-y-8">
              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatusCard title="Identity Health" value={`${user.trustScore}%`} subtext="Based on adaptive risk" icon={Shield} colorClass={user.trustScore > 60 ? 'text-emerald-400' : 'text-rose-400'} />
                <StatusCard title="Active Risks" value={riskEvents.filter(e => e.value < 0).length} subtext="Detected last 24h" icon={AlertTriangle} colorClass="text-amber-400" />
                <StatusCard title="Audit Verified" value={logs.length} subtext="Hashed chain depth" icon={Database} colorClass="text-blue-400" />
                <StatusCard title="Managed Devices" value={devices.length} subtext="Fingerprinted assets" icon={Smartphone} colorClass="text-indigo-400" />
              </div>

              {/* Charts Section */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h4 className="font-semibold text-slate-100">Trust Score Trajectory</h4>
                    <span className="text-xs text-slate-500 font-mono">REAL-TIME TELEMETRY</span>
                  </div>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={[...riskEvents.map((e, i) => ({ name: i, score: 100 + riskEvents.slice(0, i+1).reduce((acc, curr) => acc + curr.value, 0) })), { name: 'Now', score: user.trustScore }]}>
                        <defs>
                          <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                        <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                        <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} domain={[0, 100]} />
                        <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
                        <Area type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorScore)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col">
                  <h4 className="font-semibold text-slate-100 mb-4">Risk Distribution</h4>
                  <div className="flex-1 flex flex-col justify-center">
                    <div className="space-y-4">
                      {['NEW_DEVICE', 'NEW_IP', 'UNUSUAL_HOUR', 'ANOMALY'].map(type => {
                        const count = riskEvents.filter(e => e.type === type).length;
                        const total = riskEvents.length || 1;
                        const percent = (count / total) * 100;
                        return (
                          <div key={type}>
                            <div className="flex justify-between text-xs mb-1">
                              <span className="text-slate-400">{type.replace('_', ' ')}</span>
                              <span className="text-slate-200 font-mono">{count}</span>
                            </div>
                            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                              <div 
                                className="h-full bg-blue-500 rounded-full" 
                                style={{ width: `${percent}%` }}
                              />
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                  <button className="mt-6 w-full py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs font-medium border border-slate-700 transition-colors">
                    Export Risk Profile
                  </button>
                </div>
              </div>

              {/* Recent Activity Table */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                  <h4 className="font-semibold">Recent Risk Telemetry</h4>
                  <Activity size={18} className="text-slate-500" />
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider">
                        <th className="px-6 py-3 font-medium">Timestamp</th>
                        <th className="px-6 py-3 font-medium">Event Type</th>
                        <th className="px-6 py-3 font-medium">Penalty</th>
                        <th className="px-6 py-3 font-medium">Confidence</th>
                        <th className="px-6 py-3 font-medium">Action Taken</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {riskEvents.slice().reverse().map(event => (
                        <tr key={event.id} className="text-sm hover:bg-slate-800/50 transition-colors">
                          <td className="px-6 py-4 text-slate-500 font-mono">{new Date(event.timestamp).toLocaleTimeString()}</td>
                          <td className="px-6 py-4 font-medium text-slate-200">{event.type}</td>
                          <td className="px-6 py-4 text-rose-400 font-mono">{event.value}</td>
                          <td className="px-6 py-4">
                            <span className="px-2 py-1 rounded bg-slate-800 text-slate-400 text-xs">High (0.98)</span>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`flex items-center space-x-1 ${event.value < -25 ? 'text-amber-400' : 'text-emerald-400'}`}>
                              {event.value < -25 ? <Lock size={14} /> : <CheckCircle size={14} />}
                              <span>{event.value < -25 ? 'Step-up Required' : 'Logged'}</span>
                            </span>
                          </td>
                        </tr>
                      ))}
                      {riskEvents.length === 0 && (
                        <tr>
                          <td colSpan={5} className="px-6 py-8 text-center text-slate-500 italic">No risk telemetry data available.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'threats' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-2xl font-bold">AI Threat Intelligence</h3>
                <button 
                  onClick={handleAiAnalysis}
                  disabled={isAnalyzing}
                  className="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors"
                >
                  <RefreshCw size={18} className={isAnalyzing ? 'animate-spin' : ''} />
                  <span>{isAnalyzing ? 'Analyzing Pattern...' : 'Run Analysis'}</span>
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                <div className="lg:col-span-3 space-y-6">
                  <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 min-h-[400px]">
                    {isAnalyzing ? (
                      <div className="flex flex-col items-center justify-center h-full space-y-4 text-slate-400">
                        <Terminal size={48} className="animate-pulse" />
                        <p className="font-mono">Processing behavioral clusters via Isolation Forest...</p>
                      </div>
                    ) : aiAnalysis ? (
                      <div className="prose prose-invert max-w-none">
                        <div className="flex items-center space-x-2 text-blue-400 mb-4 bg-blue-400/10 p-2 rounded-lg border border-blue-400/20">
                          <Activity size={18} />
                          <span className="text-sm font-bold uppercase tracking-wider">Gemini 3 Security Protocol Analysis</span>
                        </div>
                        <div className="text-slate-300 whitespace-pre-wrap font-mono text-sm leading-relaxed bg-slate-950 p-6 rounded-xl border border-slate-800">
                          {aiAnalysis}
                        </div>
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center h-full space-y-4 text-slate-500">
                        <Terminal size={48} />
                        <p>No active analysis. Click "Run Analysis" to evaluate current telemetry.</p>
                      </div>
                    )}
                  </div>
                </div>

                <div className="space-y-6">
                  <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h5 className="text-sm font-bold uppercase text-slate-500 mb-4 tracking-tighter">Anomaly Detection</h5>
                    <div className="flex flex-col items-center py-6">
                      <div className="relative w-32 h-32 flex items-center justify-center">
                        <div className={`absolute inset-0 rounded-full border-4 border-slate-800 ${riskEvents.some(e => e.type === 'ANOMALY') ? 'border-t-rose-500' : 'border-t-emerald-500'} animate-spin`} style={{ animationDuration: '3s' }}></div>
                        <Activity size={40} className={riskEvents.some(e => e.type === 'ANOMALY') ? 'text-rose-500' : 'text-emerald-500'} />
                      </div>
                      <p className="mt-4 text-center font-bold text-slate-200">
                        {riskEvents.some(e => e.type === 'ANOMALY') ? 'High Anomaly Signal' : 'System Baseline Normal'}
                      </p>
                    </div>
                  </div>

                  <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
                    <h5 className="text-sm font-bold uppercase text-slate-500 mb-4 tracking-tighter">Recent Heuristics</h5>
                    <div className="space-y-3">
                      {riskEvents.slice(-4).map(e => (
                        <div key={e.id} className="flex items-start space-x-3 text-xs bg-slate-950 p-2 rounded-lg border border-slate-800">
                          <AlertTriangle size={14} className="text-amber-500 mt-0.5" />
                          <div>
                            <p className="font-bold text-slate-300">{e.type}</p>
                            <p className="text-slate-500">{new Date(e.timestamp).toLocaleTimeString()}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-2xl font-bold">Immutable Audit Chain</h3>
                  <p className="text-slate-400 text-sm">SHA-256 linked records providing non-repudiation and tamper-evidence.</p>
                </div>
                <div className="flex space-x-3">
                  <button 
                    onClick={verifyChain}
                    disabled={isVerifyingChain || logs.length === 0}
                    className="bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors border border-emerald-500/30"
                  >
                    <CheckCircle size={18} />
                    <span>{isVerifyingChain ? 'Verifying Integrity...' : 'Verify Chain Integrity'}</span>
                  </button>
                </div>
              </div>

              {chainValid !== null && (
                <div className={`p-4 rounded-xl border flex items-center space-x-4 animate-in fade-in slide-in-from-top-4 duration-500 ${
                  chainValid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                }`}>
                  {chainValid ? <CheckCircle size={24} /> : <XCircle size={24} />}
                  <div>
                    <h5 className="font-bold">{chainValid ? 'Chain Integrity Validated' : 'TAMPER DETECTED: Chain Broken'}</h5>
                    <p className="text-sm opacity-80">
                      {chainValid 
                        ? `All ${logs.length} blocks successfully hashed and verified against previous signatures.`
                        : 'A discrepancy was found in the hash link. The audit trail has been compromised.'}
                    </p>
                  </div>
                </div>
              )}

              <div className="space-y-4">
                {logs.slice().reverse().map((log, idx) => (
                  <div key={log.id} className="group relative bg-slate-900 border border-slate-800 rounded-xl p-6 transition-all hover:border-blue-500/50">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-4">
                        <div className="bg-slate-800 px-3 py-1 rounded text-xs font-mono text-slate-400">BLOCK #{logs.length - idx}</div>
                        <span className="font-bold text-blue-400 tracking-wide uppercase text-sm">{log.action}</span>
                      </div>
                      <span className="text-xs text-slate-500 font-mono">{log.timestamp}</span>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <p className="text-[10px] text-slate-500 font-bold uppercase">Previous Block Hash</p>
                        <p className="text-xs font-mono break-all text-slate-400 bg-slate-950 p-2 rounded border border-slate-800">{log.previousHash}</p>
                      </div>
                      <div className="space-y-2">
                        <p className="text-[10px] text-blue-500 font-bold uppercase">Current Signature (SHA-256)</p>
                        <p className="text-xs font-mono break-all text-blue-300 bg-slate-950 p-2 rounded border border-blue-900/30">{log.currentHash}</p>
                      </div>
                    </div>

                    <div className="mt-4 pt-4 border-t border-slate-800/50">
                      <details className="cursor-pointer group">
                        <summary className="text-xs text-slate-500 hover:text-slate-300 flex items-center space-x-1 outline-none">
                          <span>View Payload Context</span>
                        </summary>
                        <pre className="mt-3 bg-slate-950 p-4 rounded-lg text-xs font-mono text-slate-400 overflow-x-auto border border-slate-800">
                          {JSON.stringify(log.data, null, 2)}
                        </pre>
                      </details>
                    </div>

                    {/* Linking line for visual effect */}
                    {idx < logs.length - 1 && (
                      <div className="absolute -bottom-4 left-1/2 w-0.5 h-4 bg-slate-800"></div>
                    )}
                  </div>
                ))}
                {logs.length === 0 && (
                  <div className="bg-slate-900 border border-slate-800 border-dashed rounded-2xl p-12 text-center text-slate-500">
                    <Database size={48} className="mx-auto mb-4 opacity-20" />
                    <p>Genesis block not found. Perform an action to initialize audit chain.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'users' && (
            <div className="space-y-6">
               <div className="flex items-center justify-between">
                <h3 className="text-2xl font-bold">User Directory</h3>
                <div className="bg-slate-800 p-1 rounded-lg flex">
                  <button className="px-3 py-1 bg-blue-600 text-white rounded text-xs">All Users</button>
                  <button className="px-3 py-1 text-slate-400 rounded text-xs hover:text-white">High Risk</button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[user, ...Array(5).fill(null).map((_, i) => ({
                   id: `usr_${i+10}`,
                   username: ['j.doe', 'a.security', 'analyst_pro', 'system_bot', 'support_01'][i],
                   email: `user${i}@zt.io`,
                   role: i === 1 ? UserRole.SECURITY_ANALYST : UserRole.USER,
                   trustScore: [92, 45, 12, 100, 88][i],
                   lastLoginIp: `192.168.10.${100 + i}`,
                   lastLoginTime: new Date().toISOString()
                }))].map((u: any) => (
                  <div key={u.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:shadow-lg hover:shadow-blue-500/5 transition-all">
                    <div className="flex items-start justify-between mb-4">
                      <div className="w-12 h-12 rounded-xl bg-slate-800 flex items-center justify-center">
                        <UserIcon className="text-slate-400" size={24} />
                      </div>
                      <div className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest ${
                        u.trustScore > 70 ? 'bg-emerald-500/10 text-emerald-500' :
                        u.trustScore > 40 ? 'bg-amber-500/10 text-amber-500' :
                        'bg-rose-500/10 text-rose-500'
                      }`}>
                        {u.trustScore > 70 ? 'Trusted' : u.trustScore > 40 ? 'Suspicious' : 'Critical Risk'}
                      </div>
                    </div>
                    <h5 className="font-bold text-lg text-slate-100">{u.username}</h5>
                    <p className="text-slate-500 text-xs mb-4">{u.email}</p>
                    
                    <div className="space-y-3 pt-4 border-t border-slate-800">
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-slate-500">Role</span>
                        <span className="text-slate-300 font-medium">{u.role}</span>
                      </div>
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-slate-500">Trust Score</span>
                        <span className={`font-mono font-bold ${
                          u.trustScore > 70 ? 'text-emerald-400' :
                          u.trustScore > 40 ? 'text-amber-400' :
                          'text-rose-400'
                        }`}>{u.trustScore}/100</span>
                      </div>
                    </div>
                    
                    <div className="mt-6 flex space-x-2">
                      <button className="flex-1 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors">Details</button>
                      <button className="px-3 py-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 rounded-lg text-xs font-semibold transition-colors">Block</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'devices' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-2xl font-bold">Managed Device Inventory</h3>
                <button className="bg-slate-800 text-white px-4 py-2 rounded-lg text-sm border border-slate-700 hover:bg-slate-700 transition-colors">
                  Add Provisioning Rule
                </button>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
                <table className="w-full text-left">
                  <thead>
                    <tr className="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider">
                      <th className="px-6 py-4 font-medium">Device Name</th>
                      <th className="px-6 py-4 font-medium">Hardware Fingerprint</th>
                      <th className="px-6 py-4 font-medium">Last Known IP</th>
                      <th className="px-6 py-4 font-medium">Status</th>
                      <th className="px-6 py-4 font-medium text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {devices.map(device => (
                      <tr key={device.id} className="text-sm hover:bg-slate-800/50 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-center space-x-3">
                            <div className="bg-slate-800 p-2 rounded">
                              <Smartphone size={16} className="text-indigo-400" />
                            </div>
                            <div>
                              <p className="font-semibold text-slate-100">{device.name}</p>
                              <p className="text-[10px] text-slate-500">Seen: {new Date(device.lastSeen).toLocaleDateString()}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-xs font-mono text-slate-500 uppercase">{device.deviceHash}</td>
                        <td className="px-6 py-4 font-mono text-slate-300">{device.ip}</td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${device.trusted ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'}`}>
                            {device.trusted ? 'Trusted Asset' : 'Untrusted'}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button className="text-slate-400 hover:text-white transition-colors">Manage</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Real-time Alerts Panel (Overlay Simulation) */}
      <div className="fixed bottom-8 right-8 w-80 space-y-4 pointer-events-none z-50">
        {riskEvents.slice(-2).map((alert, i) => (
          <div key={alert.id} className={`p-4 rounded-xl border-l-4 shadow-2xl bg-slate-900 border border-slate-800 pointer-events-auto animate-in slide-in-from-right-full duration-300 ${
            alert.value <= -40 ? 'border-l-rose-500' : 'border-l-amber-500'
          }`}>
            <div className="flex justify-between items-start mb-2">
              <span className={`text-[10px] font-bold uppercase tracking-wider ${alert.value <= -40 ? 'text-rose-400' : 'text-amber-400'}`}>
                {alert.value <= -40 ? 'Critical Threat Detected' : 'Security Warning'}
              </span>
              <button className="text-slate-500 hover:text-slate-300">
                <XCircle size={14} />
              </button>
            </div>
            <p className="text-xs text-slate-200 mb-2">{alert.type}: Potential identity risk triggered penalty of {alert.value}.</p>
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-500 font-mono">{new Date(alert.timestamp).toLocaleTimeString()}</span>
              <button className="text-[10px] font-bold text-blue-400 hover:underline">REMEDIATE</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default App;
