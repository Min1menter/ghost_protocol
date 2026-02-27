import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { URLRiskScorer, URLRiskResult } from '../url-risk-scorer';

interface EventLog {
  id?: number;
  threat_type: string;
  severity: string;
  target: string;
  timestamp: string;
  entropy?: number;
}

interface SystemHealth {
  total_processes: number;
  cpu_usage: number;
  memory_used_gb: number;
  memory_total_gb: number;
}

interface WhitelistEntry {
  id?: number;
  process_name: string;
  added_at: string;
}

interface AiExplanation {
  original_log: string;
  explanation: string;
  recommendations: string[];
}

function Dashboard() {
  const [logs, setLogs] = useState<EventLog[]>([]);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [newProcess, setNewProcess] = useState("");


  
  


  const [aiExplanation, setAiExplanation] = useState<AiExplanation | null>(null);
  const [showAiModal, setShowAiModal] = useState(false);
  const [showRceAlert, setShowRceAlert] = useState(false);
  const [currentRceAlert, setCurrentRceAlert] = useState<EventLog | null>(null);
  
  // Threat confirmation dialog state
  const [showThreatConfirmation, setShowThreatConfirmation] = useState(false);
  const [currentThreat, setCurrentThreat] = useState<any>(null);

  // URL Risk Scoring state
  const [urlScorer] = useState(() => new URLRiskScorer());
  const [urlInput, setUrlInput] = useState('');
  const [urlResult, setUrlResult] = useState<URLRiskResult | null>(null);
  const [showUrlModal, setShowUrlModal] = useState(false);
  const [urlHistory, setUrlHistory] = useState<Array<{url: string, result: URLRiskResult, timestamp: string}>>([]);

  useEffect(() => {
    loadLogs();
    loadHealth();
    loadWhitelist();

    const interval = setInterval(() => {
      loadHealth();
    }, 5000);

    const currentWindow = getCurrentWebviewWindow();
    const unlisten = currentWindow.listen("threat-alert", (event: any) => {
      const alert = event.payload;
      setLogs((prev) => [alert, ...prev]);
      
      // Check if this is an RCE alert and show immediate notification
      if (alert.threat_type && alert.threat_type.toLowerCase().includes('rce')) {
        setCurrentRceAlert(alert);
        setShowRceAlert(true);
        
        // Auto-play alert sound (if available)
        const audio = new Audio('/alert.mp3');
        audio.play().catch(() => {
          // Ignore if audio file doesn't exist or can't play
          console.log('Alert sound not available');
        });
      }
    });

    // Listen for threat confirmation requests
    const unlistenThreatConfirm = currentWindow.listen("threat-confirmation-request", (event: any) => {
      const threat = event.payload;
      console.log('Threat confirmation request received:', threat);
      setCurrentThreat(threat);
      setShowThreatConfirmation(true);
      
      // Auto-play alert sound (if available)
      const audio = new Audio('/alert.mp3');
      audio.play().catch(() => {
        console.log('Alert sound not available');
      });
    });

    return () => {
      clearInterval(interval);
      unlisten.then((fn) => fn());
      unlistenThreatConfirm.then((fn) => fn());
    };
  }, []);

  const loadLogs = async () => {
    try {
      const result = await invoke<EventLog[]>("get_logs", { limit: 50 });
      setLogs(result);
    } catch (error) {
      console.error("Failed to load logs:", error);
    }
  };

  const loadHealth = async () => {
    try {
      const result = await invoke<SystemHealth>("get_system_health");
      setHealth(result);
    } catch (error) {
      console.error("Failed to load health:", error);
    }
  };

  const loadWhitelist = async () => {
    console.log("Loading whitelist...");
    try {
      const result = await invoke<WhitelistEntry[]>("get_whitelist");
      console.log("Whitelist loaded:", result);
      console.log("Number of whitelist entries:", result.length);
      if (result.length > 0) {
        console.log("First entry:", result[0]);
      }
      setWhitelist(result);
    } catch (error) {
      console.error("Failed to load whitelist:", error);
    }
  };

  const addToWhitelist = async () => {
    console.log("addToWhitelist called, newProcess:", `"${newProcess}"`);
    console.log("newProcess.trim() length:", newProcess.trim().length);
    
    if (!newProcess.trim()) {
      console.log("Empty process name, skipping");
      return;
    }
    console.log("Adding to whitelist:", newProcess);
    try {
      const result = await invoke("add_to_whitelist", { processName: newProcess });
      console.log("Add result:", result);
      setNewProcess("");
      loadWhitelist();
    } catch (error) {
      console.error("Failed to add to whitelist:", error);
      alert(`Failed to add to whitelist: ${error}`);
    }
  };

  const removeFromWhitelist = async (id: number, processName: string) => {
    console.log("Removing from whitelist:", id, processName);
    try {
      const result = await invoke("remove_from_whitelist", { id, processName });
      console.log("Remove result:", result);
      loadWhitelist();
    } catch (error) {
      console.error("Failed to remove from whitelist:", error);
      alert(`Failed to remove from whitelist: ${error}`);
    }
  };

  const explainThreat = async (log: EventLog) => {
    try {
      const result = await invoke("request_ai_explanation", {
        logText: JSON.stringify(log),
      });
      setAiExplanation(result as AiExplanation);
      setShowAiModal(true);
    } catch (error) {
      console.error("Failed to get AI explanation:", error);
      alert("Failed to get AI explanation. Check console for details.");
    }
  };

  const handleThreatDecision = async (shouldRemove: boolean) => {
    if (!currentThreat) return;
    
    try {
      const result = await invoke("handle_threat_decision", {
        alertId: currentThreat.alert_id,
        shouldRemove: shouldRemove,
        pid: currentThreat.child_pid
      });
      
      console.log('Threat decision result:', result);
      setShowThreatConfirmation(false);
      setCurrentThreat(null);
      
      // Refresh logs to see the action result
      loadLogs();
    } catch (error) {
      console.error("Failed to handle threat decision:", error);
      alert(`Failed to process threat decision: ${error}`);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "text-red-500";
      case "HIGH":
        return "text-orange-500";
      case "MEDIUM":
        return "text-yellow-500";
      default:
        return "text-blue-500";
    }
  };

  const getThreatTypeIcon = (threatType: string) => {
    const type = threatType.toLowerCase();
    if (type.includes('rce')) return '🚨';
    if (type.includes('malware') || type.includes('virus')) return '🦠';
    if (type.includes('ransom')) return '🔒';
    if (type.includes('keylog')) return '⌨️';
    if (type.includes('credential')) return '🔑';
    if (type.includes('miner')) return '⛏️';
    if (type.includes('backdoor') || type.includes('trojan')) return '🚪';
    if (type.includes('inject')) return '💉';
    if (type.includes('suspicious')) return '⚠️';
    return '🔍';
  };

  const getThreatTypeBadge = (threatType: string) => {
    const type = threatType.toLowerCase();
    if (type.includes('rce')) {
      return <span className="bg-red-600 text-white text-xs px-2 py-1 rounded-full font-semibold">RCE</span>;
    }
    if (type.includes('malware') || type.includes('virus')) {
      return <span className="bg-purple-600 text-white text-xs px-2 py-1 rounded-full font-semibold">MALWARE</span>;
    }
    if (type.includes('ransom')) {
      return <span className="bg-orange-600 text-white text-xs px-2 py-1 rounded-full font-semibold">RANSOMWARE</span>;
    }
    if (type.includes('keylog')) {
      return <span className="bg-pink-600 text-white text-xs px-2 py-1 rounded-full font-semibold">KEYLOGGER</span>;
    }
    if (type.includes('credential')) {
      return <span className="bg-indigo-600 text-white text-xs px-2 py-1 rounded-full font-semibold">CRED THEFT</span>;
    }
    if (type.includes('miner')) {
      return <span className="bg-yellow-600 text-white text-xs px-2 py-1 rounded-full font-semibold">MINER</span>;
    }
    if (type.includes('backdoor') || type.includes('trojan')) {
      return <span className="bg-red-700 text-white text-xs px-2 py-1 rounded-full font-semibold">BACKDOOR</span>;
    }
    if (type.includes('inject')) {
      return <span className="bg-violet-600 text-white text-xs px-2 py-1 rounded-full font-semibold">INJECTION</span>;
    }
    if (type.includes('suspicious')) {
      return <span className="bg-gray-600 text-white text-xs px-2 py-1 rounded-full font-semibold">SUSPICIOUS</span>;
    }
    return <span className="bg-blue-600 text-white text-xs px-2 py-1 rounded-full font-semibold">THREAT</span>;
  };

  const scoreUrl = () => {
    if (!urlInput.trim()) return;
    
    const result = urlScorer.scoreURL(urlInput);
    setUrlResult(result);
    
    // Add to history
    const historyEntry = {
      url: urlInput,
      result: result,
      timestamp: new Date().toLocaleString()
    };
    setUrlHistory(prev => [historyEntry, ...prev.slice(0, 9)]); // Keep last 10 entries
    
    // Show modal if blocked or warned
    if (result.verdict === 'BLOCK' || result.verdict === 'WARN') {
      setShowUrlModal(true);
    }
  };

  const handleUrlUnblock = () => {
    if (urlResult && urlInput) {
      urlScorer.unblockURL(urlInput);
      
      // Re-score the URL (should now be ALLOW)
      const newResult = urlScorer.scoreURL(urlInput);
      setUrlResult(newResult);
      
      // Update history
      setUrlHistory(prev => prev.map(entry => 
        entry.url === urlInput 
          ? { ...entry, result: newResult }
          : entry
      ));
      
      setShowUrlModal(false);
    }
  };

  const getUrlVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'ALLOW': return 'text-green-400';
      case 'WARN': return 'text-yellow-400';
      case 'BLOCK': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getUrlScoreColor = (score: number) => {
    if (score >= 50) return 'text-red-400';
    if (score >= 20) return 'text-yellow-400';
    return 'text-green-400';
  };

  const testURLScorer = (url: string) => {
    console.log(' Testing URL:', url);
    const result = urlScorer.scoreURL(url);
    console.log(' Result:', result);
    
    // Add to history
    const historyEntry = {
      url: url,
      result: result,
      timestamp: new Date().toLocaleString()
    };
    setUrlHistory(prev => [historyEntry, ...prev.slice(0, 9)]);
    setUrlResult(result);
    
    return result;
  };

  (window as any).testURLScorer = testURLScorer;
  (window as any).unblockURL = (url: string) => {
    console.log('🔄 Unblocking URL:', url);
    urlScorer.unblockURL(url);
    const newResult = urlScorer.scoreURL(url);
    console.log('✅ After unblock:', newResult);
    setUrlResult(newResult);
    setUrlHistory(prev => prev.map(entry => 
      entry.url === url 
        ? { ...entry, result: newResult }
        : entry
    ));
  };

  useEffect(() => {
    console.log('🚀 URL Risk Scorer loaded!');
    console.log('💻 Available console commands:');
    console.log('  testURLScorer("https://example.com") - Test any URL');
    console.log('  unblockURL("https://example.com") - Unblock and trust URL');
    console.log('');
    console.log('🧪 Running quick tests...');
    
    const testUrls = [
      'https://google.com',
      'https://suspicious.xyz', 
      'https://example.com@malicious.com',
      'https://example.com/program.exe',
      'http://192.168.1.1',
      'https://paypal-secure.com'
    ];
    
    testUrls.forEach((url, index) => {
      setTimeout(() => {
        const result = testURLScorer(url);
        console.log(`${index + 1}. ${url} → ${result.verdict} (${result.score}pts)`);
      }, index * 200);
    });
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-6">
      <header className="mb-8">
        <div>
          <h1 className="text-4xl font-bold text-transparent bg-clip-text bg-gradient-b-to-r from-purple-400 to-pink-600">
            Ghost Layer Security Console
          </h1>
          <p className="text-gray-400 mt-2">Industrial-grade threat detection and isolation</p>
        </div>
      </header>

      {/* System Health */}
      {health && (
        <div className="grid grid-cols-4 gap-4 mb-8">
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">Active Processes</div>
            <div className="text-2xl font-bold text-blue-400">{health.total_processes}</div>
            <div className="text-xs text-gray-500 mt-1">Running applications</div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">CPU Usage</div>
            <div className={`text-2xl font-bold ${health.cpu_usage > 80 ? 'text-red-400' : health.cpu_usage > 50 ? 'text-yellow-400' : 'text-green-400'}`}>
              {health.cpu_usage.toFixed(1)}%
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {health.cpu_usage > 80 ? 'High load' : health.cpu_usage > 50 ? 'Moderate load' : 'Normal'}
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">Memory Usage</div>
            <div className={`text-2xl font-bold ${(health.memory_used_gb / health.memory_total_gb) > 0.8 ? 'text-red-400' : (health.memory_used_gb / health.memory_total_gb) > 0.6 ? 'text-yellow-400' : 'text-green-400'}`}>
              {health.memory_used_gb.toFixed(1)} / {health.memory_total_gb.toFixed(1)} GB
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {((health.memory_used_gb / health.memory_total_gb) * 100).toFixed(1)}% utilized
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
            <div className="text-gray-400 text-sm mb-1">Threats Detected</div>
            <div className={`text-2xl font-bold ${logs.length > 0 ? 'text-red-500' : 'text-green-400'}`}>
              {logs.length}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {logs.length > 0 ? `${logs.length} security events` : 'System secure'}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Threat Logs */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h2 className="text-xl font-bold mb-4">Threat Logs</h2>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {logs.length === 0 ? (
              <div className="text-center text-gray-500 py-8">
                <div className="text-lg mb-2">No Threats Detected</div>
                <div className="text-sm">System is running smoothly with no security threats detected.</div>
              </div>
            ) : (
              logs.map((log, idx) => (
                <div key={idx} className="bg-gray-700 rounded p-4 border border-gray-600 hover:border-gray-500 transition-colors">
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center gap-2">
                      <span className="text-lg mr-2">{getThreatTypeIcon(log.threat_type)}</span>
                      <span className={`font-bold text-lg ${getSeverityColor(log.severity)}`}>
                        {log.severity}
                      </span>
                      {getThreatTypeBadge(log.threat_type)}
                    </div>
                    <span className="text-xs text-gray-400">
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                  </div>
                  
                  <div className="mb-2">
                    <div className="text-sm font-semibold text-blue-400 mb-1">Threat Type:</div>
                    <div className="text-sm text-gray-200">{log.threat_type}</div>
                  </div>
                  
                  <div className="mb-2">
                    <div className="text-sm font-semibold text-yellow-400 mb-1">Target:</div>
                    <div className="text-xs text-gray-300 font-mono bg-gray-800 px-2 py-1 rounded">
                      {log.target}
                    </div>
                  </div>
                  
                  {log.entropy && (
                    <div className="mb-3">
                      <div className="text-xs text-purple-400">
                        <span className="font-semibold">Entropy:</span> {log.entropy.toFixed(2)}
                        {log.entropy > 7.0 && (
                          <span className="ml-2 text-orange-400">(High - Suspicious)</span>
                        )}
                      </div>
                    </div>
                  )}
                  
                  <div className="flex gap-2 mt-3">
                    <button
                      onClick={() => explainThreat(log)}
                      className="text-xs bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded transition-colors"
                    >
                      AI Explain
                    </button>
                    {log.threat_type.toLowerCase().includes('rce') && (
                      <div className="text-xs bg-red-900 bg-opacity-50 px-2 py-1 rounded text-red-300">
                        Remote Code Execution Attempt
                      </div>
                    )}
                    {log.threat_type.toLowerCase().includes('malware') && (
                      <div className="text-xs bg-purple-900 bg-opacity-50 px-2 py-1 rounded text-purple-300">
                        Malicious Software Detected
                      </div>
                    )}
                    {log.threat_type.toLowerCase().includes('ransom') && (
                      <div className="text-xs bg-orange-900 bg-opacity-50 px-2 py-1 rounded text-orange-300">
                        Ransomware Activity
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Whitelist */}
        <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h2 className="text-xl font-bold mb-4">Process Whitelist</h2>
          <div className="mb-4 p-3 bg-gray-700 rounded border border-gray-600">
            <div className="text-sm text-gray-300 mb-2">
              <strong>Trusted Applications:</strong> {whitelist.length} processes whitelisted
            </div>
            <div className="text-xs text-gray-400">
              Whitelisted processes are allowed to run without triggering security alerts
            </div>
          </div>
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              placeholder="Process name (e.g., chrome.exe)"
              value={newProcess}
              onChange={(e) => setNewProcess(e.target.value)}
              className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2"
              onKeyPress={(e) => e.key === 'Enter' && addToWhitelist()}
            />
            <button
              onClick={() => {
                console.log("Add button clicked!");
                addToWhitelist();
              }}
              className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded font-medium transition-colors"
            >
              Add
            </button>
          </div>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {whitelist.length === 0 ? (
              <div className="text-center text-gray-500 py-6">
                <div className="text-sm">No whitelisted processes</div>
                <div className="text-xs mt-1">Add trusted applications to prevent false positives</div>
              </div>
            ) : (
              whitelist.map((entry) => (
                <div
                  key={entry.id}
                  className="bg-gray-700 rounded p-3 border border-gray-600 flex justify-between items-center hover:border-gray-500 transition-colors"
                >
                  <div className="flex-1">
                    <div className="font-medium text-green-400">{entry.process_name}</div>
                    <div className="text-xs text-gray-400">
                      Added: {new Date(entry.added_at).toLocaleString()}
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      console.log("Remove button clicked for:", entry.id, entry.process_name);
                      entry.id && removeFromWhitelist(entry.id, entry.process_name);
                    }}
                    className="text-red-400 hover:text-red-300 text-sm hover:bg-red-900 hover:bg-opacity-30 px-2 py-1 rounded transition-colors"
                  >
                    Remove
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* URL Risk Scoring Section */}
      <div className="mt-8 bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
          🔍 URL Risk Scoring Algorithm
        </h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* URL Input Section */}
          <div className="lg:col-span-1">
            <h3 className="text-lg font-semibold mb-4 text-blue-400">Link Analysis</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Enter URL to analyze:
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="https://example.com"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    className="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                    onKeyPress={(e) => e.key === 'Enter' && scoreUrl()}
                  />
                  <button
                    onClick={scoreUrl}
                    className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded font-medium transition-colors"
                  >
                    Analyze
                  </button>
                </div>
              </div>
              
              {urlResult && (
                <div className="bg-gray-700 rounded p-4 border border-gray-600">
                  <h4 className="font-semibold mb-3">Analysis Results:</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Verdict:</span>
                      <span className={`font-bold ${getUrlVerdictColor(urlResult.verdict)}`}>
                        {urlResult.verdict}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Risk Score:</span>
                      <span className={`font-bold ${getUrlScoreColor(urlResult.score)}`}>
                        {urlResult.score}
                      </span>
                    </div>
                  </div>
                  
                  {urlResult.reasons.length > 0 && (
                    <div className="mt-3">
                      <div className="text-sm font-semibold text-gray-300 mb-2">Risk Factors:</div>
                      <div className="space-y-1">
                        {urlResult.reasons.map((reason, index) => (
                          <div key={index} className="text-xs text-gray-400 flex items-center gap-2">
                            <span className="w-2 h-2 bg-yellow-400 rounded-full"></span>
                            {reason}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Recent Analysis */}
          <div className="lg:col-span-1">
            <h3 className="text-lg font-semibold mb-4 text-green-400">Recent Analysis</h3>
            <div className="space-y-3">
              <div className="bg-gray-700 rounded p-3 border border-gray-600">
                <div className="text-sm font-semibold text-gray-300 mb-2">Recent Analysis:</div>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {urlHistory.length === 0 ? (
                    <div className="text-xs text-gray-500 text-center py-2">
                      No URLs analyzed yet
                    </div>
                  ) : (
                    urlHistory.map((entry, index) => (
                      <div key={index} className="bg-gray-800 rounded p-2 border border-gray-600">
                        <div className="flex justify-between items-start mb-1">
                          <div className="text-xs font-mono text-blue-300 truncate flex-1">
                            {entry.url}
                          </div>
                          <span className={`text-xs font-bold ${getUrlVerdictColor(entry.result.verdict)} ml-2`}>
                            {entry.result.verdict}
                          </span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-500">
                            {entry.timestamp}
                          </span>
                          <span className={`text-xs font-bold ${getUrlScoreColor(entry.result.score)}`}>
                            {entry.result.score}pts
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
              
              {urlResult && urlResult.verdict !== 'ALLOW' && (
                <div className="bg-gray-700 rounded p-3 border border-gray-600">
                  <div className="text-sm font-semibold text-gray-300 mb-2">User Feedback:</div>
                  <button
                    onClick={handleUrlUnblock}
                    className="w-full bg-green-600 hover:bg-green-700 px-3 py-2 rounded text-sm font-medium transition-colors"
                  >
                    🔄 Unblock & Trust URL
                  </button>
                  <div className="text-xs text-gray-400 mt-2">
                    Adds URL to personal trusted list
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* RCE Alert Modal */}
      {showRceAlert && currentRceAlert && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
          <div className="bg-red-900 border-2 border-red-500 rounded-lg p-6 max-w-lg mx-4 shadow-2xl animate-pulse">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 bg-red-500 rounded-full flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
              </div>
              <div>
                <h3 className="text-2xl font-bold text-white">RCE ATTACK DETECTED!</h3>
                <p className="text-red-200 text-sm">Remote Code Execution Attempt Blocked</p>
              </div>
            </div>
            
            <div className="bg-black bg-opacity-50 rounded p-4 mb-4">
              <div className="text-sm text-red-200 mb-2">
                <span className="font-semibold text-white">Hijacked Application:</span> {currentRceAlert.target}
              </div>
              <div className="text-sm text-red-200 mb-2">
                <span className="font-semibold text-white">Time:</span> {new Date(currentRceAlert.timestamp).toLocaleString()}
              </div>
              <div className="text-sm text-red-200">
                <span className="font-semibold text-white">Severity:</span> 
                <span className="ml-2 text-red-400 font-bold animate-pulse">CRITICAL</span>
              </div>
            </div>
            
            <div className="bg-yellow-900 bg-opacity-50 border border-yellow-600 rounded p-3 mb-4">
              <p className="text-yellow-200 text-sm">
                <strong>IMMEDIATE ACTION REQUIRED:</strong> A trusted application was hijacked to execute malicious commands. 
                The attack has been blocked, but your system may be compromised.
              </p>
            </div>
            
            <div className="flex gap-3">
              <button
                onClick={() => {
                  setShowRceAlert(false);
                  explainThreat(currentRceAlert);
                }}
                className="flex-1 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded font-medium transition-colors"
              >
                View AI Analysis
              </button>
              <button
                onClick={() => setShowRceAlert(false)}
                className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded font-medium transition-colors"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Explanation Modal */}
      {showAiModal && aiExplanation && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-3xl max-h-[85vh] overflow-y-auto border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-6 border-b border-gray-700 pb-4">
              <div>
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  AI Threat Analysis
                </h3>
                <p className="text-sm text-gray-400 mt-1">Powered by Google Gemini AI</p>
              </div>
              <button
                onClick={() => setShowAiModal(false)}
                className="text-gray-400 hover:text-white text-xl hover:bg-gray-700 w-8 h-8 rounded-full flex items-center justify-center transition-colors"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-6">
              <div>
                <h4 className="font-semibold text-blue-400 mb-3 flex items-center gap-2">
                  Original Security Log:
                </h4>
                <pre className="bg-gray-900 p-4 rounded text-sm text-gray-300 overflow-x-auto border border-gray-700">
                  {aiExplanation.original_log}
                </pre>
              </div>
              
              <div>
                <h4 className="font-semibold text-green-400 mb-3 flex items-center gap-2">
                  AI Analysis & Explanation:
                </h4>
                <div className="bg-gray-900 p-4 rounded text-sm text-gray-300 whitespace-pre-wrap border border-gray-700 leading-relaxed">
                  {aiExplanation.explanation}
                </div>
              </div>
              
              <div>
                <h4 className="font-semibold text-yellow-400 mb-3 flex items-center gap-2">
                  Security Recommendations:
                </h4>
                <div className="bg-gray-900 p-4 rounded border border-gray-700">
                  <ul className="space-y-3">
                    {aiExplanation.recommendations.map((rec, index) => (
                      <li key={index} className="text-sm text-gray-300 flex items-start gap-3">
                        <span className="text-yellow-400 font-bold mt-0.5">{index + 1}.</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              
              <div className="pt-4 border-t border-gray-700">
                <div className="flex items-center justify-between">
                  <div className="text-xs text-gray-500">
                    This AI analysis is for informational purposes. Always verify threats through multiple security layers.
                  </div>
                  <button
                    onClick={() => setShowAiModal(false)}
                    className="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded text-sm font-medium transition-colors"
                  >
                    Close Analysis
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Threat Confirmation Modal */}
      {showThreatConfirmation && currentThreat && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 max-w-2xl border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-6 border-b border-gray-700 pb-4">
              <div>
                <h3 className="text-xl font-bold text-red-400 flex items-center gap-2">
                  🚨 Threat Detected - Action Required
                </h3>
                <p className="text-sm text-gray-400 mt-1">
                  Immediate user decision needed to handle security threat
                </p>
              </div>
              <button
                onClick={() => setShowThreatConfirmation(false)}
                className="text-gray-400 hover:text-white text-xl hover:bg-gray-700 w-8 h-8 rounded-full flex items-center justify-center transition-colors"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4 mb-6">
              <div className="bg-red-900 bg-opacity-30 border border-red-700 rounded p-4">
                <h4 className="font-semibold text-red-400 mb-2">Threat Details:</h4>
                <div className="space-y-2 text-sm">
                  <div><span className="text-gray-400">Type:</span> <span className="text-red-300 font-semibold">{currentThreat.alert_type}</span></div>
                  <div><span className="text-gray-400">Process:</span> <span className="text-red-300 font-mono">{currentThreat.child_process} (PID: {currentThreat.child_pid})</span></div>
                  <div><span className="text-gray-400">Parent:</span> <span className="text-red-300 font-mono">{currentThreat.parent_process} (PID: {currentThreat.parent_pid})</span></div>
                  <div><span className="text-gray-400">Severity:</span> <span className="text-red-300 font-semibold">{currentThreat.severity}</span></div>
                </div>
              </div>
              
              <div className="bg-gray-900 border border-gray-700 rounded p-4">
                <h4 className="font-semibold text-yellow-400 mb-2">Explanation:</h4>
                <p className="text-sm text-gray-300 leading-relaxed">
                  {currentThreat.explanation}
                </p>
              </div>
              
              <div className="bg-blue-900 bg-opacity-30 border border-blue-700 rounded p-4">
                <h4 className="font-semibold text-blue-400 mb-2">Recommended Action:</h4>
                <p className="text-sm text-blue-300">
                  {currentThreat.message}
                </p>
              </div>
            </div>
            
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => handleThreatDecision(false)}
                className="bg-gray-600 hover:bg-gray-700 px-6 py-3 rounded text-white font-medium transition-colors"
              >
                Ignore Threat
              </button>
              <button
                onClick={() => handleThreatDecision(true)}
                className="bg-red-600 hover:bg-red-700 px-6 py-3 rounded text-white font-medium transition-colors flex items-center gap-2"
              >
                🗑️ Remove Threat
              </button>
            </div>
          </div>
        </div>
      )}

      {/* URL Risk Scoring Modal */}
      {showUrlModal && urlResult && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
          <div className={`${urlResult.verdict === 'BLOCK' ? 'bg-red-900 border-red-500' : 'bg-yellow-900 border-yellow-500'} border-2 rounded-lg p-6 max-w-lg mx-4 shadow-2xl`}>
            <div className="flex items-center gap-3 mb-4">
              <div className={`w-12 h-12 ${urlResult.verdict === 'BLOCK' ? 'bg-red-500' : 'bg-yellow-500'} rounded-full flex items-center justify-center`}>
                {urlResult.verdict === 'BLOCK' ? (
                  <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                  </svg>
                ) : (
                  <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                )}
              </div>
              <div>
                <h3 className={`text-2xl font-bold text-white`}>
                  {urlResult.verdict === 'BLOCK' ? '🚫 URL BLOCKED!' : '⚠️ URL WARNING!'}
                </h3>
                <p className={`${urlResult.verdict === 'BLOCK' ? 'text-red-200' : 'text-yellow-200'} text-sm`}>
                  {urlResult.verdict === 'BLOCK' ? 'Dangerous URL detected - Access denied' : 'Suspicious URL detected - Proceed with caution'}
                </p>
              </div>
            </div>
            
            <div className="bg-black bg-opacity-50 rounded p-4 mb-4">
              <div className="text-sm text-gray-200 mb-2">
                <span className="font-semibold text-white">URL:</span> {urlInput}
              </div>
              <div className="text-sm text-gray-200 mb-2">
                <span className="font-semibold text-white">Risk Score:</span> 
                <span className={`ml-2 font-bold ${urlResult.verdict === 'BLOCK' ? 'text-red-400' : 'text-yellow-400'}`}>
                  {urlResult.score} points
                </span>
              </div>
              <div className="text-sm text-gray-200">
                <span className="font-semibold text-white">Verdict:</span> 
                <span className={`ml-2 font-bold ${urlResult.verdict === 'BLOCK' ? 'text-red-400' : 'text-yellow-400'}`}>
                  {urlResult.verdict}
                </span>
              </div>
            </div>
            
            {urlResult.reasons.length > 0 && (
              <div className={`${urlResult.verdict === 'BLOCK' ? 'bg-red-800' : 'bg-yellow-800'} bg-opacity-50 border ${urlResult.verdict === 'BLOCK' ? 'border-red-600' : 'border-yellow-600'} rounded p-3 mb-4`}>
                <h4 className={`font-semibold ${urlResult.verdict === 'BLOCK' ? 'text-red-300' : 'text-yellow-300'} mb-2`}>Risk Factors Detected:</h4>
                <div className="space-y-1">
                  {urlResult.reasons.map((reason, index) => (
                    <div key={index} className={`text-sm ${urlResult.verdict === 'BLOCK' ? 'text-red-200' : 'text-yellow-200'} flex items-center gap-2`}>
                      <span className="w-2 h-2 bg-red-400 rounded-full"></span>
                      {reason}
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            <div className={`${urlResult.verdict === 'BLOCK' ? 'bg-red-800' : 'bg-yellow-800'} bg-opacity-30 border ${urlResult.verdict === 'BLOCK' ? 'border-red-600' : 'border-yellow-600'} rounded p-3 mb-4`}>
              <p className={`${urlResult.verdict === 'BLOCK' ? 'text-red-200' : 'text-yellow-200'} text-sm`}>
                <strong>{urlResult.verdict === 'BLOCK' ? 'DANGER:' : 'CAUTION:'}</strong> 
                {urlResult.verdict === 'BLOCK' 
                  ? ' This URL has been identified as dangerous and access has been blocked to protect your security.'
                  : ' This URL exhibits suspicious characteristics. Proceed with extreme caution.'
                }
              </p>
            </div>
            
            <div className="flex gap-3">
              {urlResult.verdict === 'BLOCK' ? (
                <button
                  onClick={handleUrlUnblock}
                  className="flex-1 bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded font-medium transition-colors"
                >
                  🔄 Unblock & Trust URL
                </button>
              ) : (
                <button
                  onClick={handleUrlUnblock}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded font-medium transition-colors"
                >
                  ✓ Accept Risk & Continue
                </button>
              )}
              <button
                onClick={() => setShowUrlModal(false)}
                className="flex-1 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded font-medium transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
export default Dashboard;