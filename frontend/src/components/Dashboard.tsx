import React, { useState, useEffect } from 'react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Shield, Activity, AlertTriangle, CheckCircle, TrendingUp, Server, Zap, WifiOff, Wifi, Download, Bell, BellOff, Filter, X } from 'lucide-react';

// Simulated data generator
const generateRandomIP = () => {
  return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
};

const generateThreat = () => {
  const severities = ['low', 'medium', 'high', 'critical'];
  const threatTypes = ['Port Scan', 'SQL Injection', 'DDoS Attack', 'Brute Force', 'Malware Detection'];
  const indicators = [
    'ML anomaly detected', 'High activity from source IP', 'Port scanning detected',
    'Suspicious pattern match', 'Known attack signature', 'High connection rate', 'Unusual packet size'
  ];

  const severity = severities[Math.floor(Math.random() * severities.length)];
  const score = severity === 'critical' ? 90 + Math.random() * 10 :
                severity === 'high' ? 70 + Math.random() * 20 :
                severity === 'medium' ? 50 + Math.random() * 20 :
                25 + Math.random() * 25;

  return {
    id: `THREAT_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    source_ip: generateRandomIP(),
    destination_ip: generateRandomIP(),
    threat_score: parseFloat(score.toFixed(1)),
    severity: severity,
    indicators: [
      threatTypes[Math.floor(Math.random() * threatTypes.length)],
      indicators[Math.floor(Math.random() * indicators.length)],
      indicators[Math.floor(Math.random() * indicators.length)]
    ]
  };
};

const ThreatDashboard = () => {
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({
    total_packets: 0,
    threats_detected: 0,
    anomalies_detected: 0,
    signature_matches: 0
  });
  const [isCapturing, setIsCapturing] = useState(false);
  const [timeSeriesData, setTimeSeriesData] = useState([]);
  const [severityData, setSeverityData] = useState([]);
  const [packetRate, setPacketRate] = useState(0);
  const [alertsEnabled, setAlertsEnabled] = useState(true);
  const [showNotification, setShowNotification] = useState(false);
  const [latestThreat, setLatestThreat] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [showFilterMenu, setShowFilterMenu] = useState(false);

  // Simulate packet capture
  useEffect(() => {
    let interval;
    if (isCapturing) {
      interval = setInterval(() => {
        const packetsPerSecond = Math.floor(Math.random() * 500) + 100;
        setPacketRate(packetsPerSecond);
        setStats(prev => ({
          ...prev,
          total_packets: prev.total_packets + packetsPerSecond
        }));

        if (Math.random() < 0.15) {
          const newThreat = generateThreat();
          setThreats(prev => [newThreat, ...prev].slice(0, 100));
          
          setStats(prev => ({
            ...prev,
            threats_detected: prev.threats_detected + 1,
            anomalies_detected: prev.anomalies_detected + (Math.random() > 0.5 ? 1 : 0),
            signature_matches: prev.signature_matches + Math.floor(Math.random() * 3)
          }));

          // Show alert for high/critical threats
          if (alertsEnabled && (newThreat.severity === 'high' || newThreat.severity === 'critical')) {
            setLatestThreat(newThreat);
            setShowNotification(true);
            playAlertSound();
            setTimeout(() => setShowNotification(false), 5000);
          }
        }
      }, 1000);
    }

    return () => clearInterval(interval);
  }, [isCapturing, alertsEnabled]);

  useEffect(() => {
    updateChartData();
  }, [threats]);

  const playAlertSound = () => {
    // Browser notification sound simulation
    if ('vibrate' in navigator) {
      navigator.vibrate(200);
    }
  };

  const updateChartData = () => {
    const timeData = threats.slice(0, 10).reverse().map((threat) => ({
      time: new Date(threat.timestamp).toLocaleTimeString(),
      score: threat.threat_score
    }));
    setTimeSeriesData(timeData);

    const severityCounts = threats.reduce((acc, threat) => {
      acc[threat.severity] = (acc[threat.severity] || 0) + 1;
      return acc;
    }, {});

    const severityChart = Object.entries(severityCounts).map(([severity, count]) => ({
      name: severity.toUpperCase(),
      value: count
    }));
    setSeverityData(severityChart);
  };

  const startCapture = () => {
    setIsCapturing(true);
  };

  const stopCapture = () => {
    setIsCapturing(false);
    setPacketRate(0);
  };

  const exportToCSV = () => {
    const headers = ['Timestamp', 'Source IP', 'Destination IP', 'Severity', 'Threat Score', 'Indicators'];
    const csvData = threats.map(t => [
      t.timestamp,
      t.source_ip,
      t.destination_ip,
      t.severity,
      t.threat_score,
      t.indicators.join('; ')
    ]);

    const csv = [headers, ...csvData].map(row => row.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-threats-${new Date().toISOString()}.csv`;
    a.click();
  };

  const exportToJSON = () => {
    const json = JSON.stringify(threats, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-threats-${new Date().toISOString()}.json`;
    a.click();
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#22c55e'
    };
    return colors[severity] || '#6b7280';
  };

  const filteredThreats = filterSeverity === 'all' 
    ? threats 
    : threats.filter(t => t.severity === filterSeverity);

  const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e'];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-6">
      {/* Alert Notification */}
      {showNotification && latestThreat && (
        <div className="fixed top-6 right-6 z-50 bg-red-600 border-2 border-red-400 rounded-lg p-4 shadow-2xl animate-slideIn max-w-md">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-white flex-shrink-0 animate-pulse" />
            <div className="flex-1">
              <h4 className="font-bold text-white mb-1">
                {latestThreat.severity.toUpperCase()} THREAT DETECTED
              </h4>
              <p className="text-sm text-red-100">
                {latestThreat.indicators[0]} from {latestThreat.source_ip}
              </p>
              <p className="text-xs text-red-200 mt-1">
                Threat Score: {latestThreat.threat_score}
              </p>
            </div>
            <button onClick={() => setShowNotification(false)} className="text-white hover:text-red-200">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-blue-400 animate-pulse" />
            <div>
              <h1 className="text-3xl font-bold">Sentinel AI Threat Detector</h1>
              <p className="text-gray-400">Real-time Network Security Monitoring</p>
            </div>
          </div>
          <div className="flex gap-3 flex-wrap">
            <button
              onClick={() => setAlertsEnabled(!alertsEnabled)}
              className={`px-4 py-2 rounded-lg font-semibold flex items-center gap-2 transition-all ${
                alertsEnabled 
                  ? 'bg-blue-600 hover:bg-blue-700' 
                  : 'bg-gray-600 hover:bg-gray-700'
              }`}
            >
              {alertsEnabled ? <Bell className="w-5 h-5" /> : <BellOff className="w-5 h-5" />}
              Alerts {alertsEnabled ? 'ON' : 'OFF'}
            </button>
            {!isCapturing ? (
              <button
                onClick={startCapture}
                className="px-6 py-3 bg-green-600 hover:bg-green-700 rounded-lg font-semibold flex items-center gap-2 transition-all transform hover:scale-105"
              >
                <Zap className="w-5 h-5" />
                Start Capture
              </button>
            ) : (
              <button
                onClick={stopCapture}
                className="px-6 py-3 bg-red-600 hover:bg-red-700 rounded-lg font-semibold flex items-center gap-2 transition-all transform hover:scale-105 animate-pulse"
              >
                <Activity className="w-5 h-5" />
                Stop Capture
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Demo Notice */}
      <div className="mb-6 bg-blue-900/30 border border-blue-500/50 rounded-lg p-4">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-blue-400" />
          <div>
            <p className="font-semibold text-blue-300">Demo Mode Active</p>
            <p className="text-sm text-blue-200">Simulation with realistic network patterns. Click "Start Capture" to begin.</p>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 shadow-lg transform hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Packets</p>
              <p className="text-3xl font-bold mt-1">{stats.total_packets.toLocaleString()}</p>
              {isCapturing && (
                <p className="text-xs text-green-400 mt-1">{packetRate} pkt/s</p>
              )}
            </div>
            <Server className="w-12 h-12 text-blue-400 opacity-20" />
          </div>
          <div className="mt-4 flex items-center gap-2 text-sm text-green-400">
            <TrendingUp className="w-4 h-4" />
            <span>{isCapturing ? 'Live' : 'Paused'}</span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 shadow-lg transform hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Threats Detected</p>
              <p className="text-3xl font-bold mt-1 text-red-400">{stats.threats_detected}</p>
            </div>
            <AlertTriangle className="w-12 h-12 text-red-400 opacity-20" />
          </div>
          <div className="mt-4 text-sm text-red-400">
            {stats.threats_detected > 0 ? 'Active Threats' : 'All Clear'}
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 shadow-lg transform hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">ML Anomalies</p>
              <p className="text-3xl font-bold mt-1 text-orange-400">{stats.anomalies_detected}</p>
            </div>
            <Activity className="w-12 h-12 text-orange-400 opacity-20" />
          </div>
          <div className="mt-4 text-sm text-orange-400">AI Detection</div>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 shadow-lg transform hover:scale-105 transition-transform">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Signature Matches</p>
              <p className="text-3xl font-bold mt-1 text-yellow-400">{stats.signature_matches}</p>
            </div>
            <CheckCircle className="w-12 h-12 text-yellow-400 opacity-20" />
          </div>
          <div className="mt-4 text-sm text-yellow-400">Rule-based</div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 shadow-lg">
          <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-blue-400" />
            Threat Score Timeline
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" stroke="#9ca3af" style={{ fontSize: '12px' }} />
              <YAxis stroke="#9ca3af" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#fff' }}
              />
              <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={3} dot={{ fill: '#3b82f6', r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 shadow-lg">
          <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" />
            Severity Distribution
          </h3>
          <ResponsiveContainer width="100%" height={250}>
            {severityData.length > 0 ? (
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px' }}
                />
              </PieChart>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500">
                No threats detected yet
              </div>
            )}
          </ResponsiveContainer>
        </div>
      </div>

      {/* Threats Table with Filter & Export */}
      <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 shadow-lg">
        <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
          <h3 className="text-xl font-semibold flex items-center gap-2">
            <Shield className="w-5 h-5 text-red-400" />
            Recent Threats ({filteredThreats.length})
          </h3>
          <div className="flex gap-2">
            <div className="relative">
              <button
                onClick={() => setShowFilterMenu(!showFilterMenu)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg flex items-center gap-2 transition-all"
              >
                <Filter className="w-4 h-4" />
                Filter: {filterSeverity === 'all' ? 'All' : filterSeverity}
              </button>
              {showFilterMenu && (
                <div className="absolute right-0 mt-2 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-10 min-w-[150px]">
                  {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
                    <button
                      key={sev}
                      onClick={() => { setFilterSeverity(sev); setShowFilterMenu(false); }}
                      className="w-full px-4 py-2 text-left hover:bg-gray-700 first:rounded-t-lg last:rounded-b-lg capitalize"
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              onClick={exportToCSV}
              disabled={threats.length === 0}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg flex items-center gap-2 transition-all"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </button>
            <button
              onClick={exportToJSON}
              disabled={threats.length === 0}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg flex items-center gap-2 transition-all"
            >
              <Download className="w-4 h-4" />
              Export JSON
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4 text-gray-400 font-medium">Time</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium">Source IP</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium">Destination IP</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium">Severity</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium">Score</th>
                <th className="text-left py-3 px-4 text-gray-400 font-medium">Indicators</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.slice(0, 10).map((threat, idx) => (
                <tr 
                  key={threat.id} 
                  className="border-b border-gray-700 hover:bg-gray-750 transition-all animate-fadeIn"
                  style={{ animationDelay: `${idx * 0.05}s` }}
                >
                  <td className="py-3 px-4 text-sm">
                    {new Date(threat.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-3 px-4 text-sm font-mono text-blue-300">{threat.source_ip}</td>
                  <td className="py-3 px-4 text-sm font-mono text-blue-300">{threat.destination_ip}</td>
                  <td className="py-3 px-4">
                    <span
                      className="px-3 py-1 rounded-full text-xs font-bold uppercase shadow-lg"
                      style={{ 
                        backgroundColor: getSeverityColor(threat.severity) + '20', 
                        color: getSeverityColor(threat.severity),
                        border: `1px solid ${getSeverityColor(threat.severity)}`
                      }}
                    >
                      {threat.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm font-bold text-yellow-400">{threat.threat_score}</td>
                  <td className="py-3 px-4 text-sm text-gray-400">
                    {threat.indicators.slice(0, 2).join(', ')}
                    {threat.indicators.length > 2 && '...'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filteredThreats.length === 0 && (
            <div className="text-center py-12 text-gray-400">
              <Shield className="w-16 h-16 mx-auto mb-4 opacity-20" />
              <p className="text-lg">No threats detected</p>
              <p className="text-sm mt-2">
                {filterSeverity === 'all' 
                  ? 'Start capture to begin monitoring' 
                  : `No ${filterSeverity} severity threats found`}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Status Indicator */}
      <div className="fixed bottom-6 right-6">
        <div className={`px-5 py-3 rounded-full flex items-center gap-3 shadow-2xl border-2 transition-all ${
          isCapturing 
            ? 'bg-green-600 border-green-400 animate-pulse' 
            : 'bg-gray-700 border-gray-600'
        }`}>
          {isCapturing ? (
            <Wifi className="w-5 h-5 text-white" />
          ) : (
            <WifiOff className="w-5 h-5 text-gray-400" />
          )}
          <span className="text-sm font-bold">
            {isCapturing ? 'MONITORING ACTIVE' : 'MONITORING INACTIVE'}
          </span>
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .animate-fadeIn { animation: fadeIn 0.3s ease-out forwards; }
        .animate-slideIn { animation: slideIn 0.3s ease-out forwards; }
      `}</style>
    </div>
  );
};

export default ThreatDashboard;