import React, { useState, useEffect } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import { 
  LayoutGrid, Server, ShieldAlert, RefreshCw, ChevronRight,
  X, Terminal, ShieldCheck, AlertOctagon, Layers, Globe, Download, Copy, Check, Loader2
} from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend);

export default function App() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedResource, setSelectedResource] = useState(null);
  const location = useLocation();

  const fetchData = async () => {
    if (loading && data.length > 0) return; // Prevent concurrent fetches
    setLoading(true);
    try {
      const apiEndpoint = import.meta.env.VITE_API_URL;
      const apiKey = import.meta.env.VITE_API_KEY;

      const res = await fetch(apiEndpoint, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'x-api-token': apiKey
        }
      });

      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }

      const json = await res.json();
      const findings = Array.isArray(json) ? json : (json.findings || []);
      setData(findings);
    } catch (err) {
      console.error("Error fetching scan data from AWS API Gateway:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Initial fetch on component mount
    fetchData();

    // Auto-refresh scan data every 2 minutes (120,000 ms)
    const interval = setInterval(() => {
      fetchData();
    }, 120000);

    // Cleanup interval on component unmount
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex h-screen bg-[#0a0b0d] text-neutral-200 font-sans overflow-hidden select-none">
      
      {/* LEFT ICON NAVIGATION SIDEBAR */}
      <aside className="w-16 bg-[#121318] border-r border-neutral-800/80 flex flex-col items-center py-5 space-y-8 z-20">
        <div className="w-10 h-10 rounded-xl bg-purple-600/20 border border-purple-500/40 flex items-center justify-center text-purple-400">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <nav className="flex flex-col space-y-6 text-neutral-400">
          <Link to="/" title="Dashboard Overview" className={`p-2.5 rounded-xl transition-all ${location.pathname === '/' ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30' : 'hover:bg-neutral-800 hover:text-white'}`}>
            <LayoutGrid className="w-5 h-5" />
          </Link>
          <Link to="/inventory" title="Resource Inventory" className={`p-2.5 rounded-xl transition-all ${location.pathname === '/inventory' ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30' : 'hover:bg-neutral-800 hover:text-white'}`}>
            <Server className="w-5 h-5" />
          </Link>
        </nav>
      </aside>

      {/* MAIN CONTAINER */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        
        {/* HEADER */}
        <header className="h-16 bg-[#0a0b0d] border-b border-neutral-800/60 flex items-center justify-between px-8 z-10">
          <div className="flex items-center space-x-3 bg-[#121318] p-1.5 rounded-2xl border border-neutral-800/80">
            <Link to="/" className={`px-5 py-1.5 rounded-xl text-xs font-semibold transition-all ${location.pathname === '/' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30' : 'text-neutral-400 hover:text-white'}`}>
              Dashboard
            </Link>
            <Link to="/inventory" className={`px-5 py-1.5 rounded-xl text-xs font-semibold transition-all ${location.pathname === '/inventory' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30' : 'text-neutral-400 hover:text-white'}`}>
              All Resources
            </Link>
          </div>

          <div className="flex items-center space-x-4">
            {/* REFRESH BUTTON WITH DISABLED STATE & SCANNING TEXT */}
            <button 
              onClick={fetchData} 
              disabled={loading}
              title={loading ? "Scan in progress..." : "Re-Run Scan"} 
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-[#121318] border transition-all ${
                loading 
                  ? 'border-purple-500/40 text-purple-400 cursor-not-allowed opacity-80' 
                  : 'border-neutral-800 text-neutral-400 hover:text-white hover:border-neutral-700 cursor-pointer'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-purple-400' : ''}`} />
              <span className="text-xs font-mono font-medium">
                {loading ? 'Scanning AWS...' : 'Re-Run Scan'}
              </span>
            </button>

            <div className="flex items-center space-x-2 bg-[#121318] border border-neutral-800 px-3 py-1.5 rounded-xl">
              <div className="w-6 h-6 rounded-full bg-purple-600/30 border border-purple-500 text-purple-300 flex items-center justify-center text-[10px] font-bold">
                AM
              </div>
              <span className="text-xs font-medium text-neutral-300">Amman</span>
            </div>
          </div>
        </header>

        {/* PAGE CONTENT ROUTING */}
        <main className="flex-1 overflow-y-auto p-8 space-y-8 bg-[#0a0b0d]">
          <Routes>
            <Route path="/" element={<DashboardPage data={data} loading={loading} onSelectResource={setSelectedResource} />} />
            <Route path="/inventory" element={<InventoryPage data={data} loading={loading} onSelectResource={setSelectedResource} />} />
          </Routes>
        </main>
      </div>

      {/* RESOURCE DRILL-DOWN MODAL */}
      {selectedResource && (
        <ResourceDetailModal 
          resource={selectedResource} 
          onClose={() => setSelectedResource(null)} 
        />
      )}

    </div>
  );
}

/* =====================================================================
   1. DASHBOARD PAGE (Main View with Greeting, Metrics, Filters & CSV Export)
===================================================================== */
function DashboardPage({ data, loading, onSelectResource }) {
  const [filterService, setFilterService] = useState('ALL');
  const [filterRegion, setFilterRegion] = useState('ALL');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const uniqueRegions = ['ALL', ...new Set(data.map(i => i.region || 'global'))].sort();

  // Apply Live Multi-Filter Logic
  const filteredData = data.filter(item => {
    const s = (item.service || 'S3').toUpperCase();
    const r = (item.region || 'global').toLowerCase();
    const sev = item.highest_severity_level || item.severity_level || 'CLEAN';

    const matchService = filterService === 'ALL' || s === filterService;
    const matchRegion = filterRegion === 'ALL' || r === filterRegion.toLowerCase();
    const matchSeverity = filterSeverity === 'ALL' || sev === filterSeverity;

    return matchService && matchRegion && matchSeverity;
  });

  // Export to CSV Utility Function
  const exportToCSV = () => {
    if (filteredData.length === 0) return;

    const headers = ["Resource Identifier", "Service", "Region", "Severity", "Risk Score", "Vulnerabilities Count"];
    const rows = filteredData.map(item => {
      const name = item.resource_name || item.resource_id || "Unknown";
      const service = (item.service || "S3").toUpperCase();
      const region = item.region || "global";
      const sev = item.highest_severity_level || item.severity_level || "CLEAN";
      const score = item.final_risk_score !== undefined ? item.final_risk_score : (item.risk_score || 0);
      const vulnLen = (item.individual_problems || []).length;

      return [`"${name}"`, `"${service}"`, `"${region}"`, `"${sev}"`, score.toFixed(2), vulnLen];
    });

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `aws_security_audit_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Calculate Metrics
  const totalAssets = filteredData.length;
  const criticalCount = filteredData.filter(i => (i.highest_severity_level || i.severity_level) === 'CRITICAL').length;
  const highCount = filteredData.filter(i => (i.highest_severity_level || i.severity_level) === 'HIGH').length;
  const compliantCount = filteredData.filter(i => (i.highest_severity_level || i.severity_level) === 'ADVISORY' || (i.final_risk_score === 0)).length;
  
  const totalRiskSum = filteredData.reduce((acc, curr) => acc + (curr.final_risk_score !== undefined ? curr.final_risk_score : (curr.risk_score || 0)), 0);
  const avgRisk = totalAssets > 0 ? (totalRiskSum / totalAssets).toFixed(2) : '0.00';

  const chartData = {
    labels: ['Critical', 'High', 'Compliant', 'Other'],
    datasets: [{
      data: [criticalCount, highCount, compliantCount, Math.max(0, totalAssets - criticalCount - highCount - compliantCount)],
      backgroundColor: ['#ef4444', '#f97316', '#10b981', '#3b82f6'],
      borderWidth: 0
    }]
  };

  return (
    <div className="space-y-6">
      
      {/* INITIAL SCAN STATUS BANNER */}
      {loading && (
        <div className="bg-purple-950/40 border border-purple-800/80 rounded-2xl p-4 flex items-center justify-between text-purple-200 animate-pulse">
          <div className="flex items-center space-x-3">
            <Loader2 className="w-5 h-5 text-purple-400 animate-spin" />
            <div>
              <p className="text-xs font-bold font-mono">Parallel Security Scan in Progress...</p>
              <p className="text-[11px] text-purple-300/70 font-mono">Querying S3, EC2, RDS, IAM, Lambda, and API Gateway auditor functions across AWS regions.</p>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2.5 py-1 rounded-lg bg-purple-900/60 border border-purple-700 font-bold uppercase">
            Executing
          </span>
        </div>
      )}

      {/* ACCOUNT GREETING & CSV EXPORT BUTTON */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">Hello, Amman 👋</h1>
          <p className="text-xs text-neutral-400 mt-1 font-mono">AWS Multi-Region Exposure & Vulnerability Audit Dashboard</p>
        </div>

        <button 
          onClick={exportToCSV}
          disabled={filteredData.length === 0 || loading}
          className="flex items-center space-x-2 bg-purple-600 hover:bg-purple-500 disabled:bg-neutral-800 disabled:text-neutral-600 text-white text-xs font-semibold px-4 py-2 rounded-xl transition-all shadow-md shadow-purple-600/20 cursor-pointer disabled:cursor-not-allowed"
        >
          <Download className="w-4 h-4" />
          <span>Export CSV Audit Report</span>
        </button>
      </div>

      {/* TOP METRICS CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-5 shadow-lg">
          <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Total Monitored Assets</p>
          <p className="text-3xl font-black text-white mt-2">{loading && data.length === 0 ? '--' : totalAssets}</p>
          <p className="text-[10px] text-neutral-500 mt-1 font-mono">Active Resources</p>
        </div>

        <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-5 shadow-lg border-l-4 border-l-red-500">
          <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Most Critical Threats</p>
          <p className="text-3xl font-black text-red-500 mt-2">{loading && data.length === 0 ? '--' : criticalCount}</p>
          <p className="text-[10px] text-neutral-500 mt-1 font-mono">Requires Immediate Fix</p>
        </div>

        <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-5 shadow-lg border-l-4 border-l-emerald-500">
          <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Zero Exposure (Compliant)</p>
          <p className="text-3xl font-black text-emerald-400 mt-2">{loading && data.length === 0 ? '--' : compliantCount}</p>
          <p className="text-[10px] text-neutral-500 mt-1 font-mono">Fully Hardened</p>
        </div>

        <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-5 shadow-lg border-l-4 border-l-purple-500">
          <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">Avg Account Risk Score</p>
          <p className="text-3xl font-black text-purple-400 mt-2">{loading && data.length === 0 ? '--' : avgRisk}</p>
          <p className="text-[10px] text-neutral-500 mt-1 font-mono">Scale 0.0 - 10.0</p>
        </div>
      </div>

      {/* DASHBOARD FILTER BAR */}
      <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        
        {/* Service Filter (Includes APIGATEWAY) */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-neutral-400 uppercase">Service:</span>
          {['ALL', 'S3', 'EC2', 'RDS', 'IAM', 'LAMBDA', 'APIGATEWAY'].map(s => (
            <button
              key={s}
              onClick={() => setFilterService(s)}
              className={`px-3 py-1 rounded-xl text-xs font-mono transition-all border cursor-pointer ${
                filterService === s ? 'bg-purple-600 text-white border-purple-500 font-bold' : 'bg-[#0a0b0d] text-neutral-400 border-neutral-800 hover:text-white'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        {/* Region Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-neutral-400 uppercase">Region:</span>
          <select 
            value={filterRegion} 
            onChange={e => setFilterRegion(e.target.value)}
            className="bg-[#0a0b0d] text-xs font-mono text-neutral-200 border border-neutral-800 rounded-xl px-3 py-1.5 focus:outline-none focus:border-purple-500 cursor-pointer"
          >
            {uniqueRegions.map(r => (
              <option key={r} value={r}>{r.toUpperCase()}</option>
            ))}
          </select>
        </div>

        {/* Severity Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-neutral-400 uppercase">Severity:</span>
          <select 
            value={filterSeverity} 
            onChange={e => setFilterSeverity(e.target.value)}
            className="bg-[#0a0b0d] text-xs font-mono text-neutral-200 border border-neutral-800 rounded-xl px-3 py-1.5 focus:outline-none focus:border-purple-500 cursor-pointer"
          >
            <option value="ALL">ALL SEVERITIES</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="ADVISORY">ADVISORY</option>
          </select>
        </div>

      </div>

      {/* OVERVIEW SECTIONS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Doughnut Widget */}
        <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-6 flex flex-col items-center justify-between">
          <h3 className="text-xs font-bold text-neutral-300 tracking-wider uppercase self-start">Severity Breakdown</h3>
          <div className="w-48 h-48 relative flex items-center justify-center my-4">
            <Doughnut data={chartData} options={{ plugins: { legend: { display: false } }, cutout: '75%', responsive: true, maintainAspectRatio: false }} />
            <div className="absolute text-center">
              <p className="text-2xl font-black text-white">{loading && data.length === 0 ? '--' : totalAssets}</p>
              <p className="text-[10px] text-neutral-500 font-mono">Filtered Assets</p>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 w-full text-xs font-mono text-neutral-400 border-t border-neutral-800/60 pt-3">
            <span className="text-red-400">Critical: {criticalCount}</span>
            <span className="text-orange-400">High: {highCount}</span>
            <span className="text-emerald-400">Compliant: {compliantCount}</span>
            <span className="text-blue-400">Other: {Math.max(0, totalAssets - criticalCount - highCount - compliantCount)}</span>
          </div>
        </div>

        {/* Priority Alerts Table */}
        <div className="lg:col-span-2 bg-[#121318] border border-neutral-800/80 rounded-2xl p-6 space-y-4">
          <h3 className="text-xs font-bold text-neutral-300 tracking-wider uppercase">Filtered Vulnerabilities (Click for Details)</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-neutral-300">
              <thead className="bg-[#0a0b0d] text-neutral-500 font-mono text-[10px] uppercase border-b border-neutral-800">
                <tr>
                  <th className="p-3">Resource Identifier</th>
                  <th className="p-3">Service</th>
                  <th className="p-3">Region</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-800/60">
                {loading && data.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="p-8 text-center text-purple-400 font-mono">
                      <div className="flex items-center justify-center space-x-2">
                        <Loader2 className="w-4 h-4 animate-spin" />
                        <span>Initializing initial scan...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredData.length === 0 ? (
                  <tr><td colSpan="5" className="p-4 text-center text-neutral-500 font-mono">No resources match selected filters.</td></tr>
                ) : (
                  filteredData.map((item, idx) => {
                    const name = item.resource_name || item.resource_id;
                    const sev = item.highest_severity_level || item.severity_level || 'CLEAN';
                    const score = item.final_risk_score !== undefined ? item.final_risk_score : (item.risk_score || 0);

                    return (
                      <tr 
                        key={idx} 
                        onClick={() => onSelectResource(item)} 
                        className="hover:bg-purple-900/20 cursor-pointer transition-all"
                      >
                        <td className="p-3 font-mono font-bold text-purple-400 flex items-center justify-between">
                          <span>{name}</span>
                          <ChevronRight className="w-3.5 h-3.5 text-neutral-600" />
                        </td>
                        <td className="p-3 font-mono text-neutral-400">{(item.service || 'S3').toUpperCase()}</td>
                        <td className="p-3 font-mono text-neutral-500">{item.region || 'global'}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            sev === 'CRITICAL' ? 'bg-red-950/40 text-red-400 border-red-900' :
                            sev === 'HIGH' ? 'bg-orange-950/40 text-orange-400 border-orange-900' :
                            'bg-emerald-950/40 text-emerald-400 border-emerald-900'
                          }`}>
                            {sev}
                          </span>
                        </td>
                        <td className="p-3 font-bold text-white">{score.toFixed(2)}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>

    </div>
  );
}

/* =====================================================================
   2. INVENTORY PAGE (All Resources Grouped by Service or Region)
===================================================================== */
function InventoryPage({ data, loading, onSelectResource }) {
  const [groupBy, setGroupBy] = useState('SERVICE');
  const [filterService, setFilterService] = useState('ALL');
  const [filterRegion, setFilterRegion] = useState('ALL');

  const uniqueRegions = ['ALL', ...new Set(data.map(i => i.region || 'global'))].sort();

  const filtered = data.filter(item => {
    const s = (item.service || 'S3').toUpperCase();
    const r = (item.region || 'global').toLowerCase();
    const matchS = filterService === 'ALL' || s === filterService;
    const matchR = filterRegion === 'ALL' || r === filterRegion.toLowerCase();
    return matchS && matchR;
  });

  const groupedData = {};
  filtered.forEach(item => {
    const key = groupBy === 'SERVICE' 
      ? (item.service || 'S3').toUpperCase() 
      : (item.region || 'global').toUpperCase();

    if (!groupedData[key]) groupedData[key] = [];
    groupedData[key].push(item);
  });

  return (
    <div className="space-y-6">
      
      {/* SCANNING BANNER */}
      {loading && (
        <div className="bg-purple-950/40 border border-purple-800/80 rounded-2xl p-4 flex items-center justify-between text-purple-200 animate-pulse">
          <div className="flex items-center space-x-3">
            <Loader2 className="w-5 h-5 text-purple-400 animate-spin" />
            <div>
              <p className="text-xs font-bold font-mono">Updating Asset Inventory...</p>
              <p className="text-[11px] text-purple-300/70 font-mono">Fetching latest configurations across your AWS account.</p>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">Full Resource Inventory</h1>
          <p className="text-xs text-neutral-400 mt-0.5 font-mono">Select any asset card to view detailed risk scores and remediation guides.</p>
        </div>

        <div className="flex items-center bg-[#121318] p-1 rounded-2xl border border-neutral-800/80">
          <button 
            onClick={() => setGroupBy('SERVICE')} 
            className={`flex items-center space-x-1.5 px-4 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              groupBy === 'SERVICE' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30' : 'text-neutral-400 hover:text-white'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Group by Service</span>
          </button>
          <button 
            onClick={() => setGroupBy('REGION')} 
            className={`flex items-center space-x-1.5 px-4 py-1.5 rounded-xl text-xs font-semibold transition-all cursor-pointer ${
              groupBy === 'REGION' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30' : 'text-neutral-400 hover:text-white'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Group by Region</span>
          </button>
        </div>
      </div>

      <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        {/* Service Filter (Includes APIGATEWAY) */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-neutral-400 uppercase">Service:</span>
          {['ALL', 'S3', 'EC2', 'RDS', 'IAM', 'LAMBDA', 'APIGATEWAY'].map(s => (
            <button
              key={s}
              onClick={() => setFilterService(s)}
              className={`px-3 py-1 rounded-xl text-xs font-mono transition-all border cursor-pointer ${
                filterService === s ? 'bg-purple-600 text-white border-purple-500 font-bold' : 'bg-[#0a0b0d] text-neutral-400 border-neutral-800 hover:text-white'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-neutral-400 uppercase">Region:</span>
          <select 
            value={filterRegion} 
            onChange={e => setFilterRegion(e.target.value)}
            className="bg-[#0a0b0d] text-xs font-mono text-neutral-200 border border-neutral-800 rounded-xl px-3 py-1.5 focus:outline-none focus:border-purple-500 cursor-pointer"
          >
            {uniqueRegions.map(r => (
              <option key={r} value={r}>{r.toUpperCase()}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="space-y-8">
        {loading && data.length === 0 ? (
          <div className="p-8 bg-[#121318] rounded-2xl border border-neutral-800 text-center font-mono text-xs text-purple-400 flex items-center justify-center space-x-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Building resource inventory map...</span>
          </div>
        ) : Object.keys(groupedData).length === 0 ? (
          <div className="p-8 bg-[#121318] rounded-2xl border border-neutral-800 text-center font-mono text-xs text-neutral-500">
            No resources match current grouping or filter criteria.
          </div>
        ) : (
          Object.keys(groupedData).map(groupName => (
            <div key={groupName} className="space-y-4">
              <div className="flex items-center space-x-2 border-b border-neutral-800/80 pb-2">
                <span className="text-sm font-bold font-mono text-purple-400 uppercase tracking-wider">{groupName}</span>
                <span className="text-xs font-mono text-neutral-500">({groupedData[groupName].length} assets)</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {groupedData[groupName].map((item, idx) => {
                  const name = item.resource_name || item.resource_id;
                  const sev = item.highest_severity_level || item.severity_level || 'CLEAN';
                  const score = item.final_risk_score !== undefined ? item.final_risk_score : (item.risk_score || 0);

                  return (
                    <div 
                      key={idx} 
                      onClick={() => onSelectResource(item)}
                      className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-5 space-y-3 cursor-pointer hover:border-purple-500/50 hover:bg-[#16171f] transition-all group"
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800">
                          {(item.service || 'S3').toUpperCase()}
                        </span>
                        <span className="text-xs font-mono text-neutral-500">{item.region || 'global'}</span>
                      </div>

                      <h3 className="text-sm font-mono font-bold text-white truncate group-hover:text-purple-300 transition-colors">
                        {name}
                      </h3>

                      <div className="flex justify-between items-center border-t border-neutral-800/80 pt-3 text-xs">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          sev === 'CRITICAL' ? 'bg-red-950/40 text-red-400 border-red-900' :
                          sev === 'HIGH' ? 'bg-orange-950/40 text-orange-400 border-orange-900' :
                          'bg-emerald-950/40 text-emerald-400 border-emerald-900'
                        }`}>
                          {sev}
                        </span>
                        <div className="text-right">
                          <span className="text-[10px] text-neutral-500 block">Risk Score</span>
                          <span className="font-bold text-purple-400">{score.toFixed(2)}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))
        )}
      </div>

    </div>
  );
}

/* =====================================================================
   3. DRILL-DOWN MODAL (With Copy Remediation Command Utility)
===================================================================== */
function ResourceDetailModal({ resource, onClose }) {
  const [copiedIdx, setCopiedIdx] = useState(null);

  const name = resource.resource_name || resource.resource_id;
  const service = (resource.service || 'S3').toUpperCase();
  const region = resource.region || 'global';
  const score = resource.final_risk_score !== undefined ? resource.final_risk_score : (resource.risk_score || 0);
  const problems = resource.individual_problems || [];

  const copyToClipboard = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(index);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-[#121318] border border-neutral-800 rounded-3xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-150">
        
        {/* MODAL HEADER */}
        <div className="p-6 border-b border-neutral-800/80 flex justify-between items-start bg-[#16171f]">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800">
                {service}
              </span>
              <span className="text-xs font-mono text-neutral-400 bg-neutral-900 px-2 py-0.5 rounded border border-neutral-800">
                {region}
              </span>
            </div>
            <h2 className="text-xl font-mono font-bold text-white mt-2">{name}</h2>
          </div>
          <button onClick={onClose} className="p-2 rounded-xl bg-neutral-800 text-neutral-400 hover:text-white transition-all cursor-pointer">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* MODAL BODY */}
        <div className="p-6 overflow-y-auto space-y-6">
          
          {/* RISK SCORE OVERVIEW PANEL */}
          <div className="bg-[#0a0b0d] p-5 rounded-2xl border border-neutral-800/80 flex justify-between items-center">
            <div>
              <p className="text-xs font-mono text-neutral-400 uppercase tracking-wider">Detailed Risk Assessment</p>
              <p className="text-xs text-neutral-500 mt-1">Calculated via CVSS weightings across configuration vectors.</p>
            </div>
            <div className="text-right">
              <span className="text-3xl font-black text-purple-400">{score.toFixed(2)}</span>
              <span className="text-xs text-neutral-500 font-mono block">/ 10.0 MAX</span>
            </div>
          </div>

          {/* REMEDIATION & VULNERABILITY LOGS */}
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white tracking-wider uppercase flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-purple-400" />
              <span>Identified Flaws & Remediation Steps</span>
            </h3>

            {problems.length === 0 ? (
              <div className="p-6 bg-[#0a0b0d] rounded-2xl border border-neutral-800 text-center space-y-2">
                <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
                <p className="text-xs font-mono text-emerald-400 font-bold">ZERO VULNERABILITIES IDENTIFIED</p>
                <p className="text-[11px] text-neutral-500 font-mono">This resource fully meets established cloud security baseline standards.</p>
              </div>
            ) : (
              problems.map((prob, pIdx) => {
                const remediationText = prob.remediation_suggestion || 'Review resource security parameters in AWS Management Console.';
                const isCopied = copiedIdx === pIdx;

                return (
                  <div key={pIdx} className="bg-[#0a0b0d] border border-neutral-800 rounded-2xl p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <AlertOctagon className="w-4 h-4 text-red-500" />
                        <span className="text-xs font-bold text-white">{prob.vulnerability_description || prob.title}</span>
                      </div>
                      <span className="text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-900 uppercase">
                        {prob.severity}
                      </span>
                    </div>

                    {/* Remediation Box with One-Click Copy */}
                    <div className="bg-[#121318] p-3 rounded-xl border border-neutral-800/80 space-y-2">
                      <div className="flex justify-between items-center">
                        <p className="text-[10px] font-mono text-purple-400 font-bold uppercase">Recommended Remediation Action:</p>
                        <button 
                          onClick={() => copyToClipboard(remediationText, pIdx)}
                          className="flex items-center space-x-1 text-[10px] font-mono text-neutral-400 hover:text-white bg-neutral-800 hover:bg-neutral-700 px-2 py-1 rounded transition-all cursor-pointer"
                        >
                          {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>{isCopied ? "Copied!" : "Copy Fix"}</span>
                        </button>
                      </div>
                      <p className="text-xs font-mono text-neutral-300 select-all leading-relaxed">
                        {remediationText}
                      </p>
                    </div>
                  </div>
                );
              })
            )}
          </div>

        </div>

      </div>
    </div>
  );
}