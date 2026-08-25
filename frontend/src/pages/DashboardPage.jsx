import React, { useState, useMemo } from 'react';
import { Download, ChevronRight, Loader2 } from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import { MetricCard } from '../components/ui/MetricCard';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { ScanBanner } from '../components/ui/ScanBanner';
import { normalizeResource, exportToCSV, SERVICES, SEVERITIES } from '../utils/auditUtils';

ChartJS.register(ArcElement, Tooltip, Legend);

export function DashboardPage({ data, loading, onSelectResource }) {
  const [filterService, setFilterService] = useState('ALL');
  const [filterRegion, setFilterRegion] = useState('ALL');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const uniqueRegions = useMemo(() => {
    return ['ALL', ...new Set(data.map(i => i.region || 'global'))].sort();
  }, [data]);

  const filteredData = useMemo(() => {
    return data.filter(item => {
      const norm = normalizeResource(item);
      const matchService = filterService === 'ALL' || norm.service === filterService;
      const matchRegion = filterRegion === 'ALL' || norm.region.toLowerCase() === filterRegion.toLowerCase();
      const matchSeverity = filterSeverity === 'ALL' || norm.severity === filterSeverity;
      return matchService && matchRegion && matchSeverity;
    });
  }, [data, filterService, filterRegion, filterSeverity]);

  const metrics = useMemo(() => {
    const totalAssets = filteredData.length;
    const criticalCount = filteredData.filter(i => (i.highest_severity_level || i.severity_level) === 'CRITICAL').length;
    const highCount = filteredData.filter(i => (i.highest_severity_level || i.severity_level) === 'HIGH').length;
    const compliantCount = filteredData.filter(i => (i.highest_severity_level || i.severity_level) === 'ADVISORY' || ((i.final_risk_score ?? i.risk_score) === 0)).length;
    const totalRiskSum = filteredData.reduce((acc, curr) => acc + (curr.final_risk_score !== undefined ? curr.final_risk_score : (curr.risk_score || 0)), 0);
    const avgRisk = totalAssets > 0 ? (totalRiskSum / totalAssets).toFixed(2) : '0.00';
    const otherCount = Math.max(0, totalAssets - criticalCount - highCount - compliantCount);

    return { totalAssets, criticalCount, highCount, compliantCount, avgRisk, otherCount };
  }, [filteredData]);

  const chartData = {
    labels: ['Critical', 'High', 'Compliant', 'Other'],
    datasets: [{
      data: [metrics.criticalCount, metrics.highCount, metrics.compliantCount, metrics.otherCount],
      backgroundColor: ['#ef4444', '#f97316', '#10b981', '#3b82f6'],
      borderWidth: 0
    }]
  };

  return (
    <div className="space-y-6">
      {loading && (
        <ScanBanner 
          title="Parallel Security Scan in Progress..." 
          description="Querying S3, EC2, RDS, IAM, Lambda, API Gateway, and CloudFront auditor functions across AWS regions."
          showBadge={true}
        />
      )}

      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">Hello, Amman 👋</h1>
          <p className="text-xs text-neutral-400 mt-1 font-mono">AWS Multi-Region Exposure & Vulnerability Audit Dashboard</p>
        </div>

        <button 
          onClick={() => exportToCSV(filteredData)}
          disabled={filteredData.length === 0 || loading}
          className="flex items-center space-x-2 bg-purple-600 hover:bg-purple-500 disabled:bg-neutral-800 disabled:text-neutral-600 text-white text-xs font-semibold px-4 py-2 rounded-xl transition-all shadow-md shadow-purple-600/20 cursor-pointer disabled:cursor-not-allowed"
        >
          <Download className="w-4 h-4" />
          <span>Export CSV Audit Report</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard 
          title="Total Monitored Assets" 
          value={loading && data.length === 0 ? '--' : metrics.totalAssets} 
          subtitle="Active Resources" 
        />
        <MetricCard 
          title="Most Critical Threats" 
          value={loading && data.length === 0 ? '--' : metrics.criticalCount} 
          subtitle="Requires Immediate Fix" 
          borderAccent="border-l-4 border-l-red-500" 
          textAccent="text-red-500" 
        />
        <MetricCard 
          title="Zero Exposure (Compliant)" 
          value={loading && data.length === 0 ? '--' : metrics.compliantCount} 
          subtitle="Fully Hardened" 
          borderAccent="border-l-4 border-l-emerald-500" 
          textAccent="text-emerald-400" 
        />
        <MetricCard 
          title="Avg Account Risk Score" 
          value={loading && data.length === 0 ? '--' : metrics.avgRisk} 
          subtitle="Scale 0.0 - 10.0" 
          borderAccent="border-l-4 border-l-purple-500" 
          textAccent="text-purple-400" 
        />
      </div>

      {/* FILTER CONTROLS */}
      <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-neutral-400 uppercase">Service:</span>
          {SERVICES.map(s => (
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

        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-neutral-400 uppercase">Severity:</span>
          <select 
            value={filterSeverity} 
            onChange={e => setFilterSeverity(e.target.value)}
            className="bg-[#0a0b0d] text-xs font-mono text-neutral-200 border border-neutral-800 rounded-xl px-3 py-1.5 focus:outline-none focus:border-purple-500 cursor-pointer"
          >
            {SEVERITIES.map(sev => (
              <option key={sev} value={sev}>{sev === 'ALL' ? 'ALL SEVERITIES' : sev}</option>
            ))}
          </select>
        </div>
      </div>

      {/* OVERVIEW DATA */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-6 flex flex-col items-center justify-between">
          <h3 className="text-xs font-bold text-neutral-300 tracking-wider uppercase self-start">Severity Breakdown</h3>
          <div className="w-48 h-48 relative flex items-center justify-center my-4">
            <Doughnut data={chartData} options={{ plugins: { legend: { display: false } }, cutout: '75%', responsive: true, maintainAspectRatio: false }} />
            <div className="absolute text-center">
              <p className="text-2xl font-black text-white">{loading && data.length === 0 ? '--' : metrics.totalAssets}</p>
              <p className="text-[10px] text-neutral-500 font-mono">Filtered Assets</p>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 w-full text-xs font-mono text-neutral-400 border-t border-neutral-800/60 pt-3">
            <span className="text-red-400">Critical: {metrics.criticalCount}</span>
            <span className="text-orange-400">High: {metrics.highCount}</span>
            <span className="text-emerald-400">Compliant: {metrics.compliantCount}</span>
            <span className="text-blue-400">Other: {metrics.otherCount}</span>
          </div>
        </div>

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
                    const norm = normalizeResource(item);
                    return (
                      <tr 
                        key={idx} 
                        onClick={() => onSelectResource(item)} 
                        className="hover:bg-purple-900/20 cursor-pointer transition-all"
                      >
                        <td className="p-3 font-mono font-bold text-purple-400 flex items-center justify-between">
                          <span>{norm.name}</span>
                          <ChevronRight className="w-3.5 h-3.5 text-neutral-600" />
                        </td>
                        <td className="p-3 font-mono text-neutral-400">{norm.service}</td>
                        <td className="p-3 font-mono text-neutral-500">{norm.region}</td>
                        <td className="p-3">
                          <SeverityBadge severity={norm.severity} />
                        </td>
                        <td className="p-3 font-bold text-white">{norm.score.toFixed(2)}</td>
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