import React, { useState, useMemo } from 'react';
import { Layers, Globe, Loader2 } from 'lucide-react';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { ScanBanner } from '../components/ui/ScanBanner';
import { normalizeResource, SERVICES } from '../utils/auditUtils';

export function InventoryPage({ data, loading, onSelectResource }) {
  const [groupBy, setGroupBy] = useState('SERVICE');
  const [filterService, setFilterService] = useState('ALL');
  const [filterRegion, setFilterRegion] = useState('ALL');

  const uniqueRegions = useMemo(() => {
    return ['ALL', ...new Set(data.map(i => i.region || 'global'))].sort();
  }, [data]);

  const filtered = useMemo(() => {
    return data.filter(item => {
      const norm = normalizeResource(item);
      const matchS = filterService === 'ALL' || norm.service === filterService;
      const matchR = filterRegion === 'ALL' || norm.region.toLowerCase() === filterRegion.toLowerCase();
      return matchS && matchR;
    });
  }, [data, filterService, filterRegion]);

  const groupedData = useMemo(() => {
    const groups = {};
    filtered.forEach(item => {
      const norm = normalizeResource(item);
      const key = groupBy === 'SERVICE' ? norm.service : norm.region.toUpperCase();
      if (!groups[key]) groups[key] = [];
      groups[key].push(item);
    });
    return groups;
  }, [filtered, groupBy]);

  return (
    <div className="space-y-6">
      {loading && (
        <ScanBanner 
          title="Updating Asset Inventory..." 
          description="Fetching latest configurations across your AWS account." 
        />
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
                  const norm = normalizeResource(item);

                  return (
                    <div 
                      key={idx} 
                      onClick={() => onSelectResource(item)}
                      className="bg-[#121318] border border-neutral-800/80 rounded-2xl p-5 space-y-3 cursor-pointer hover:border-purple-500/50 hover:bg-[#16171f] transition-all group"
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800">
                          {norm.service}
                        </span>
                        <span className="text-xs font-mono text-neutral-500">{norm.region}</span>
                      </div>

                      <h3 className="text-sm font-mono font-bold text-white truncate group-hover:text-purple-300 transition-colors">
                        {norm.name}
                      </h3>

                      <div className="flex justify-between items-center border-t border-neutral-800/80 pt-3 text-xs">
                        <SeverityBadge severity={norm.severity} />
                        <div className="text-right">
                          <span className="text-[10px] text-neutral-500 block">Risk Score</span>
                          <span className="font-bold text-purple-400">{norm.score.toFixed(2)}</span>
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