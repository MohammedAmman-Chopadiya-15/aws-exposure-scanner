import React from 'react';

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-950/40 text-red-400 border-red-900',
  HIGH: 'bg-orange-950/40 text-orange-400 border-orange-900',
  MEDIUM: 'bg-yellow-950/40 text-yellow-400 border-yellow-900',
  LOW: 'bg-blue-950/40 text-blue-400 border-blue-900',
  ADVISORY: 'bg-emerald-950/40 text-emerald-400 border-emerald-900',
  CLEAN: 'bg-emerald-950/40 text-emerald-400 border-emerald-900'
};

export function SeverityBadge({ severity }) {
  const sev = (severity || 'CLEAN').toUpperCase();
  const badgeClass = SEVERITY_STYLES[sev] || SEVERITY_STYLES.CLEAN;

  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badgeClass}`}>
      {sev}
    </span>
  );
}

// Added default export as well to prevent any import mismatch
export default SeverityBadge;