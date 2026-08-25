import React from 'react';

export function MetricCard({ title, value, subtitle, borderAccent = '', textAccent = 'text-white' }) {
  return (
    <div className={`bg-[#121318] border border-neutral-800/80 rounded-2xl p-5 shadow-lg ${borderAccent}`}>
      <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider">{title}</p>
      <p className={`text-3xl font-black mt-2 ${textAccent}`}>{value}</p>
      <p className="text-[10px] text-neutral-500 mt-1 font-mono">{subtitle}</p>
    </div>
  );
}

export default MetricCard;