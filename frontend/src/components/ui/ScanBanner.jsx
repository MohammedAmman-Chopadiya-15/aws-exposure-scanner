import React from 'react';
import { Loader2 } from 'lucide-react';

export function ScanBanner({ title, description, showBadge = false }) {
  return (
    <div className="bg-purple-950/40 border border-purple-800/80 rounded-2xl p-4 flex items-center justify-between text-purple-200 animate-pulse">
      <div className="flex items-center space-x-3">
        <Loader2 className="w-5 h-5 text-purple-400 animate-spin" />
        <div>
          <p className="text-xs font-bold font-mono">{title}</p>
          <p className="text-[11px] text-purple-300/70 font-mono">{description}</p>
        </div>
      </div>
      {showBadge && (
        <span className="text-[10px] font-mono px-2.5 py-1 rounded-lg bg-purple-900/60 border border-purple-700 font-bold uppercase">
          Executing
        </span>
      )}
    </div>
  );
}

export default ScanBanner;