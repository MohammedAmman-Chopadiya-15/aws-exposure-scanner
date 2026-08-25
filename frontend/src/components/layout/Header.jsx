import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { RefreshCw } from 'lucide-react';

export function Header({ loading, onRefresh }) {
  const location = useLocation();

  return (
    <header className="h-16 bg-[#0a0b0d] border-b border-neutral-800/60 flex items-center justify-between px-8 z-10">
      <div className="flex items-center space-x-3 bg-[#121318] p-1.5 rounded-2xl border border-neutral-800/80">
        <Link 
          to="/" 
          className={`px-5 py-1.5 rounded-xl text-xs font-semibold transition-all ${
            location.pathname === '/' 
              ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30' 
              : 'text-neutral-400 hover:text-white'
          }`}
        >
          Dashboard
        </Link>
        <Link 
          to="/inventory" 
          className={`px-5 py-1.5 rounded-xl text-xs font-semibold transition-all ${
            location.pathname === '/inventory' 
              ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30' 
              : 'text-neutral-400 hover:text-white'
          }`}
        >
          All Resources
        </Link>
      </div>

      <div className="flex items-center space-x-4">
        <button 
          onClick={onRefresh} 
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
  );
}