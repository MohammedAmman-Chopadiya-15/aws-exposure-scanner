import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ShieldAlert, LayoutGrid, Server } from 'lucide-react';

export function Sidebar() {
  const location = useLocation();

  return (
    <aside className="w-16 bg-[#121318] border-r border-neutral-800/80 flex flex-col items-center py-5 space-y-8 z-20">
      <div className="w-10 h-10 rounded-xl bg-purple-600/20 border border-purple-500/40 flex items-center justify-center text-purple-400">
        <ShieldAlert className="w-5 h-5" />
      </div>
      <nav className="flex flex-col space-y-6 text-neutral-400">
        <Link 
          to="/" 
          title="Dashboard Overview" 
          className={`p-2.5 rounded-xl transition-all ${
            location.pathname === '/' 
              ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30' 
              : 'hover:bg-neutral-800 hover:text-white'
          }`}
        >
          <LayoutGrid className="w-5 h-5" />
        </Link>
        <Link 
          to="/inventory" 
          title="Resource Inventory" 
          className={`p-2.5 rounded-xl transition-all ${
            location.pathname === '/inventory' 
              ? 'bg-purple-600 text-white shadow-lg shadow-purple-600/30' 
              : 'hover:bg-neutral-800 hover:text-white'
          }`}
        >
          <Server className="w-5 h-5" />
        </Link>
      </nav>
    </aside>
  );
}