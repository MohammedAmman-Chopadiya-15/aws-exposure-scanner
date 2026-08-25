import React, { useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import { useCloudAudit } from './hooks/useCloudAudit';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { DashboardPage } from './pages/DashboardPage';
import { InventoryPage } from './pages/InventoryPage';
import { ResourceDetailModal } from './components/modals/ResourceDetailModal';

export default function App() {
  const { data, loading, refetch } = useCloudAudit(120000);
  const [selectedResource, setSelectedResource] = useState(null);

  return (
    <div className="flex h-screen bg-[#0a0b0d] text-neutral-200 font-sans overflow-hidden select-none">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header loading={loading} onRefresh={refetch} />
        <main className="flex-1 overflow-y-auto p-8 space-y-8 bg-[#0a0b0d]">
          <Routes>
            <Route 
              path="/" 
              element={<DashboardPage data={data} loading={loading} onSelectResource={setSelectedResource} />} 
            />
            <Route 
              path="/inventory" 
              element={<InventoryPage data={data} loading={loading} onSelectResource={setSelectedResource} />} 
            />
          </Routes>
        </main>
      </div>

      {selectedResource && (
        <ResourceDetailModal 
          resource={selectedResource} 
          onClose={() => setSelectedResource(null)} 
        />
      )}
    </div>
  );
}