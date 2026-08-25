import React, { useState } from 'react';
import { X, Terminal, ShieldCheck, AlertOctagon, Copy, Check } from 'lucide-react';
import { normalizeResource } from '../../utils/auditUtils';

export function ResourceDetailModal({ resource, onClose }) {
  const [copiedIdx, setCopiedIdx] = useState(null);

  if (!resource) return null;
  const { name, service, region, score, problems } = normalizeResource(resource);

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