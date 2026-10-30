import React from 'react';

/**
 * PipelineStatus Component
 * Illustrative visual indicator reflecting the sequential processing stages
 * supported by the SentinelLLM defense architecture.
 */
export default function PipelineStatus({ statusState }) {
  const stages = [
    { id: 1, name: 'Input Validation', key: 'validation' },
    { id: 2, name: 'Preprocessing & Encodings', key: 'preprocessing' },
    { id: 3, name: 'ML Pattern Classification', key: 'ml' },
    { id: 4, name: 'Explicit Security Rules', key: 'rules' },
    { id: 5, name: 'Behavioral Session Analysis', key: 'behavior' },
    { id: 6, name: 'Composite Risk Scoring', key: 'risk' },
    { id: 7, name: 'Final Policy Decision', key: 'policy' },
  ];

  const getStatusDisplay = (stageKey) => {
    const state = statusState[stageKey] || 'pending';
    switch (state) {
      case 'completed':
        return { icon: '[OK]', text: 'Completed', className: 'status-completed' };
      case 'processing':
        return { icon: '[..]', text: 'Processing', className: 'status-processing' };
      case 'error':
        return { icon: '[X]', text: 'Failed', className: 'status-error' };
      case 'pending':
      default:
        return { icon: '[--]', text: 'Pending', className: 'status-pending' };
    }
  };

  return (
    <div className="pipeline-card">
      <div className="card-header">
        <h3>Security Pipeline Flow</h3>
        <span className="pipeline-count">7 Stages</span>
      </div>

      <div className="pipeline-stages-grid">
        {stages.map((stage) => {
          const status = getStatusDisplay(stage.key);
          return (
            <div key={stage.id} className={`pipeline-stage-item ${status.className}`}>
              <div className="stage-number">{stage.id}</div>
              <div className="stage-info">
                <span className="stage-name">{stage.name}</span>
                <span className="stage-status-label">
                  <span className="status-icon">{status.icon}</span> {status.text}
                </span>
              </div>
            </div>
          );
        })}
      </div>
      <p className="pipeline-caption">
        * Illustrative processing flow reflecting the modular security defense layers evaluated by the backend.
      </p>
    </div>
  );
}
