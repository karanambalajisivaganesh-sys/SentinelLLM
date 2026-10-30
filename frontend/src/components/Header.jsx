import React from 'react';

/**
 * Header Component for SentinelLLM.
 * Displays project title, subtitle, and multi-layer security architecture badge.
 */
export default function Header() {
  return (
    <header className="app-header">
      <div className="header-badge">SentinelLLM • Multi-Layer Security Architecture</div>
      <div className="header-title-wrapper">
        <h1>SENTINEL LLM</h1>
      </div>
      <p className="subtitle">
        An Adaptive Behavioral Security Framework for Large Language Models
      </p>
      <p className="description">
        Comprehensive prompt-injection defense synthesizing input preprocessing, ML pattern classification, deterministic security rules, multi-turn behavioral tracking, and explainable policy decisions.
      </p>
    </header>
  );
}
