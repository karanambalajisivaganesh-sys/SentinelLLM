import React, { useState } from 'react';
import DetectionCard from './DetectionCard';

/**
 * AnalysisResult Component
 * Displays the complete multi-layer security analysis output returned by the FastAPI backend:
 * - Policy Decision Banner (ALLOW, FLAG_FOR_REVIEW, BLOCK)
 * - Composite Risk Score Gauge (0-100) & Risk Level
 * - Explainable Reasons, Reason Codes, and Signals
 * - ML Classification and Multi-Turn Behavioral Analysis
 * - Preprocessing & Text Transformations
 * - Collapsible Raw JSON Response Inspector
 */
export default function AnalysisResult({ result }) {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  if (!result) return null;

  // Validation Error State
  if (!result.success) {
    return (
      <div className="result-container error-card">
        <div className="error-header">
          <h3>Input Validation Error</h3>
        </div>
        <p className="error-message">{result.error || 'Invalid prompt input.'}</p>
        <p className="error-summary">{result.processing_summary}</p>
      </div>
    );
  }

  const risk = result.risk_assessment;
  const ml = result.ml_result;
  const behavior = result.behavioral_analysis;

  // Consistency Check
  const topDecision = result.policy_decision;
  const nestedDecision = risk?.policy_decision;
  const hasConsistencyError = (
    topDecision && nestedDecision && topDecision !== nestedDecision
  );

  const decision = topDecision || nestedDecision || 'UNKNOWN';

  // Format Input Type
  const formatInputType = (type) => {
    switch (type) {
      case 'plain_text':
        return 'Plain Text';
      case 'base64_encoded':
        return 'Base64 Encoded';
      case 'hexadecimal_encoded':
        return 'Hexadecimal Encoded';
      case 'unicode_obfuscated':
        return 'Unicode Obfuscated';
      case 'url_encoded':
        return 'URL Encoded';
      case 'mixed_or_obfuscated':
        return 'Mixed / Obfuscated';
      default:
        return type || 'Unknown';
    }
  };

  // Decision styling helper
  const getDecisionStyle = (dec) => {
    switch (dec) {
      case 'BLOCK':
        return {
          bannerClass: 'decision-banner-block',
          badgeClass: 'badge-decision-block',
          title: 'DECISION: BLOCK',
          explanation: 'The prompt was blocked by the SentinelLLM security policy to protect downstream models.',
        };
      case 'FLAG_FOR_REVIEW':
        return {
          bannerClass: 'decision-banner-review',
          badgeClass: 'badge-decision-review',
          title: 'DECISION: FLAG FOR REVIEW',
          explanation: 'The prompt requires manual review or secondary inspection due to moderate risk or conflicting signals.',
        };
      case 'ALLOW':
        return {
          bannerClass: 'decision-banner-allow',
          badgeClass: 'badge-decision-allow',
          title: 'DECISION: ALLOW',
          explanation: 'The prompt was permitted according to the configured security policy. (Note: ALLOW does not guarantee complete absence of risk).',
        };
      default:
        return {
          bannerClass: 'decision-banner-review',
          badgeClass: 'badge-decision-review',
          title: `DECISION: ${dec || 'UNKNOWN'}`,
          explanation: 'The decision could not be definitively determined or an unhandled policy state was encountered.',
        };
    }
  };

  const decisionInfo = getDecisionStyle(decision);
  const score = risk ? Number(risk.risk_score || 0) : 0;
  const clampedScore = Math.min(Math.max(score, 0), 100);

  return (
    <div className="result-container">
      {/* Consistency Warning Banner if top-level and nested decisions mismatch */}
      {hasConsistencyError && (
        <div className="consistency-error-banner">
          <h4>Data Consistency Warning</h4>
          <p>
            Mismatch detected between top-level policy decision (<code>{topDecision}</code>)
            and risk assessment policy decision (<code>{nestedDecision}</code>). Please inspect the raw API payload.
          </p>
        </div>
      )}

      {/* 1. Final Policy Decision Banner */}
      <div className={`policy-decision-banner ${decisionInfo.bannerClass}`}>
        <div className="decision-banner-top">
          <span className={`decision-badge ${decisionInfo.badgeClass}`}>
            {decisionInfo.title}
          </span>
          {risk && (
            <div className="decision-meta">
              <span className="risk-level-tag">Risk Level: {(risk.risk_level || 'unknown').toUpperCase()}</span>
              <span className="policy-version-tag">Policy {risk.policy_version || '1.0.0'}</span>
            </div>
          )}
        </div>
        <p className="decision-explanation-text">{decisionInfo.explanation}</p>
      </div>

      {/* 2. Composite Risk Score Visualization */}
      {risk && (
        <div className="risk-score-card">
          <div className="score-header">
            <h4>Composite Policy Risk Score</h4>
            <span className="score-numerical-display">{score.toFixed(1)} / 100</span>
          </div>

          <div className="risk-gauge-container">
            <div className="risk-gauge-track">
              <div
                className={`risk-gauge-fill fill-${risk.risk_level || 'low'}`}
                style={{ width: `${clampedScore}%` }}
              />
            </div>
            <div className="risk-gauge-markers">
              <span className="gauge-marker marker-0">0 (Safe)</span>
              <span className="gauge-marker marker-review">| 35 (Review)</span>
              <span className="gauge-marker marker-block">| 70 (Block)</span>
              <span className="gauge-marker marker-100">100 (Critical)</span>
            </div>
          </div>
          <p className="score-disclaimer">
            * Policy risk score represents a composite threat index, not a statistical Bayesian probability.
          </p>
        </div>
      )}

      {/* 3. Explainable Detection Results: Reasons, Reason Codes, Signals */}
      {risk && (
        <div className="explainable-reasons-card">
          <h4>Policy Evaluation & Reasons</h4>

          {risk.reasons && risk.reasons.length > 0 && (
            <div className="reasons-block">
              <span className="reasons-label">Decision Justifications:</span>
              <ul className="reasons-list">
                {risk.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}

          {risk.reason_codes && risk.reason_codes.length > 0 && (
            <div className="reason-codes-block">
              <span className="reasons-label">Machine-Readable Reason Codes:</span>
              <div className="reason-codes-pills">
                {risk.reason_codes.map((code, i) => (
                  <span key={i} className="code-pill">{code}</span>
                ))}
              </div>
            </div>
          )}

          {risk.signals && risk.signals.length > 0 && (
            <div className="contributing-signals-block">
              <span className="reasons-label">Contributing Signals:</span>
              <ul className="signals-list">
                {risk.signals.map((sig, i) => (
                  <li key={i}>{sig}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* 4. Multi-Layer Detection Status Cards */}
      <div className="section-title-wrapper">
        <h3>Security Layer Findings</h3>
      </div>
      <div className="detection-cards-grid">
        {/* ML Model Card */}
        {ml && (
          <DetectionCard
            title="ML Pattern Classifier"
            value={ml.predicted_class ? ml.predicted_class.toUpperCase() : 'N/A'}
            statusType={ml.predicted_class === 'benign' ? 'success' : 'danger'}
            description={`Decision Score: ${ml.attack_score ?? 'N/A'} (threshold: ${ml.threshold_used}) • ${ml.model_name}`}
          />
        )}

        {/* Behavioral Analysis Card */}
        {behavior && (
          <DetectionCard
            title="Behavioral Session Risk"
            value={`${behavior.session_risk_score} / 100`}
            statusType={behavior.session_risk_score === 0 ? 'success' : behavior.session_risk_score >= 40 ? 'danger' : 'warning'}
            description={`Recent attacks (5m): ${behavior.recent_suspicious_count} • Repeated: ${behavior.repeated_attack_detected ? 'Yes' : 'No'} • Escalation: ${behavior.escalation_detected ? 'Yes' : 'No'}`}
          />
        )}

        {/* Input Type Representation Card */}
        <DetectionCard
          title="Input Representation"
          value={formatInputType(result.input_type)}
          statusType={result.input_type === 'plain_text' ? 'success' : 'warning'}
          description="Syntactic representation category"
        />

        {/* Encoding Status Card */}
        <DetectionCard
          title="Encoding Detected"
          value={result.encoding_detected && result.encoding_detected.length > 0 ? result.encoding_detected.join(', ') : 'None'}
          statusType={result.encoding_detected && result.encoding_detected.length > 0 ? 'warning' : 'success'}
          description={result.encoding_detected && result.encoding_detected.length > 0 ? 'Encoded payload decoded safely' : 'Standard character set'}
        />

        {/* Zero-Width Injection Card */}
        <DetectionCard
          title="Zero-Width Unicode"
          value={result.zero_width_detected ? 'Detected' : 'Clean'}
          statusType={result.zero_width_detected ? 'danger' : 'success'}
          description={result.zero_width_detected ? 'Invisible characters detected' : 'No zero-width codepoints'}
        />
      </div>

      {behavior && (
        <div className="session-context-bar">
          <span className="session-bar-label">Active Session:</span>
          <code>{behavior.session_id}</code>
          <span className="session-bar-note">* Session state is maintained in-memory (resets on server restart).</span>
        </div>
      )}

      {/* 5. Text Transformations Section */}
      <div className="transformations-section">
        <h3>Text Representations & Normalization</h3>

        <div className="text-box-group">
          <div className="text-box">
            <div className="text-box-header">
              <span className="box-title">1. Original Input</span>
              <span className="char-count">{(result.original_text || '').length} chars</span>
            </div>
            <pre className="text-box-content mono-font">{result.original_text || ''}</pre>
          </div>

          <div className="text-box">
            <div className="text-box-header">
              <span className="box-title">2. Normalized Input</span>
              <span className="char-count">{(result.normalized_text || '').length} chars</span>
            </div>
            <pre className="text-box-content mono-font">{result.normalized_text || ''}</pre>
          </div>
        </div>

        {/* Decoded Content Section if Encodings Decoded */}
        {result.decoded_content && (
          <div className="decoded-content-box highlight-box">
            <div className="box-header-accent">
              <span className="box-title">Decoded Payload Content</span>
              <span className="badge-tag">Decoded Safely</span>
            </div>
            <pre className="text-box-content mono-font">{result.decoded_content}</pre>
          </div>
        )}

        {/* Cleaned Content Section if Zero-width Stripped */}
        {result.cleaned_content && result.cleaned_content !== result.normalized_text && (
          <div className="cleaned-content-box highlight-box">
            <div className="box-header-accent">
              <span className="box-title">Cleaned Content (Zero-Width Stripped)</span>
              <span className="badge-tag">Sanitized</span>
            </div>
            <pre className="text-box-content mono-font">{result.cleaned_content}</pre>
          </div>
        )}
      </div>

      {/* 6. Collapsible Technical Processing Details JSON View */}
      <div className="technical-details-card">
        <button
          type="button"
          className="technical-details-toggle"
          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
        >
          <span>{showTechnicalDetails ? '[-] Hide' : '[+] Show'} Technical Processing Details (Structured JSON API Response)</span>
          <span className="json-badge">FastAPI Response</span>
        </button>

        {showTechnicalDetails && (
          <div className="json-viewer-container">
            <p className="json-help-text">
              Real-time structured payload returned from <code>POST /analyze</code> to FastAPI:
            </p>
            <pre className="json-code-block mono-font">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
