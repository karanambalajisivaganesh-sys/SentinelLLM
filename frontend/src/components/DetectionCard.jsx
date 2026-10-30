import React from 'react';

/**
 * DetectionCard Component
 * Reusable summary card for key security preprocessing findings.
 */
export default function DetectionCard({ title, value, statusType, description }) {
  // Determine CSS styling variant based on statusType
  let badgeClass = 'badge-neutral';
  if (statusType === 'danger' || statusType === 'alert') {
    badgeClass = 'badge-danger';
  } else if (statusType === 'warning') {
    badgeClass = 'badge-warning';
  } else if (statusType === 'success') {
    badgeClass = 'badge-success';
  }

  return (
    <div className="detection-card">
      <div className="detection-card-top">
        <span className="card-title">{title}</span>
      </div>
      <div className="detection-card-main">
        <span className={`detection-badge ${badgeClass}`}>{value}</span>
      </div>
      {description && <p className="card-description">{description}</p>}
    </div>
  );
}
