import React from 'react';

const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'LOW').toUpperCase();
  let badgeClass = 'badge-low';
  
  if (sev === 'CRITICAL') badgeClass = 'badge-critical';
  else if (sev === 'HIGH') badgeClass = 'badge-high';
  else if (sev === 'MEDIUM') badgeClass = 'badge-medium';
  else if (sev === 'LOW') badgeClass = 'badge-low';

  return (
    <span className={`badge ${badgeClass}`}>
      {sev}
    </span>
  );
};

export default SeverityBadge;
