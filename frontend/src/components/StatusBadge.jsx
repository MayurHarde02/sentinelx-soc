import React from 'react';

const StatusBadge = ({ status }) => {
  const st = status || 'Open';
  let badgeClass = 'badge-neutral';

  if (st === 'Open') badgeClass = 'badge-critical';
  else if (st === 'Investigating') badgeClass = 'badge-medium';
  else if (st === 'Resolved' || st === 'Mitigated' || st === 'Closed' || st === 'SUCCESS') badgeClass = 'badge-success';
  else if (st === 'False Positive') badgeClass = 'badge-neutral';
  else if (st === 'FAILURE' || st === 'BLOCKED') badgeClass = 'badge-high';

  return (
    <span className={`badge ${badgeClass}`}>
      {st}
    </span>
  );
};

export default StatusBadge;
