// File: src/components/AchievementCard/index.tsx

import React from 'react';

interface AchievementCardProps {
  title: string;
  description?: string;
  iframeSrc: string;
  height?: string;
}

const AchievementCard: React.FC<AchievementCardProps> = ({
  title,
  description,
  iframeSrc,
  height = '500px',
}) => {
  return (
    <div className="rounded-2xl shadow-md p-4 mb-6 border border-gray-200 bg-white dark:bg-gray-900">
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      {description && <p className="text-sm mb-4">{description}</p>}
      <div className="overflow-hidden rounded-lg border border-gray-300">
        <iframe
          src={iframeSrc}
          width="100%"
          height={height}
          style={{ border: 'none' }}
          title={title}
          loading="lazy"
        />
      </div>
    </div>
  );
};

export default AchievementCard;