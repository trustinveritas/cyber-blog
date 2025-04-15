import React, { useEffect } from 'react';
import Layout from '@theme-original/Layout';
import mediumZoom from 'medium-zoom';
import { useLocation } from '@docusaurus/router';

export default function LayoutWrapper(props) {
  const location = useLocation();

  useEffect(() => {
    const timeout = setTimeout(() => {
      // 🔧 Patch: Lazy Loading deaktivieren
      const imgs = document.querySelectorAll('.theme-doc-markdown img');
      imgs.forEach((img) => {
        img.setAttribute('loading', 'eager'); // ← wichtig!
      });

      // 🔍 Medium Zoom aktivieren
      const zoom = mediumZoom('.theme-doc-markdown img', {
        margin: 24,
        background: 'rgba(0, 0, 0, 0.85)',
      });

      return () => zoom.detach(); // Clean-up
    }, 300); // kleiner Delay, um sicherzustellen, dass Bilder da sind

    return () => clearTimeout(timeout);
  }, [location.pathname]); // bei Seitenwechsel neu ausführen

  return <Layout {...props} />;
}