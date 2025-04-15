import React, { useEffect } from 'react';
import Layout from '@theme-original/Layout';
import mediumZoom from 'medium-zoom';
import { useLocation } from '@docusaurus/router';

export default function LayoutWrapper(props) {
  const location = useLocation();

  useEffect(() => {
    const zoom = mediumZoom('.theme-doc-markdown img', {
      margin: 24,
      background: 'rgba(0, 0, 0, 0.85)',
    });
    return () => zoom.detach();
  }, [location.pathname]); // neu initialisieren bei Seitenwechsel

  return <Layout {...props} />;
}