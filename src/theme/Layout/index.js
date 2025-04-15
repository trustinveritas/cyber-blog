import React, { useEffect } from 'react';
import Layout from '@theme-original/Layout';
import mediumZoom from 'medium-zoom';

export default function LayoutWrapper(props) {
  useEffect(() => {
    mediumZoom('article img'); // oder einfach 'img' für alles
  }, []);

  return <Layout {...props} />;
}