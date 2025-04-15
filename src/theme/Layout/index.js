import React, { useEffect } from 'react';
import Layout from '@theme-original/Layout';
import mediumZoom from 'medium-zoom';

export default function LayoutWrapper(props) {
  useEffect(() => {
    mediumZoom('.theme-doc-markdown img');
  }, []);

  return <Layout {...props} />;
}