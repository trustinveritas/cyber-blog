import type { ReactNode } from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Packets, Ports, and Pranks',
    description: (
      <>
        A Fun-filled Log of my Pentesting Pursuits!
      </>
    ),
  },
];

function Feature({ title, description }: FeatureItem) {
  return (
    <div 
      className="text--center"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
      }}
    >
      <Heading as="h1" style={{ fontSize: '3rem', fontWeight: 'bold', marginBottom: '0.5rem' }}>
        {title}
      </Heading>
      <h2 style={{ fontStyle: 'italic', fontSize: '2rem', marginBottom: '1.5rem' }}>
        {description}
      </h2>
      
      {/* Centered Image with Correct Path */}
      <div 
        className="text--center"
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          width: '100%',
          marginTop: '20px',
        }}
      >
        <img 
          src="/img/HackerTerminal.png" 
          alt="Hacker ASCII Art"
          style={{
            maxWidth: '100%',
            height: 'auto',
            borderRadius: '10px',
            display: 'block',
            margin: '0 auto',
          }}
        />
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row" style={{ display: 'flex', justifyContent: 'center' }}>
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}