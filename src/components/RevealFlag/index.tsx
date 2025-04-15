import React, { useState, ReactNode } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ClipboardCopy, Check } from 'lucide-react';

type RevealFlagProps = {
  readonly children: ReactNode;
};

export default function RevealFlag({ children }: RevealFlagProps) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(String(children));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Clipboard copy failed:', err);
    }
  };

  return (
    <div className="my-6">
      <AnimatePresence>
        {!revealed && (
          <motion.div
            initial={{ opacity: 1 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mb-4 text-sm text-yellow-500 font-mono bg-yellow-100 dark:bg-yellow-900 px-4 py-2 rounded-lg border border-yellow-400 dark:border-yellow-600"
          >
            ⚠️ Spoiler Warning: Click the button to reveal the flag!
          </motion.div>
        )}
      </AnimatePresence>

      <motion.button
        whileTap={{ scale: 0.95 }}
        whileHover={{ scale: 1.05 }}
        onClick={() => setRevealed(true)}
        className="button button--secondary button--lg"
      >
        🔐 Reveal Solution
      </motion.button>

      {revealed ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="relative bg-gray-100 dark:bg-gray-800 p-4 rounded-md font-mono text-green-600 dark:text-green-400 border border-green-500 dark:border-green-400"
        >
          <code>{children}</code>
          <button
            onClick={copyToClipboard}
            className="absolute top-2 right-2 flex items-center gap-1 text-xs bg-green-200 dark:bg-green-600 hover:bg-green-300 dark:hover:bg-green-500 text-green-800 dark:text-white px-2 py-1 rounded"
            title={copied ? 'Copied!' : 'Copy to clipboard'}
          >
            {copied ? (
              <>
                <Check className="w-4 h-4" />
                Copied!
              </>
            ) : (
              <>
                <ClipboardCopy className="w-4 h-4" />
                Copy
              </>
            )}
          </button>
        </motion.div>
      ) : (
        <div className="blur-sm select-none bg-gray-200 dark:bg-gray-700 p-4 rounded-md h-6" />
      )}
    </div>
  );
}