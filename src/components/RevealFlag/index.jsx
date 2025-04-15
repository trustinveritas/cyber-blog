import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { motion, AnimatePresence } from 'framer-motion';

export default function RevealFlag({ children }) {
  const [revealed, setRevealed] = useState(false);

  return (
    <div className="my-6">
      <AnimatePresence>
        {!revealed && (
          <motion.div
            initial={{ opacity: 1 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mb-4 text-sm text-yellow-500 font-mono bg-yellow-100 dark:bg-yellow-900 px-4 py-2 rounded-lg border border-yellow-400"
          >
            ⚠️ Spoiler Warning: Click the button to reveal the flag!
          </motion.div>
        )}
      </AnimatePresence>

      <Button
        variant="outline"
        onClick={() => setRevealed(true)}
        className="mb-4"
      >
        Reveal Solution
      </Button>

      {revealed ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-gray-100 dark:bg-gray-800 p-4 rounded-md font-mono text-green-600 dark:text-green-400 border border-green-500"
        >
          {children}
        </motion.div>
      ) : (
        <div className="blur-sm select-none bg-gray-200 dark:bg-gray-700 p-4 rounded-md h-6" />
      )}
    </div>
  );
}