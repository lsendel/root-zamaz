/**
 * Loading Spinner Component
 * 
 * Consistent loading indicator across the application with
 * multiple size variants and accessibility support.
 */

import React from 'react';
import './LoadingSpinner.css';

export interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  color?: 'primary' | 'secondary' | 'white' | 'current';
  text?: string;
  className?: string;
  overlay?: boolean;
  'data-testid'?: string;
}

const sizeClasses = {
  sm: 'loading-spinner--sm',
  md: 'loading-spinner--md', 
  lg: 'loading-spinner--lg',
  xl: 'loading-spinner--xl',
} as const;

const colorClasses = {
  primary: 'loading-spinner--primary',
  secondary: 'loading-spinner--secondary',
  white: 'loading-spinner--white',
  current: 'loading-spinner--current',
} as const;

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  color = 'primary',
  text,
  className = '',
  overlay = false,
  'data-testid': testId = 'loading-spinner',
}) => {
  const spinnerClasses = [
    'loading-spinner',
    sizeClasses[size],
    colorClasses[color],
    className,
  ].filter(Boolean).join(' ');

  const spinner = (
    <div className={spinnerClasses} data-testid={testId}>
      <svg
        className="loading-spinner__icon"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        role="progressbar"
        aria-label={text || 'Loading'}
        aria-describedby={text ? `${testId}-text` : undefined}
      >
        <circle
          className="loading-spinner__circle"
          cx="12"
          cy="12"
          r="10"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeDasharray="31.416"
          strokeDashoffset="31.416"
        />
      </svg>
      {text && (
        <span 
          id={`${testId}-text`}
          className="loading-spinner__text"
          aria-live="polite"
        >
          {text}
        </span>
      )}
    </div>
  );

  if (overlay) {
    return (
      <div 
        className="loading-spinner-overlay" 
        data-testid={`${testId}-overlay`}
        role="progressbar"
        aria-label="Loading overlay"
      >
        {spinner}
      </div>
    );
  }

  return spinner;
};

// Specialized loading components
export const FullPageLoader: React.FC<{ text?: string }> = ({ text = 'Loading application...' }) => (
  <div className="loading-spinner-fullpage" data-testid="fullpage-loader">
    <LoadingSpinner size="lg" text={text} />
  </div>
);

export const InlineLoader: React.FC<{ text?: string }> = ({ text }) => (
  <LoadingSpinner size="sm" color="current" text={text} data-testid="inline-loader" />
);

export const ButtonLoader: React.FC = () => (
  <LoadingSpinner size="sm" color="white" data-testid="button-loader" />
);