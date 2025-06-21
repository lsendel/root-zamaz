import React from "react";
import { ErrorBoundary as ReactErrorBoundary } from "react-error-boundary";
import { useUIStore } from "../stores/ui-store";

interface ErrorFallbackProps {
  error: Error;
  resetErrorBoundary: () => void;
}

const ErrorFallback: React.FC<ErrorFallbackProps> = ({
  error,
  resetErrorBoundary,
}) => {
  return (
    <div className="error-boundary">
      <div className="error-boundary__container">
        <h2 className="error-boundary__title">Something went wrong</h2>
        <p className="error-boundary__message">
          {error.message || "An unexpected error occurred"}
        </p>
        <div className="error-boundary__actions">
          <button
            onClick={resetErrorBoundary}
            className="error-boundary__button error-boundary__button--primary"
          >
            Try again
          </button>
          <button
            onClick={() => window.location.reload()}
            className="error-boundary__button error-boundary__button--secondary"
          >
            Reload page
          </button>
        </div>
        {process.env.NODE_ENV === "development" && (
          <details className="error-boundary__details">
            <summary>Error details (dev only)</summary>
            <pre className="error-boundary__stack">{error.stack}</pre>
          </details>
        )}
      </div>
    </div>
  );
};

interface ErrorBoundaryProps {
  children: React.ReactNode;
  fallback?: React.ComponentType<ErrorFallbackProps>;
}

export const ErrorBoundary: React.FC<ErrorBoundaryProps> = ({
  children,
  fallback = ErrorFallback,
}) => {
  const addNotification = useUIStore((state) => state.addNotification);

  const handleError = (
    error: Error,
    errorInfo: { componentStack?: string },
  ) => {
    // Log error to console in development
    if (process.env.NODE_ENV === "development") {
      console.error("Error caught by boundary:", error);
      console.error("Component stack:", errorInfo.componentStack);
    }

    // Show notification
    addNotification({
      type: "error",
      title: "Application Error",
      message: "An unexpected error occurred. Please try again.",
      duration: 0, // Don't auto-dismiss
    });

    // In production, you might want to send error to logging service
    if (process.env.NODE_ENV === "production") {
      // Example: send to error tracking service
      // errorTrackingService.captureException(error, { extra: errorInfo })
    }
  };

  return (
    <ReactErrorBoundary
      FallbackComponent={fallback}
      onError={handleError}
      onReset={() => {
        // Clear any error state when resetting
        window.location.hash = "#";
      }}
    >
      {children}
    </ReactErrorBoundary>
  );
};
