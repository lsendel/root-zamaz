/**
 * Modal Component
 *
 * Accessible modal dialog with focus management, keyboard navigation,
 * and consistent styling across the application.
 */

import React, { useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import "./Modal.css";

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  size?: "sm" | "md" | "lg" | "xl" | "full";
  closeOnOverlayClick?: boolean;
  closeOnEscape?: boolean;
  showCloseButton?: boolean;
  className?: string;
  overlayClassName?: string;
  "data-testid"?: string;
  footer?: React.ReactNode;
  preventScroll?: boolean;
}

const sizeClasses = {
  sm: "modal__content--sm",
  md: "modal__content--md",
  lg: "modal__content--lg",
  xl: "modal__content--xl",
  full: "modal__content--full",
} as const;

export const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = "md",
  closeOnOverlayClick = true,
  closeOnEscape = true,
  showCloseButton = true,
  className = "",
  overlayClassName = "",
  "data-testid": testId = "modal",
  footer,
  preventScroll = true,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  // Focus management
  useEffect(() => {
    if (isOpen) {
      // Store the previously focused element
      previousActiveElement.current = document.activeElement as HTMLElement;

      // Focus the modal
      const focusableElement = modalRef.current?.querySelector(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      ) as HTMLElement;

      if (focusableElement) {
        focusableElement.focus();
      } else {
        modalRef.current?.focus();
      }

      // Prevent body scroll
      if (preventScroll) {
        document.body.style.overflow = "hidden";
      }
    } else {
      // Restore focus to previously focused element
      if (previousActiveElement.current) {
        previousActiveElement.current.focus();
      }

      // Restore body scroll
      if (preventScroll) {
        document.body.style.overflow = "";
      }
    }

    return () => {
      if (preventScroll) {
        document.body.style.overflow = "";
      }
    };
  }, [isOpen, preventScroll]);

  // Keyboard event handler
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!isOpen) return;

      if (event.key === "Escape" && closeOnEscape) {
        event.preventDefault();
        onClose();
        return;
      }

      if (event.key === "Tab") {
        // Trap focus within modal
        const modal = modalRef.current;
        if (!modal) return;

        const focusableElements = modal.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        );

        const firstFocusable = focusableElements[0] as HTMLElement;
        const lastFocusable = focusableElements[
          focusableElements.length - 1
        ] as HTMLElement;

        if (event.shiftKey) {
          // Shift + Tab
          if (document.activeElement === firstFocusable) {
            event.preventDefault();
            lastFocusable?.focus();
          }
        } else {
          // Tab
          if (document.activeElement === lastFocusable) {
            event.preventDefault();
            firstFocusable?.focus();
          }
        }
      }
    },
    [isOpen, closeOnEscape, onClose],
  );

  // Add/remove event listeners
  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  // Handle overlay click
  const handleOverlayClick = useCallback(
    (event: React.MouseEvent) => {
      if (event.target === event.currentTarget && closeOnOverlayClick) {
        onClose();
      }
    },
    [closeOnOverlayClick, onClose],
  );

  if (!isOpen) return null;

  const modalContent = (
    <div
      className={`modal__overlay ${overlayClassName}`}
      onClick={handleOverlayClick}
      data-testid={`${testId}-overlay`}
      role="presentation"
    >
      <div
        ref={modalRef}
        className={`modal__content ${sizeClasses[size]} ${className}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${testId}-title`}
        data-testid={testId}
        tabIndex={-1}
      >
        {/* Header */}
        <div className="modal__header">
          <h2 id={`${testId}-title`} className="modal__title">
            {title}
          </h2>
          {showCloseButton && (
            <button
              type="button"
              className="modal__close-button"
              onClick={onClose}
              aria-label="Close modal"
              data-testid={`${testId}-close-button`}
            >
              <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
                aria-hidden="true"
              >
                <path
                  d="M18 6L6 18M6 6L18 18"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </button>
          )}
        </div>

        {/* Body */}
        <div className="modal__body">{children}</div>

        {/* Footer */}
        {footer && <div className="modal__footer">{footer}</div>}
      </div>
    </div>
  );

  // Render modal in portal
  return createPortal(modalContent, document.body);
};

// Confirmation modal variant
export interface ConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  variant?: "default" | "danger" | "warning";
  isLoading?: boolean;
}

export const ConfirmModal: React.FC<ConfirmModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = "Confirm",
  cancelText = "Cancel",
  variant = "default",
  isLoading = false,
}) => {
  const handleConfirm = useCallback(() => {
    if (!isLoading) {
      onConfirm();
    }
  }, [onConfirm, isLoading]);

  const variantClasses = {
    default: "btn--primary",
    danger: "btn--danger",
    warning: "btn--warning",
  };

  const footer = (
    <div className="modal__footer-actions">
      <button
        type="button"
        className="btn btn--secondary"
        onClick={onClose}
        disabled={isLoading}
        data-testid="confirm-modal-cancel"
      >
        {cancelText}
      </button>
      <button
        type="button"
        className={`btn ${variantClasses[variant]}`}
        onClick={handleConfirm}
        disabled={isLoading}
        data-testid="confirm-modal-confirm"
      >
        {isLoading ? "Processing..." : confirmText}
      </button>
    </div>
  );

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      size="sm"
      footer={footer}
      data-testid="confirm-modal"
    >
      <p className="modal__confirm-message">{message}</p>
    </Modal>
  );
};
