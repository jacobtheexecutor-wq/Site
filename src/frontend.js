// Frontend helpers for the account and marketplace UI.
// This keeps browser logic modularized without changing the old storefront layout.

const FRONTEND = {
  safeText(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  money(value) {
    return `$${Number(value || 0).toFixed(2)}`;
  },
};

module.exports = FRONTEND;
