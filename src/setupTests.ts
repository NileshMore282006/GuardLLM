import '@testing-library/jest-dom';

// Mock scrollIntoView in jsdom
if (typeof window !== 'undefined') {
  window.HTMLElement.prototype.scrollIntoView = function () {};
}
