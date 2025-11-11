// Simple HTML entity encoding for sanitization
export function sanitizeHTML(html: string): string {
  const entities: { [key: string]: string } = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return html.replace(/[&<>"']/g, (char) => entities[char] || char);
}

export function sanitizeMarkdown(markdown: string): string {
  // For now, just sanitize HTML entities
  return sanitizeHTML(markdown);
}
