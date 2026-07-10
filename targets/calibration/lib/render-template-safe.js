import Handlebars from "handlebars";

// NEGATIVE (N-TEMPLATE-ESCAPED): default Handlebars.compile keeps HTML escaping on. No noEscape
// option — harvey-template-autoescape-off is cleared.
export function render(tpl, data) {
  const template = Handlebars.compile(tpl);
  return template(data);
}
