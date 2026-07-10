import Handlebars from "handlebars";

// PLANTED BUG (P-TEMPLATE-AUTOESCAPE-OFF): Handlebars.compile with { noEscape: true } disables HTML
// escaping for every interpolation, so any user data rendered through the template becomes an XSS
// sink. harvey-template-autoescape-off.
export function render(tpl, data) {
  const template = Handlebars.compile(tpl, { noEscape: true });
  return template(data);
}
