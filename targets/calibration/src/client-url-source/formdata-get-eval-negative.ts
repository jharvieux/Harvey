export function evaluateLocalForm(formData: FormData) {
  return eval(formData.get("expression"));
}
