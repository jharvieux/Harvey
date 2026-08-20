export async function evaluateRequestForm(request: Request) {
  const formData = await request.formData();
  return eval(formData.get("expression"));
}
