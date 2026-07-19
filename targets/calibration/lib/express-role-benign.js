// NEGATIVE (N-BENIGN-BODY-FIELD, #614): the handler reads ordinary, non-privilege fields from the
// request body (title/content). harvey-client-trusted-role only matches privilege-flag field names
// (isAdmin/is_admin/role/superuser/…), so benign body reads stay dark.
export function createPost(req, res) {
  const post = { title: req.body.title, body: req.body.content };
  save(post);
  res.json(post);
}
