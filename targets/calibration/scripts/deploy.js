// PLANTED BUG (P-GH-TOKEN): a hardcoded GitHub Personal Access Token in a deploy script. The
// value is FAKE (valid ghp_ + 36 chars shape). gitleaks github-pat matches the prefix;
// TruffleHog can't verify a dead token → review, not the free count.
const GITHUB_TOKEN = "ghp_Z9Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7N";

export function tagRelease(version) {
  return fetch("https://api.github.com/repos/acme/app/git/refs", {
    method: "POST",
    headers: { authorization: `token ${GITHUB_TOKEN}` },
    body: JSON.stringify({ ref: `refs/tags/${version}` }),
  });
}
