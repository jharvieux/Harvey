// PLANTED BUG (P-AWS-KEY): a hardcoded AWS access key id + secret access key. Both VALUES are
// DEFANGED — a real AKIA... id + 40-char secret trips GitHub push protection, so the committed
// literals are pure high-entropy fakes with the AWS prefixes removed. gitleaks catches the secret
// via generic-api-key at review; the aws-access-token pattern was validated on the real-shape
// value pre-commit (GROUND-TRUTH §B1). Review, not the free count (a live key would verify at STS).
const AWS_ACCESS_KEY_ID = "Mw3Qr8Kp2Ld6Hj4Gg1Fa9Sc0Rb5Tn3Uv8Wm2Xk7Yl4";
const AWS_SECRET_ACCESS_KEY = "Uo1Bx6Vt0Zi7Ny5Mw3Qr8Kp2Ld6Hj4Gg1Fa9Sc0Rb5Tn3Uv8";

export function s3Config() {
  return { accessKeyId: AWS_ACCESS_KEY_ID, secretAccessKey: AWS_SECRET_ACCESS_KEY, region: "us-east-1" };
}
