import { execFile } from "node:child_process";

// N-CMD-SAFE (NEGATIVE — must NOT be flagged): execFile with an ARGUMENT ARRAY and no shell.
// The untrusted filename is a discrete argv entry, never interpreted by /bin/sh, so there is no
// command injection. The command-injection rule must fire only on exec/execSync of a string.
export function toThumbnail(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    execFile("convert", [inputPath, "-resize", "128x128", outputPath], (err) =>
      err ? reject(err) : resolve(outputPath),
    );
  });
}
