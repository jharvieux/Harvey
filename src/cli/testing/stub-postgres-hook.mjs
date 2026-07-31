// Registers a resolve hook that points the bare `postgres` specifier at
// stub-postgres.mjs, so a child process can run the real src/cli/detect-deeper.ts
// with no database (#1407). Used as `node --import tsx --import <this file>`.

import { register } from "node:module";
import { pathToFileURL } from "node:url";

register("./stub-postgres-resolver.mjs", pathToFileURL(import.meta.filename));
