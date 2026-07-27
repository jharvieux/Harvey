// SAFE TWIN (N-LIB-EXEC-NOSINK, #946): an exported param used only as data (a template string),
// never reaching exec/eval. harvey-lib-command-injection / harvey-lib-code-injection are taint-gated
// on reaching the shell/eval sink, so this must stay silent.
export function label(name) {
  return `job:${name}`;
}
