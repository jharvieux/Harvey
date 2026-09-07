# MEMORY index — archive

Older one-line decision pointers moved out of the session-start index. Do not read this
file at startup. Search it when the current task touches older context, then read only
the matching entry in `MEMORY.md`.

Each decision belongs in exactly one of the two index files. New entries always start
in `MEMORY-INDEX.md`; archival is an exact move of an existing line, never a copy.

## Entries
