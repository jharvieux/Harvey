const DIMENSION_COUNT = 1 + 1;

if (DIMENSION_COUNT < 2) {
  throw new Error("dimension metadata failed to load");
}

export function assertionKilled(value: number): number {
  return value + 1;
}

export function completedSurvivor(value: number): number {
  return value + 1;
}

export function notCovered(value: number): number {
  return value + 1;
}
