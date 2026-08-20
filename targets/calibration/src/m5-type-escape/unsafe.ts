interface Account {
  id: string;
}

interface AccountView {
  id: string;
}

declare const raw: unknown;

export const uncheckedAny = raw as any as Account;
export const uncheckedAccount = (raw as unknown) as Account;
export const collapsedChain = raw as unknown as Account as AccountView;

// @ts-ignore
export const silentlySuppressed: number = raw;
