import { stack } from "../lib/stack";

export const ledgerService = new CloudService("ledger", {
  accountId: stack.require("accountId"),
});
