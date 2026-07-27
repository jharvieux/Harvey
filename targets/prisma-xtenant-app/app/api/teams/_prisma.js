// Prisma client for the live stand-up (#1163). Reads DATABASE_URL from the schema's env datasource —
// Harvey forces it at the Postgres container it stood up.
import { PrismaClient } from "@prisma/client";

export const prisma = globalThis.__harveyPrisma ?? new PrismaClient();
globalThis.__harveyPrisma = prisma;
