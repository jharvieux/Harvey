import { describe, expect, it } from "vitest";
import { findUnindexedForeignKeys } from "./prisma-schema-perf.js";

// Each negative differs from the positive by exactly one gate, so a single-gate regression fails a
// specific test rather than only the whole-schema finding count.

describe("findUnindexedForeignKeys (#761 — Prisma schema.prisma static index review)", () => {
  it("flags a relation scalar FK field with no covering index anywhere on its model", () => {
    const schema = `
      model User {
        id    String @id @default(cuid())
        notes Note[]
      }
      model Note {
        id     String @id @default(cuid())
        userId String
        user   User   @relation(fields: [userId], references: [id])
      }
    `;
    const gaps = findUnindexedForeignKeys(schema);
    expect(gaps).toEqual([{ model: "Note", field: "userId", relationField: "user", line: expect.any(Number) }]);
  });

  it("stays silent when the FK field is covered by @@index", () => {
    const schema = `
      model Note {
        id     String @id @default(cuid())
        userId String
        user   User   @relation(fields: [userId], references: [id])
        @@index([userId])
      }
    `;
    expect(findUnindexedForeignKeys(schema)).toEqual([]);
  });

  it("stays silent when the FK field itself carries @unique (one-to-one relation)", () => {
    const schema = `
      model Profile {
        id     String @id @default(cuid())
        userId String @unique
        user   User   @relation(fields: [userId], references: [id])
      }
    `;
    expect(findUnindexedForeignKeys(schema)).toEqual([]);
  });

  it("stays silent when the FK field is covered by @@unique", () => {
    const schema = `
      model Note {
        id     String @id @default(cuid())
        userId String
        user   User   @relation(fields: [userId], references: [id])
        @@unique([userId])
      }
    `;
    expect(findUnindexedForeignKeys(schema)).toEqual([]);
  });

  it("stays silent when the FK field is the model's own @id (or leads a composite @@id)", () => {
    const schema = `
      model Note {
        userId String @id
        user   User   @relation(fields: [userId], references: [id])
      }
    `;
    expect(findUnindexedForeignKeys(schema)).toEqual([]);
  });

  it("covers a field named anywhere in a composite @@index, not only in the leading position", () => {
    const schema = `
      model Note {
        id       String @id @default(cuid())
        tenantId String
        userId   String
        user     User   @relation(fields: [userId], references: [id])
        @@index([tenantId, userId])
      }
    `;
    expect(findUnindexedForeignKeys(schema)).toEqual([]);
  });

  it("flags each uncovered FK column independently across multiple models", () => {
    const schema = `
      model Note {
        id     String @id
        userId String
        user   User   @relation(fields: [userId], references: [id])
      }
      model Comment {
        id     String @id
        noteId String
        note   Note   @relation(fields: [noteId], references: [id])
        @@index([noteId])
      }
    `;
    const gaps = findUnindexedForeignKeys(schema);
    expect(gaps).toEqual([{ model: "Note", field: "userId", relationField: "user", line: expect.any(Number) }]);
  });

  it("returns nothing for a model with no relation fields", () => {
    const schema = `
      model Widget {
        id   String @id
        name String
      }
    `;
    expect(findUnindexedForeignKeys(schema)).toEqual([]);
  });
});
