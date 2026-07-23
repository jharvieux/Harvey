import { describe, expect, it } from "vitest";
import { parsePrismaSchema } from "./prisma-schema-parse.js";

describe("parsePrismaSchema (#758) — schema.prisma model/field extraction, CLI-independent", () => {
  it("extracts scalar fields from a model, using the model name as the table name", () => {
    const schema = `
      model User {
        id    String   @id @default(cuid())
        email String   @unique
        phone String?
        createdAt DateTime @default(now())
      }
    `;
    const columns = parsePrismaSchema(schema);
    expect(columns).toEqual(
      expect.arrayContaining([
        { table_name: "User", column_name: "id", data_type: "text" },
        { table_name: "User", column_name: "email", data_type: "text" },
        { table_name: "User", column_name: "phone", data_type: "text" },
        { table_name: "User", column_name: "createdAt", data_type: "timestamptz" },
      ]),
    );
  });

  it("skips relation fields — their type is another model, not a scalar, and the backing FK scalar is captured instead", () => {
    const schema = `
      model User {
        id    String @id
        notes Note[]
      }
      model Note {
        id     String @id
        userId String
        user   User   @relation(fields: [userId], references: [id])
      }
    `;
    const columns = parsePrismaSchema(schema);
    expect(columns.some((c) => c.column_name === "notes")).toBe(false);
    expect(columns.some((c) => c.column_name === "user" && c.table_name === "Note")).toBe(false);
    expect(columns).toContainEqual({ table_name: "Note", column_name: "userId", data_type: "text" });
  });

  it("honors @map (column rename) and @@map (table rename)", () => {
    const schema = `
      model Customer {
        id           String @id
        paymentRef   String @map("payment_ref")
        @@map("customers")
      }
    `;
    const columns = parsePrismaSchema(schema);
    expect(columns).toContainEqual({ table_name: "customers", column_name: "payment_ref", data_type: "text" });
    expect(columns.some((c) => c.table_name === "Customer")).toBe(false);
  });

  it("maps every Prisma scalar type to a data_type the classifier's boolean/jsonb checks recognize", () => {
    const schema = `
      model Widget {
        active   Boolean
        payload  Json
        blob     Bytes
        price    Decimal
        qty      Int
        bigNum   BigInt
        ratio    Float
      }
    `;
    const byName = Object.fromEntries(parsePrismaSchema(schema).map((c) => [c.column_name, c.data_type]));
    expect(byName.active).toBe("boolean");
    expect(byName.payload).toBe("jsonb");
    expect(byName.blob).toBe("bytea");
    expect(byName.price).toBe("numeric");
    expect(byName.qty).toBe("integer");
    expect(byName.bigNum).toBe("bigint");
    expect(byName.ratio).toBe("double precision");
  });

  it("strips // line comments before parsing", () => {
    const schema = `
      // A user account
      model User {
        id String @id // primary key
        email String
      }
    `;
    expect(parsePrismaSchema(schema)).toEqual([
      { table_name: "User", column_name: "id", data_type: "text" },
      { table_name: "User", column_name: "email", data_type: "text" },
    ]);
  });

  it("returns no columns for schema text with no model blocks", () => {
    const schema = `
      generator client {
        provider = "prisma-client-js"
      }
      datasource db {
        provider = "postgresql"
        url      = env("DATABASE_URL")
      }
    `;
    expect(parsePrismaSchema(schema)).toEqual([]);
  });

  it("captures an enum-typed field as a column by name, but still skips a model-typed relation (#854)", () => {
    const schema = `
      enum Gender { MALE FEMALE OTHER }
      enum Role { ADMIN MEMBER }
      model User {
        id     String @id
        gender Gender
        roles  Role[]
        posts  Post[]
      }
      model Post {
        id     String @id
        userId String
      }
    `;
    const columns = parsePrismaSchema(schema);
    // enum fields (incl. an enum array) are stored columns → classified by name
    expect(columns).toContainEqual({ table_name: "User", column_name: "gender", data_type: "gender" });
    expect(columns).toContainEqual({ table_name: "User", column_name: "roles", data_type: "role" });
    // a model-typed relation has no column of its own
    expect(columns.some((c) => c.column_name === "posts")).toBe(false);
  });

  it("parses composite `type` blocks like models so their embedded fields become columns (#854)", () => {
    const schema = `
      type Address {
        street String
        city   String
      }
      model User {
        id       String  @id
        homeAddr Address
      }
    `;
    const columns = parsePrismaSchema(schema);
    expect(columns).toContainEqual({ table_name: "Address", column_name: "street", data_type: "text" });
    expect(columns).toContainEqual({ table_name: "Address", column_name: "city", data_type: "text" });
    // the embedded-object field itself is not a stored scalar column
    expect(columns.some((c) => c.column_name === "homeAddr")).toBe(false);
  });

  it("skips a field whose capitalized type is declared nowhere — under-extract, don't guess", () => {
    const schema = `
      model User {
        id    String @id
        thing Mystery
      }
    `;
    expect(parsePrismaSchema(schema).some((c) => c.column_name === "thing")).toBe(false);
  });

  it("parses multiple models independently, each with its own table name", () => {
    const schema = `
      model Account {
        id    String @id
        email String
      }
      model Session {
        id        String @id
        sessionId String
      }
    `;
    const columns = parsePrismaSchema(schema);
    expect(columns.filter((c) => c.table_name === "Account")).toHaveLength(2);
    expect(columns.filter((c) => c.table_name === "Session")).toHaveLength(2);
  });
});
