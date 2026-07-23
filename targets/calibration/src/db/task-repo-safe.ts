import { prisma } from "./client";

// #760 negative fixture: the same reads/writes, each scoped to the caller's organizationId, so the
// where clause confines the row to the caller's tenant. The prisma-tenant-scope pass must stay
// fully silent here (a tenant/owner column present in the where clears the finding).

export async function getTask(id: string, organizationId: string) {
  return prisma.task.findFirst({ where: { id, organizationId } });
}

export async function renameTask(id: string, organizationId: string, name: string) {
  return prisma.task.updateMany({ where: { id, organizationId }, data: { name } });
}

export async function deleteTask(id: string, organizationId: string) {
  return prisma.task.deleteMany({ where: { id, organizationId } });
}
