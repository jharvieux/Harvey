import { z } from "zod";

const rawCloudProjectId = process.env.CLOUD_PROJECT_ID;
const cloudProjectId = z.string().min(1).parse(rawCloudProjectId);
export const deploymentConfig = { projectId: cloudProjectId };
