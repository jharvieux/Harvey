import { env } from "../lib/env";

export const ordersClient = new OrdersClient({ baseURL: env.ORDERS_BASE_URL });
