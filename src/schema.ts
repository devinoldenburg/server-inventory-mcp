import { z } from "zod";

/**
 * A single server entry in the inventory.
 *
 * Either `ssh_alias` (preferred — resolves through ~/.ssh/config) or
 * `host` must be set. If `ssh_alias` is set, the agent should connect
 * with `ssh <alias>` and let ssh_config handle user/port/identity.
 */
export const ServerSchema = z.object({
  name: z
    .string()
    .min(1)
    .regex(/^[A-Za-z0-9._-]+$/, "name may only contain letters, digits, dot, underscore, dash"),
  host: z.string().min(1).nullable().optional(),
  user: z.string().min(1).nullable().optional(),
  port: z.number().int().positive().max(65535).nullable().optional(),
  ssh_alias: z.string().min(1).nullable().optional(),
  identity_file: z.string().min(1).nullable().optional(),
  jump_host: z.string().min(1).nullable().optional(),
  groups: z.array(z.string().min(1)).default([]),
  tags: z.array(z.string().min(1)).default([]),
  description: z.string().nullable().optional(),
  environment: z.string().nullable().optional(),
  role: z.string().nullable().optional(),
  notes: z.string().nullable().optional(),
});

export type Server = z.infer<typeof ServerSchema>;

export const InventorySchema = z.object({
  version: z.literal(1).default(1),
  servers: z.array(ServerSchema).default([]),
});

export type Inventory = z.infer<typeof InventorySchema>;

export function validateConnectable(s: Server): void {
  if (!s.ssh_alias && !s.host) {
    throw new Error(
      `Server "${s.name}" must define either ssh_alias or host so it is reachable.`,
    );
  }
}
