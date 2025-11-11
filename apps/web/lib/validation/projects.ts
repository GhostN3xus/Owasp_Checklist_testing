import { z } from "zod";

export const projectSchema = z.object({
  name: z.string().min(1, "Nome do projeto é obrigatório"),
  description: z.string().optional(),
  scope: z.string().optional(),
});

export type ProjectInput = z.infer<typeof projectSchema>;
