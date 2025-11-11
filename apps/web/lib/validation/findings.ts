import { z } from "zod";

export const findingSchema = z.object({
  assessmentId: z.string().min(1, "Assessment ID é obrigatório"),
  itemId: z.string().optional(),
  title: z.string().min(1, "Título é obrigatório"),
  description: z.string().min(1, "Descrição é obrigatória"),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
  status: z.string().default("OPEN"),
});

export type FindingInput = z.infer<typeof findingSchema>;
