import { z } from "zod";

export const assessmentSchema = z.object({
  projectId: z.string().min(1, "Project ID é obrigatório"),
  checklistId: z.string().min(1, "Checklist ID é obrigatório"),
  title: z.string().min(1, "Título é obrigatório"),
  notes: z.string().optional(),
});

export type AssessmentInput = z.infer<typeof assessmentSchema>;

export const assessmentItemSchema = z.object({
  status: z.enum(["PENDING", "PASS", "FAIL", "NA"]),
  notes: z.string().optional(),
  evidence: z.string().optional(),
});

export type AssessmentItemInput = z.infer<typeof assessmentItemSchema>;
