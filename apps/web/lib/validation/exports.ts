import { z } from "zod";

/**
 * Export validation schemas
 */

export const exportRequestSchema = z.object({
  assessmentId: z.string().cuid("Invalid assessment ID"),
  format: z.enum(["pdf", "csv", "json"]).optional().default("pdf"),
  includeFindings: z.boolean().optional().default(true),
  includeEvidence: z.boolean().optional().default(true),
});

export const pdfExportRequestSchema = z.object({
  assessmentId: z.string().cuid("Invalid assessment ID"),
  includeFindings: z.boolean().optional().default(true),
  includeEvidence: z.boolean().optional().default(true),
});

export const csvExportRequestSchema = z.object({
  assessmentId: z.string().cuid("Invalid assessment ID"),
  includeNotes: z.boolean().optional().default(true),
});

export const jsonExportRequestSchema = z.object({
  assessmentId: z.string().cuid("Invalid assessment ID"),
  includeFindings: z.boolean().optional().default(true),
  includeMetadata: z.boolean().optional().default(true),
});

export type ExportRequest = z.infer<typeof exportRequestSchema>;
export type PDFExportRequest = z.infer<typeof pdfExportRequestSchema>;
export type CSVExportRequest = z.infer<typeof csvExportRequestSchema>;
export type JSONExportRequest = z.infer<typeof jsonExportRequestSchema>;
