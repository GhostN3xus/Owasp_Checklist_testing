/**
 * JSON Export utilities
 * Handles conversion of assessment data to JSON format
 */

export interface ExportAssessment {
  id: string;
  title: string;
  status: string;
  progress: number;
  notes?: string | null;
  createdAt: Date;
  updatedAt: Date;
  startedAt?: Date | null;
  completedAt?: Date | null;
  project: {
    id: string;
    name: string;
    description?: string | null;
  };
  checklist: {
    id: string;
    slug: string;
    title: string;
    version: string;
    category: string;
  };
  items: Array<{
    id: string;
    status: string;
    notes?: string | null;
    evidence?: string | null;
    item: {
      code: string;
      title: string;
      description?: string | null;
      severity: string;
      cweId?: string | null;
      category: string;
    };
  }>;
  findings?: Array<{
    id: string;
    title: string;
    description: string;
    severity: string;
    status: string;
    createdAt: Date;
    updatedAt: Date;
  }>;
}

export function assessmentToJSON(assessment: ExportAssessment): string {
  const exportData = {
    metadata: {
      exportedAt: new Date().toISOString(),
      version: "1.0",
      format: "OWASP Checklist Assessment Export",
    },
    assessment: {
      id: assessment.id,
      title: assessment.title,
      status: assessment.status,
      progress: assessment.progress,
      notes: assessment.notes,
      createdAt: assessment.createdAt,
      updatedAt: assessment.updatedAt,
      startedAt: assessment.startedAt,
      completedAt: assessment.completedAt,
    },
    project: assessment.project,
    checklist: assessment.checklist,
    items: assessment.items.map((item) => ({
      code: item.item.code,
      title: item.item.title,
      description: item.item.description,
      category: item.item.category,
      severity: item.item.severity,
      cweId: item.item.cweId,
      status: item.status,
      notes: item.notes,
      evidence: item.evidence,
    })),
    findings: assessment.findings?.map((finding) => ({
      id: finding.id,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      status: finding.status,
      createdAt: finding.createdAt,
      updatedAt: finding.updatedAt,
    })),
    statistics: {
      totalItems: assessment.items.length,
      itemsByStatus: calculateItemsByStatus(assessment.items),
      itemsBySeverity: calculateItemsBySeverity(assessment.items),
      findingsCount: assessment.findings?.length || 0,
    },
  };

  return JSON.stringify(exportData, null, 2);
}

function calculateItemsByStatus(
  items: ExportAssessment["items"]
): Record<string, number> {
  return items.reduce(
    (acc, item) => {
      acc[item.status] = (acc[item.status] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );
}

function calculateItemsBySeverity(
  items: ExportAssessment["items"]
): Record<string, number> {
  return items.reduce(
    (acc, item) => {
      acc[item.item.severity] = (acc[item.item.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );
}

export function generateJSONFilename(
  assessmentTitle: string,
  assessmentId: string
): string {
  const sanitizedTitle = assessmentTitle
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  const timestamp = new Date().toISOString().split("T")[0];
  return `assessment-${sanitizedTitle}-${timestamp}-${assessmentId.slice(0, 8)}.json`;
}
