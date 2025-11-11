import { NextRequest, NextResponse } from "next/server";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const assessment = await prisma.assessment.findUnique({
      where: { id: params.id },
      include: {
        project: true,
        checklist: { include: { items: true } },
        items: {
          include: {
            item: true,
          },
        },
        findings: true,
      },
    });

    if (!assessment) {
      return NextResponse.json(
        errorResponse("Assessment not found"),
        { status: 404 }
      );
    }

    // Calculate progress
    const totalItems = assessment.items.length;
    const completedItems = assessment.items.filter(
      (i: any) => i.status !== "PENDING"
    ).length;
    const progress = totalItems > 0 ? (completedItems / totalItems) * 100 : 0;

    return NextResponse.json(
      successResponse({ ...assessment, progress })
    );
  } catch (error) {
    logger.error(error, "Error fetching assessment");
    return NextResponse.json(
      errorResponse("Failed to fetch assessment"),
      { status: 500 }
    );
  }
}
