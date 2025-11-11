import { NextRequest, NextResponse } from "next/server";
import { assessmentSchema } from "@/lib/validation/assessments";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { rateLimit } from "@/lib/rate-limit";

export async function GET() {
  try {
    const assessments = await prisma.assessment.findMany({
      include: {
        project: { select: { name: true } },
        checklist: { select: { title: true } },
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(successResponse(assessments));
  } catch (error) {
    logger.error(error, "Error fetching assessments");
    return NextResponse.json(
      errorResponse("Failed to fetch assessments"),
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") || request.ip || "unknown";

    if (!rateLimit(`create:assessment:${ip}`, 10, 60000)) {
      return NextResponse.json(errorResponse("Rate limited"), { status: 429 });
    }

    const body = await request.json();
    const { projectId, checklistId, title, notes } =
      assessmentSchema.parse(body);

    // Get checklist items to create assessment items
    const checklistItems = await prisma.checklistItem.findMany({
      where: { checklistId },
    });

    const assessment = await prisma.assessment.create({
      data: {
        projectId,
        checklistId,
        title,
        notes,
        startedAt: new Date(),
        items: {
          create: checklistItems.map((item: any) => ({
            itemId: item.id,
            status: "PENDING",
          })),
        },
      },
      include: {
        items: true,
      },
    });

    logger.info({ assessmentId: assessment.id }, "Assessment created");

    return NextResponse.json(successResponse(assessment), { status: 201 });
  } catch (error) {
    logger.error(error, "Error creating assessment");
    return NextResponse.json(
      errorResponse("Failed to create assessment"),
      { status: 400 }
    );
  }
}
