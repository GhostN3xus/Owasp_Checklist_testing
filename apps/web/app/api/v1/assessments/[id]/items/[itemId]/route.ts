import { NextRequest, NextResponse } from "next/server";
import { assessmentItemSchema } from "@/lib/validation/assessments";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string; itemId: string } }
) {
  try {
    const body = await request.json();
    const { status, notes, evidence } = assessmentItemSchema.parse(body);

    const assessmentItem = await prisma.assessmentItem.update({
      where: {
        assessmentId_itemId: {
          assessmentId: params.id,
          itemId: params.itemId,
        },
      },
      data: {
        status,
        notes,
        evidence,
        updatedAt: new Date(),
      },
    });

    // Update assessment progress
    const assessment = await prisma.assessment.findUnique({
      where: { id: params.id },
      include: { items: true },
    });

    if (assessment) {
      const totalItems = assessment.items.length;
      const completedItems = assessment.items.filter(
        (i: any) => i.status !== "PENDING"
      ).length;
      const progress = totalItems > 0 ? (completedItems / totalItems) * 100 : 0;

      await prisma.assessment.update({
        where: { id: params.id },
        data: { progress },
      });
    }

    logger.info(
      { assessmentId: params.id, itemId: params.itemId, status },
      "Assessment item updated"
    );

    return NextResponse.json(successResponse(assessmentItem));
  } catch (error) {
    logger.error(error, "Error updating assessment item");
    return NextResponse.json(
      errorResponse("Failed to update assessment item"),
      { status: 400 }
    );
  }
}
