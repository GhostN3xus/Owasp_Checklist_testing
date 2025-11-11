import { NextRequest, NextResponse } from "next/server";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const finding = await prisma.finding.findUnique({
      where: { id: params.id },
      include: {
        assessment: true,
        evidence: true,
      },
    });

    if (!finding) {
      return NextResponse.json(
        errorResponse("Finding not found"),
        { status: 404 }
      );
    }

    return NextResponse.json(successResponse(finding));
  } catch (error) {
    logger.error(error, "Error fetching finding");
    return NextResponse.json(
      errorResponse("Failed to fetch finding"),
      { status: 500 }
    );
  }
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const body = await request.json();
    const { title, description, severity, status } = body;

    const finding = await prisma.finding.update({
      where: { id: params.id },
      data: {
        title,
        description,
        severity,
        status,
      },
    });

    logger.info({ findingId: finding.id }, "Finding updated");

    return NextResponse.json(successResponse(finding));
  } catch (error) {
    logger.error(error, "Error updating finding");
    return NextResponse.json(
      errorResponse("Failed to update finding"),
      { status: 400 }
    );
  }
}
