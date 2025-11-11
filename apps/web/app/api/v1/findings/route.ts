import { NextRequest, NextResponse } from "next/server";
import { findingSchema } from "@/lib/validation/findings";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { rateLimit } from "@/lib/rate-limit";

export async function GET() {
  try {
    const findings = await prisma.finding.findMany({
      include: {
        assessment: { select: { title: true, projectId: true } },
        evidence: true,
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(successResponse(findings));
  } catch (error) {
    logger.error(error, "Error fetching findings");
    return NextResponse.json(
      errorResponse("Failed to fetch findings"),
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") || request.ip || "unknown";

    if (!rateLimit(`create:finding:${ip}`, 10, 60000)) {
      return NextResponse.json(errorResponse("Rate limited"), { status: 429 });
    }

    const body = await request.json();
    const { assessmentId, itemId, title, description, severity, status } =
      findingSchema.parse(body);

    const finding = await prisma.finding.create({
      data: {
        assessmentId,
        itemId,
        title,
        description,
        severity,
        status,
      },
    });

    logger.info({ findingId: finding.id }, "Finding created");

    return NextResponse.json(successResponse(finding), { status: 201 });
  } catch (error) {
    logger.error(error, "Error creating finding");
    return NextResponse.json(
      errorResponse("Failed to create finding"),
      { status: 400 }
    );
  }
}
