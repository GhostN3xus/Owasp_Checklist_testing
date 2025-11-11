import { NextRequest, NextResponse } from "next/server";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET(_: NextRequest) {
  try {
    const checklists = await prisma.checklist.findMany({
      include: {
        items: {
          select: {
            id: true,
            code: true,
            title: true,
            category: true,
            severity: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(successResponse(checklists));
  } catch (error) {
    logger.error(error, "Error fetching checklists");
    return NextResponse.json(
      errorResponse("Failed to fetch checklists"),
      { status: 500 }
    );
  }
}
