import { NextRequest, NextResponse } from "next/server";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET(
  request: NextRequest,
  { params }: { params: { slug: string } }
) {
  try {
    const checklist = await prisma.checklist.findUnique({
      where: { slug: params.slug },
      include: {
        items: {
          orderBy: { sort: "asc" },
        },
      },
    });

    if (!checklist) {
      return NextResponse.json(
        errorResponse("Checklist not found"),
        { status: 404 }
      );
    }

    return NextResponse.json(successResponse(checklist));
  } catch (error) {
    logger.error(error, "Error fetching checklist");
    return NextResponse.json(
      errorResponse("Failed to fetch checklist"),
      { status: 500 }
    );
  }
}
