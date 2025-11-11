import { NextRequest, NextResponse } from "next/server";
import { projectSchema } from "@/lib/validation/projects";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { rateLimit } from "@/lib/rate-limit";

export async function GET() {
  try {
    const projects = await prisma.project.findMany({
      include: {
        assessments: {
          select: { id: true, status: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(successResponse(projects));
  } catch (error) {
    logger.error(error, "Error fetching projects");
    return NextResponse.json(
      errorResponse("Failed to fetch projects"),
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") || request.ip || "unknown";

    if (!rateLimit(`create:project:${ip}`, 10, 60000)) {
      return NextResponse.json(errorResponse("Rate limited"), { status: 429 });
    }

    const body = await request.json();
    const { name, description, scope } = projectSchema.parse(body);

    const project = await prisma.project.create({
      data: { name, description, scope },
    });

    logger.info({ projectId: project.id }, "Project created");

    return NextResponse.json(successResponse(project), { status: 201 });
  } catch (error) {
    logger.error(error, "Error creating project");
    return NextResponse.json(
      errorResponse("Failed to create project"),
      { status: 400 }
    );
  }
}
