import { NextRequest, NextResponse } from "next/server";
import { projectSchema } from "@/lib/validation/projects";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const project = await prisma.project.findUnique({
      where: { id: params.id },
      include: {
        assessments: {
          include: {
            checklist: { select: { title: true } },
          },
        },
      },
    });

    if (!project) {
      return NextResponse.json(
        errorResponse("Project not found"),
        { status: 404 }
      );
    }

    return NextResponse.json(successResponse(project));
  } catch (error) {
    logger.error(error, "Error fetching project");
    return NextResponse.json(
      errorResponse("Failed to fetch project"),
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
    const { name, description, scope } = projectSchema.partial().parse(body);

    const project = await prisma.project.update({
      where: { id: params.id },
      data: { name, description, scope },
    });

    logger.info({ projectId: project.id }, "Project updated");

    return NextResponse.json(successResponse(project));
  } catch (error) {
    logger.error(error, "Error updating project");
    return NextResponse.json(
      errorResponse("Failed to update project"),
      { status: 400 }
    );
  }
}
