import { NextRequest, NextResponse } from "next/server";
import { loginSchema } from "@/lib/validation/auth";
import { successResponse, errorResponse } from "@/lib/api-response";
import { prisma } from "@/lib/prisma";
import { compare } from "bcryptjs";
import { rateLimit } from "@/lib/rate-limit";
import { logger } from "@/lib/logger";

export async function POST(request: NextRequest) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") || request.ip || "unknown";

    if (!rateLimit(`login:${ip}`, 5, 900000)) {
      logger.warn({ ip }, "Rate limit exceeded for login");
      return NextResponse.json(
        errorResponse("Too many login attempts. Try again later."),
        { status: 429 }
      );
    }

    const body = await request.json();
    const { email, password } = loginSchema.parse(body);

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      logger.warn({ email }, "Login attempt with non-existent user");
      return NextResponse.json(errorResponse("Invalid credentials"), {
        status: 401,
      });
    }

    const isPasswordValid = await compare(password, user.password);

    if (!isPasswordValid) {
      logger.warn({ email }, "Login attempt with invalid password");
      return NextResponse.json(errorResponse("Invalid credentials"), {
        status: 401,
      });
    }

    logger.info({ userId: user.id, email }, "User logged in successfully");

    return NextResponse.json(
      successResponse({
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      })
    );
  } catch (error) {
    logger.error(error, "Login error");
    return NextResponse.json(
      errorResponse("Invalid request"),
      { status: 400 }
    );
  }
}
