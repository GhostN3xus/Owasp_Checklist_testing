import { describe, it, expect } from "vitest";
import { loginSchema } from "../auth";

describe("Auth Validation", () => {
  it("should validate correct login credentials", () => {
    const result = loginSchema.parse({
      email: "user@example.com",
      password: "securepass123",
    });
    expect(result.email).toBe("user@example.com");
    expect(result.password).toBe("securepass123");
  });

  it("should reject invalid email", () => {
    expect(() => {
      loginSchema.parse({
        email: "invalid-email",
        password: "securepass123",
      });
    }).toThrow();
  });

  it("should reject short password", () => {
    expect(() => {
      loginSchema.parse({
        email: "user@example.com",
        password: "short",
      });
    }).toThrow();
  });
});
