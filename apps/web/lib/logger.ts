import pino from "pino";

const isDevelopment = process.env.NODE_ENV === "development";
const isProduction = process.env.NODE_ENV === "production";

/**
 * Structured logger using Pino
 *
 * Features:
 * - Automatic timestamp
 * - Request ID tracking
 * - Error serialization
 * - Pretty printing in development
 * - JSON output in production
 *
 * Usage:
 * logger.info({ userId: '123' }, 'User logged in');
 * logger.error({ err, requestId }, 'Request failed');
 */
export const logger = pino(
  {
    level: process.env.LOG_LEVEL || (isDevelopment ? "debug" : "info"),
    formatters: {
      level: (label) => {
        return { level: label };
      },
      bindings: (bindings) => {
        return {
          pid: bindings.pid,
          hostname: bindings.hostname,
          app: "owasp-checklist",
        };
      },
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    serializers: {
      req: pino.stdSerializers.req,
      res: pino.stdSerializers.res,
      err: pino.stdSerializers.err,
    },
    redact: {
      paths: [
        "password",
        "*.password",
        "*.token",
        "*.accessToken",
        "*.refreshToken",
        "req.headers.authorization",
        "req.headers.cookie",
      ],
      censor: "[REDACTED]",
    },
  },
  isDevelopment
    ? pino.transport({
        target: "pino-pretty",
        options: {
          colorize: true,
          translateTime: "HH:MM:ss Z",
          ignore: "pid,hostname",
          singleLine: false,
        },
      })
    : undefined
);

/**
 * Create a child logger with additional context
 */
export function createChildLogger(context: Record<string, any>) {
  return logger.child(context);
}

/**
 * Log HTTP request
 */
export function logRequest(
  method: string,
  path: string,
  statusCode: number,
  duration: number,
  context?: Record<string, any>
) {
  logger.info(
    {
      method,
      path,
      statusCode,
      duration,
      ...context,
    },
    `${method} ${path} ${statusCode} - ${duration}ms`
  );
}

/**
 * Log security event
 */
export function logSecurityEvent(
  event: string,
  severity: "low" | "medium" | "high" | "critical",
  details?: Record<string, any>
) {
  logger.warn(
    {
      event,
      severity,
      type: "security",
      ...details,
    },
    `Security event: ${event}`
  );
}

/**
 * Log authentication event
 */
export function logAuthEvent(
  action: "login" | "logout" | "failed_login" | "password_reset",
  userId?: string,
  details?: Record<string, any>
) {
  logger.info(
    {
      action,
      userId,
      type: "auth",
      ...details,
    },
    `Auth event: ${action}`
  );
}

export default logger;
