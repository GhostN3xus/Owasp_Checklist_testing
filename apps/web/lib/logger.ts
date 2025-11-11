import pino from "pino";

const isDevelopment = process.env.NODE_ENV === "development";

export const logger = pino(
  {
    level: process.env.LOG_LEVEL || "info",
  },
  isDevelopment ? pino.transport({
    target: "pino-pretty",
    options: {
      colorize: true,
    },
  }) : undefined
);

export default logger;
