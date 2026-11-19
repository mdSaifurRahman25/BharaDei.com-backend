/**
 * Wraps async Express route handlers to forward unexpected rejections consistently.
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Handles unmatched API routes with a standardized 404 JSON response.
 */
export function notFoundHandler(req, res) {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
}

/**
 * Centralized Express error handler returning structured JSON payloads.
 */
export function globalErrorHandler(err, req, res, _next) {
  const statusCode = err.statusCode || err.status || 500;
  const message =
    statusCode >= 500 && process.env.NODE_ENV === "production"
      ? "Internal server error"
      : err.message || "Something went wrong";

  if (statusCode >= 500) {
    console.error(`[API Error] ${req.method} ${req.originalUrl}:`, err);
  }

  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV !== "production" && statusCode >= 500
      ? { stack: err.stack }
      : {}),
  });
}
