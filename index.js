import express from "express";
import cors from "cors";
import "dotenv/config";
import { connectDB, isDBConnected } from "./config/db.js";
import healthRoutes from "./routes/health.routes.js";
import { globalErrorHandler, notFoundHandler } from "./middleware/errorHandler.js";

const app = express();
const port = process.env.PORT || 5000;

const allowedOrigins = new Set(
  [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    process.env.CLIENT_URL,
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : []),
  ]
    .map((origin) => origin?.trim())
    .filter(Boolean)
);

const corsOptions = {
  origin(origin, callback) {
    // Allow non-browser requests (curl, health checks, server-to-server) and whitelisted origins
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    const err = new Error(`CORS blocked for origin: ${origin}`);
    err.statusCode = 403;
    return callback(err);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

app.get("/", (_req, res) => {
  res.status(200).json({
    success: true,
    name: "BharaDei.com API",
    message: "BharaDei.com Equipment Rental API is running.",
    dbConnected: isDBConnected(),
  });
});

app.use("/api", healthRoutes);

app.use(notFoundHandler);
app.use(globalErrorHandler);

async function startServer() {
  try {
    await connectDB();
  } catch (err) {
    console.error("[DB] Initial MongoDB connection failed:", err.message);
  }

  app.listen(port, () => {
    console.log(`BharaDei.com server running at http://localhost:${port}`);
  });
}

startServer();

export default app;
