import { Router } from "express";
import { getDB, isDBConnected } from "../config/db.js";

const router = Router();

router.get("/health", async (_req, res) => {
  let dbConnected = isDBConnected();
  if (!dbConnected && process.env.MONGODB_URI) {
    try {
      const db = await getDB();
      dbConnected = Boolean(db);
    } catch {
      dbConnected = false;
    }
  }

  res.status(200).json({
    success: true,
    service: "BharaDei.com API",
    tagline: "Everything You Need, Ready to Rent.",
    dbConnected,
    timestamp: new Date().toISOString(),
  });
});

export default router;
