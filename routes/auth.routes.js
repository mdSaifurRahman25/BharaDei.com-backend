import { Router } from "express";
import { asyncHandler } from "../middleware/errorHandler.js";
import { verifyToken } from "../middleware/auth.js";
import {
  getCurrentProfile,
  loginUser,
  registerUser,
  syncOAuthUser,
  updateCurrentProfile,
} from "../controllers/auth.controller.js";

const router = Router();

router.post("/register", asyncHandler(registerUser));
router.post("/login", asyncHandler(loginUser));
router.post("/oauth-sync", asyncHandler(syncOAuthUser));
router.get("/me", verifyToken, asyncHandler(getCurrentProfile));
router.put("/profile", verifyToken, asyncHandler(updateCurrentProfile));

export default router;
