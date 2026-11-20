import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Stripe from "stripe";

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const app = express();
const port = process.env.PORT || 5000;

// ---------------------------------------------------------------------------
// 1. CORS & Core Middleware
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// 2. MongoDB Connection & Collections
// ---------------------------------------------------------------------------
const COLLECTIONS = {
  USERS: "users",
  EQUIPMENT: "equipment",
  BOOKINGS: "bookings",
  PAYMENTS: "payments",
  FAVORITES: "favorites",
  REVIEWS: "reviews",
};

let mongoClient = null;
let database = null;
let connectionPromise = null;

async function connectDB() {
  if (database) return database;

  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.warn(
      "[DB] MONGODB_URI is not set in backend/.env — running in limited mode until configured."
    );
    return null;
  }

  if (!connectionPromise) {
    connectionPromise = (async () => {
      mongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 4000,
        serverApi: {
          version: ServerApiVersion.v1,
          strict: true,
          deprecationErrors: true,
        },
      });
      await mongoClient.connect();
      const dbName = process.env.DB_NAME || "bharadei";
      database = mongoClient.db(dbName);

      await Promise.all([
        database.collection(COLLECTIONS.USERS).createIndex({ email: 1 }, { unique: true }),
        database
          .collection(COLLECTIONS.EQUIPMENT)
          .createIndex({ status: 1, category: 1, createdAt: -1 }),
        database.collection(COLLECTIONS.EQUIPMENT).createIndex({ ownerEmail: 1 }),
        database
          .collection(COLLECTIONS.BOOKINGS)
          .createIndex({ customerEmail: 1, createdAt: -1 }),
        database
          .collection(COLLECTIONS.BOOKINGS)
          .createIndex({ ownerEmail: 1, createdAt: -1 }),
        database.collection(COLLECTIONS.BOOKINGS).createIndex({ equipmentId: 1 }),
        database
          .collection(COLLECTIONS.FAVORITES)
          .createIndex({ userEmail: 1, equipmentId: 1 }, { unique: true }),
        database
          .collection(COLLECTIONS.PAYMENTS)
          .createIndex({ sessionId: 1 }, { unique: true, sparse: true }),
      ]);

      console.log(`[DB] Connected to MongoDB database: ${dbName}`);
      await seedInitialMarketplaceData(database);
      return database;
    })().catch((err) => {
      connectionPromise = null;
      database = null;
      throw err;
    });
  }

  return connectionPromise;
}

async function getCollection(name) {
  const db = database || (await connectDB());
  if (!db) {
    const err = new Error("Database connection is not configured.");
    err.statusCode = 503;
    throw err;
  }
  return db.collection(name);
}

// ---------------------------------------------------------------------------
// 3. JWT Helpers & Role-Based Middlewares (Challenge 2)
// ---------------------------------------------------------------------------
function getJwtSecret() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("JWT_SECRET environment variable is required in production.");
  }
  return "bharadei_dev_fallback_jwt_secret_change_me";
}

function signAccessToken(user) {
  return jwt.sign(
    {
      id: String(user._id || user.id || ""),
      email: user.email,
      name: user.name,
      role: user.role || "Customer",
    },
    getJwtSecret(),
    { expiresIn: "7d" }
  );
}

function sanitizeUser(doc) {
  return {
    id: String(doc._id),
    name: doc.name,
    email: doc.email,
    image: doc.image || "",
    role: doc.role || "Customer",
    phone: doc.phone || "",
    address: doc.address || "",
    createdAt: doc.createdAt,
  };
}

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 6) {
    return "Password must be at least 6 characters long.";
  }
  if (!/[A-Z]/.test(password)) {
    return "Password must include at least one uppercase letter.";
  }
  if (!/[a-z]/.test(password)) {
    return "Password must include at least one lowercase letter.";
  }
  return null;
}

async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: Missing Bearer access token.",
      });
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: Empty access token.",
      });
    }

    const decoded = jwt.verify(token, getJwtSecret());
    const users = await getCollection(COLLECTIONS.USERS);
    const dbUser = await users.findOne(
      { email: decoded.email.toLowerCase() },
      { projection: { password: 0 } }
    );

    if (!dbUser) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: User account no longer exists.",
      });
    }

    req.user = sanitizeUser(dbUser);
    return next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message:
        err.name === "TokenExpiredError"
          ? "Session expired. Please login again."
          : "Unauthorized: Invalid access token.",
    });
  }
}

function verifyRenter(req, res, next) {
  if (req.user?.role !== "Customer") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Customer (Renter) access required.",
    });
  }
  return next();
}

function verifyOwner(req, res, next) {
  if (req.user?.role !== "Owner") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Equipment Owner access required.",
    });
  }
  return next();
}

function verifyAdmin(req, res, next) {
  if (req.user?.role !== "Admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden: Admin access required.",
    });
  }
  return next();
}

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ---------------------------------------------------------------------------
// 4. Health & Auth Routes
// ---------------------------------------------------------------------------
async function ensureDbConnected() {
  if (database) return true;
  if (!process.env.MONGODB_URI) return false;
  try {
    const db = await connectDB();
    return Boolean(db);
  } catch {
    return false;
  }
}

app.get("/", async (_req, res) => {
  const dbConnected = await ensureDbConnected();

  res.status(200).json({
    success: true,
    name: "BharaDei.com API",
    message: "BharaDei.com Equipment Rental API is running.",
    dbConnected,
  });
});

app.get("/api/health", async (_req, res) => {
  const dbConnected = await ensureDbConnected();

  res.status(200).json({
    success: true,
    service: "BharaDei.com API",
    tagline: "Everything You Need, Ready to Rent.",
    dbConnected,
    timestamp: new Date().toISOString(),
  });
});

app.post(
  "/api/auth/register",
  asyncHandler(async (req, res) => {
    const { name, email, image = "", password } = req.body || {};

    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required.",
      });
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({ success: false, message: passwordError });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const users = await getCollection(COLLECTIONS.USERS);

    const existing = await users.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date();
    const newUserDoc = {
      name: name.trim(),
      email: normalizedEmail,
      image: typeof image === "string" ? image.trim() : "",
      password: hashedPassword,
      role: "Customer",
      phone: "",
      address: "",
      provider: "credentials",
      createdAt: now,
      updatedAt: now,
    };

    const result = await users.insertOne(newUserDoc);
    const createdUser = sanitizeUser({ ...newUserDoc, _id: result.insertedId });
    const token = signAccessToken(createdUser);

    return res.status(201).json({
      success: true,
      message: "Account registered successfully.",
      user: createdUser,
      token,
    });
  })
);

app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};

    if (!email?.trim() || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const users = await getCollection(COLLECTIONS.USERS);
    const userDoc = await users.findOne({ email: normalizedEmail });

    if (!userDoc || !userDoc.password) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const isMatch = await bcrypt.compare(password, userDoc.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const user = sanitizeUser(userDoc);
    const token = signAccessToken(user);

    return res.status(200).json({
      success: true,
      message: "Login successful.",
      user,
      token,
    });
  })
);

app.post(
  "/api/auth/oauth-sync",
  asyncHandler(async (req, res) => {
    const { name, email, image = "", provider = "google" } = req.body || {};

    if (!email?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Email is required to sync account.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const users = await getCollection(COLLECTIONS.USERS);
    const now = new Date();

    const updatedDoc = await users.findOneAndUpdate(
      { email: normalizedEmail },
      {
        $setOnInsert: {
          email: normalizedEmail,
          role: "Customer",
          phone: "",
          address: "",
          createdAt: now,
        },
        $set: {
          name: (name || normalizedEmail.split("@")[0]).trim(),
          ...(image ? { image: image.trim() } : {}),
          provider,
          updatedAt: now,
        },
      },
      { upsert: true, returnDocument: "after", projection: { password: 0 } }
    );

    const user = sanitizeUser(updatedDoc);
    const token = signAccessToken(user);

    return res.status(200).json({
      success: true,
      message: "Session synchronized.",
      user,
      token,
    });
  })
);

app.get(
  "/api/auth/me",
  verifyToken,
  asyncHandler(async (req, res) => {
    return res.status(200).json({
      success: true,
      user: req.user,
    });
  })
);

app.put(
  "/api/auth/profile",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { name, image, phone, address } = req.body || {};
    const users = await getCollection(COLLECTIONS.USERS);

    const updates = { updatedAt: new Date() };
    if (typeof name === "string" && name.trim()) updates.name = name.trim();
    if (typeof image === "string") updates.image = image.trim();
    if (typeof phone === "string") updates.phone = phone.trim();
    if (typeof address === "string") updates.address = address.trim();

    const updated = await users.findOneAndUpdate(
      { email: req.user.email },
      { $set: updates },
      { returnDocument: "after", projection: { password: 0 } }
    );

    if (!updated) {
      return res.status(404).json({
        success: false,
        message: "User profile not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully.",
      user: sanitizeUser(updated),
    });
  })
);

const DEFAULT_SEED_EQUIPMENT = [
  {
    name: "Sony Alpha A7 IV Mirrorless Cinema Kit",
    description:
      "Full-frame 33MP hybrid camera with 24-70mm f/2.8 GM II lens, dual batteries, and carbon tripod for commercial shoots.",
    category: "Photography Equipment",
    location: "Banani, Dhaka",
    rentalPrice: 3500,
    rentalType: "Daily",
    availableQuantity: 4,
    condition: "Like New",
    brand: "Sony",
    model: "ILCE-7M4",
    image:
      "https://images.unsplash.com/photo-1516035069371-29a1b244cc32?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Valid NID copy required upon pickup. Late return incurs 20% daily fee. Handle lens optics with care.",
    status: "Approved",
    ownerName: "Dhaka Lens Hub",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000101",
    rentalCount: 28,
  },
  {
    name: "Bosch GBH 2-26 Heavy Rotary Hammer Drill",
    description:
      "800W SDS-plus rotary hammer drill with chisel set and hard carrying case for concrete & renovation tasks.",
    category: "Construction Equipment",
    location: "Mirpur 10, Dhaka",
    rentalPrice: 950,
    rentalType: "Daily",
    availableQuantity: 7,
    condition: "Excellent",
    brand: "Bosch",
    model: "GBH 2-26 DRE",
    image:
      "https://images.unsplash.com/photo-1504148455328-c376907d081c?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Inspect chuck and bits before use. Return clean without concrete residue.",
    status: "Approved",
    ownerName: "BuildPro Rentals BD",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000102",
    rentalCount: 41,
  },
  {
    name: "Toyota HiAce 14-Seater Commercial Van",
    description:
      "Air-conditioned high-roof commuter van suitable for corporate travel, production crews, and inter-district logistics.",
    category: "Vehicles & Transportation",
    location: "Uttara Sector 7, Dhaka",
    rentalPrice: 28000,
    rentalType: "Weekly",
    availableQuantity: 2,
    condition: "Good",
    brand: "Toyota",
    model: "HiAce GL 2022",
    image:
      "https://images.unsplash.com/photo-1549317661-bd82c8e0f8e9?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Fuel excluded. Valid driving license required for self-drive or driver package available.",
    status: "Approved",
    ownerName: "MetroFleet Logistics",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000103",
    rentalCount: 19,
  },
  {
    name: "Kubota L4508 Agricultural Power Tractor",
    description:
      "45HP 4WD agricultural tractor with rotary tiller attachment for field preparation and seasonal harvesting.",
    category: "Agriculture Equipment",
    location: "Bogura Sadar, Bogura",
    rentalPrice: 6500,
    rentalType: "Daily",
    availableQuantity: 3,
    condition: "Good",
    brand: "Kubota",
    model: "L4508 4WD",
    image:
      "https://images.unsplash.com/photo-1530267981375-f0de937f5f13?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Diesel supplied by renter. Operator briefing provided at handover.",
    status: "Approved",
    ownerName: "AgroMach Bangladesh",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000104",
    rentalCount: 14,
  },
  {
    name: "JBL EON715 Event PA Sound & Mixer Rig",
    description:
      "Dual 15-inch powered PA speakers, 12-channel digital mixer, tripod stands, and 2 wireless UHF microphones.",
    category: "Event Equipment",
    location: "Dhanmondi 27, Dhaka",
    rentalPrice: 4800,
    rentalType: "Daily",
    availableQuantity: 5,
    condition: "Like New",
    brand: "JBL Professional",
    model: "EON715 Bundle",
    image:
      "https://images.unsplash.com/photo-1470225620780-dba8ba36b745?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Indoor or covered stage use only. Protect from rain and voltage spikes.",
    status: "Approved",
    ownerName: "Dhaka StageCraft",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000105",
    rentalCount: 33,
  },
  {
    name: "DJI Mavic 3 Pro Cine Enterprise Drone",
    description:
      "Triple-camera Hasselblad aerial cinema drone with RC Pro controller, ND filters, and 3 intelligent flight batteries.",
    category: "Electronics",
    location: "Gulshan 2, Dhaka",
    rentalPrice: 5500,
    rentalType: "Daily",
    availableQuantity: 3,
    condition: "Like New",
    brand: "DJI",
    model: "Mavic 3 Pro Cine",
    image:
      "https://images.unsplash.com/photo-1507582020474-9a35b7d455d9?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "CAAB flight compliance is renter responsibility. MicroSD card included.",
    status: "Approved",
    ownerName: "SkyView Media BD",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000106",
    rentalCount: 25,
  },
  {
    name: "Honda EU22i Silent Inverter Generator",
    description:
      "2200W ultra-quiet portable inverter generator ideal for outdoor film sets, pop-up booths, and backup power.",
    category: "Construction Equipment",
    location: "Chattogram GEC",
    rentalPrice: 14500,
    rentalType: "Weekly",
    availableQuantity: 4,
    condition: "Excellent",
    brand: "Honda",
    model: "EU22i",
    image:
      "https://images.unsplash.com/photo-1581092160607-ee22621dd758?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Use unleaded petrol only. Check oil indicator before every start.",
    status: "Approved",
    ownerName: "PortCity Power",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000107",
    rentalCount: 16,
  },
  {
    name: "Epson EB-L530U 5200-Lumen Laser Projector",
    description:
      "Full HD WUXGA laser projector with 120-inch tripod screen and HDMI wireless presenter for conferences.",
    category: "Electronics",
    location: "Sylhet Zindabazar",
    rentalPrice: 24000,
    rentalType: "Monthly",
    availableQuantity: 6,
    condition: "Excellent",
    brand: "Epson",
    model: "EB-L530U",
    image:
      "https://images.unsplash.com/photo-1517457373958-b7bdd4587205?auto=format&fit=crop&w=900&q=80",
    rentalTerms:
      "Do not unplug during cool-down fan cycle. Carry in padded flight case.",
    status: "Approved",
    ownerName: "Sylhet AV Solutions",
    ownerEmail: "owner@bharadei.com",
    ownerPhone: "+8801711000108",
    rentalCount: 12,
  },
];

const DEFAULT_SEED_REVIEWS = [
  {
    customerName: "Tanvir Ahmed",
    role: "Commercial Filmmaker, Dhaka",
    rating: 5,
    equipmentName: "Sony Alpha A7 IV Mirrorless Cinema Kit",
    comment:
      "Booked a Sony A7 IV kit for a 3-day agency shoot in Banani. Gear was spotless, batteries fully charged, and Stripe checkout took under a minute.",
    createdAt: new Date("2026-10-15T10:00:00Z"),
  },
  {
    customerName: "Nusrat Jahan",
    role: "Event Coordinator, Dhanmondi",
    rating: 5,
    equipmentName: "JBL EON715 Event PA Sound & Mixer Rig",
    comment:
      "Instead of buying pricey PA speakers for one seminar, we rented the JBL bundle at a fraction of the cost. Crystal clear audio and punctual handover.",
    createdAt: new Date("2026-10-22T14:30:00Z"),
  },
  {
    customerName: "Rafiqul Islam",
    role: "Civil Contractor, Mirpur",
    rating: 4,
    equipmentName: "Bosch GBH 2-26 Heavy Rotary Hammer Drill",
    comment:
      "Transparent daily pricing and verified owners saved our renovation team from buying extra heavy tools. Booking tracking in the dashboard is super clean.",
    createdAt: new Date("2026-11-02T09:15:00Z"),
  },
  {
    customerName: "Farhana Chowdhury",
    role: "Agri-Tech Lead, Bogura",
    rating: 5,
    equipmentName: "Kubota L4508 Agricultural Power Tractor",
    comment:
      "Finding reliable farm machinery with clear rental terms used to take days of phone calls. BharaDei.com made availability and booking effortless.",
    createdAt: new Date("2026-11-10T11:45:00Z"),
  },
];

const CORE_CATEGORIES = [
  "Construction Equipment",
  "Photography Equipment",
  "Vehicles & Transportation",
  "Agriculture Equipment",
  "Electronics",
  "Event Equipment",
];

async function seedInitialMarketplaceData(db) {
  try {
    const equipmentCol = db.collection(COLLECTIONS.EQUIPMENT);
    const reviewsCol = db.collection(COLLECTIONS.REVIEWS);

    const equipCount = await equipmentCol.countDocuments();
    if (equipCount === 0) {
      const now = Date.now();
      const docs = DEFAULT_SEED_EQUIPMENT.map((item, idx) => ({
        ...item,
        createdAt: new Date(now - idx * 86400000),
        updatedAt: new Date(now - idx * 86400000),
      }));
      await equipmentCol.insertMany(docs);
      console.log(`[Seed] Inserted ${docs.length} initial equipment listings.`);
    }

    const reviewCount = await reviewsCol.countDocuments();
    if (reviewCount === 0) {
      await reviewsCol.insertMany(DEFAULT_SEED_REVIEWS);
      console.log(`[Seed] Inserted ${DEFAULT_SEED_REVIEWS.length} initial reviews.`);
    }
  } catch (err) {
    console.warn("[Seed] Skipped seeding:", err.message);
  }
}

function serializeEquipment(doc) {
  return {
    id: String(doc._id || doc.id || ""),
    name: doc.name,
    description: doc.description,
    category: doc.category,
    location: doc.location,
    rentalPrice: Number(doc.rentalPrice || 0),
    rentalType: doc.rentalType || "Daily",
    availableQuantity: Number(doc.availableQuantity ?? 0),
    condition: doc.condition || "Good",
    brand: doc.brand || "",
    model: doc.model || "",
    image: doc.image || "",
    rentalTerms: doc.rentalTerms || "",
    status: doc.status || "Pending",
    ownerName: doc.ownerName || "Verified Owner",
    ownerEmail: doc.ownerEmail || "",
    ownerPhone: doc.ownerPhone || "",
    rentalCount: Number(doc.rentalCount || 0),
    createdAt: doc.createdAt || new Date(),
  };
}

function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ---------------------------------------------------------------------------
// 5. Public Home & Discovery Routes
// ---------------------------------------------------------------------------
app.get(
  "/api/equipment",
  asyncHandler(async (req, res) => {
    const {
      search = "",
      category = "",
      rentalType = "",
      minPrice = "",
      maxPrice = "",
      availability = "",
      sort = "recent",
      page = "1",
      limit = "6",
    } = req.query;

    const parsedPage = Math.max(1, parseInt(String(page), 10) || 1);
    const parsedLimit = Math.min(24, Math.max(1, parseInt(String(limit), 10) || 6));
    const trimmedSearch = String(search || "").trim();
    const trimmedCategory = String(category || "").trim();
    const trimmedRentalType = String(rentalType || "").trim();
    const minP = minPrice !== "" && !Number.isNaN(Number(minPrice)) ? Number(minPrice) : null;
    const maxP = maxPrice !== "" && !Number.isNaN(Number(maxPrice)) ? Number(maxPrice) : null;

    try {
      const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
      const query = { status: "Approved" };

      if (trimmedSearch) {
        const rx = new RegExp(escapeRegex(trimmedSearch), "i");
        query.$or = [
          { name: rx },
          { location: rx },
          { category: rx },
          { brand: rx },
        ];
      }

      if (trimmedCategory && trimmedCategory !== "All") {
        query.category = trimmedCategory;
      }

      if (trimmedRentalType && trimmedRentalType !== "All") {
        query.rentalType = trimmedRentalType;
      }

      if (minP !== null || maxP !== null) {
        query.rentalPrice = {};
        if (minP !== null) query.rentalPrice.$gte = minP;
        if (maxP !== null) query.rentalPrice.$lte = maxP;
      }

      if (availability === "available") {
        query.availableQuantity = { $gt: 0 };
      } else if (availability === "unavailable") {
        query.availableQuantity = { $lte: 0 };
      }

      let sortStage = { createdAt: -1 };
      if (sort === "price_asc") sortStage = { rentalPrice: 1, createdAt: -1 };
      else if (sort === "price_desc") sortStage = { rentalPrice: -1, createdAt: -1 };

      const total = await equipmentCol.countDocuments(query);
      const totalPages = Math.max(1, Math.ceil(total / parsedLimit));
      const safePage = Math.min(parsedPage, totalPages);

      const docs = await equipmentCol
        .find(query)
        .sort(sortStage)
        .skip((safePage - 1) * parsedLimit)
        .limit(parsedLimit)
        .toArray();

      return res.status(200).json({
        success: true,
        items: docs.map(serializeEquipment),
        pagination: {
          total,
          page: safePage,
          limit: parsedLimit,
          totalPages,
        },
      });
    } catch {
      // Fallback filtering/sorting/pagination if DB is offline
      let filtered = DEFAULT_SEED_EQUIPMENT.map((item, idx) =>
        serializeEquipment({
          ...item,
          id: `seed-${idx + 1}`,
          createdAt: new Date(Date.now() - idx * 86400000),
        })
      );

      if (trimmedSearch) {
        const lower = trimmedSearch.toLowerCase();
        filtered = filtered.filter(
          (i) =>
            i.name.toLowerCase().includes(lower) ||
            i.location.toLowerCase().includes(lower) ||
            i.category.toLowerCase().includes(lower) ||
            (i.brand || "").toLowerCase().includes(lower)
        );
      }

      if (trimmedCategory && trimmedCategory !== "All") {
        filtered = filtered.filter((i) => i.category === trimmedCategory);
      }
      if (trimmedRentalType && trimmedRentalType !== "All") {
        filtered = filtered.filter((i) => i.rentalType === trimmedRentalType);
      }
      if (minP !== null) {
        filtered = filtered.filter((i) => i.rentalPrice >= minP);
      }
      if (maxP !== null) {
        filtered = filtered.filter((i) => i.rentalPrice <= maxP);
      }
      if (availability === "available") {
        filtered = filtered.filter((i) => i.availableQuantity > 0);
      } else if (availability === "unavailable") {
        filtered = filtered.filter((i) => i.availableQuantity <= 0);
      }

      if (sort === "price_asc") {
        filtered.sort((a, b) => a.rentalPrice - b.rentalPrice);
      } else if (sort === "price_desc") {
        filtered.sort((a, b) => b.rentalPrice - a.rentalPrice);
      }

      const total = filtered.length;
      const totalPages = Math.max(1, Math.ceil(total / parsedLimit));
      const safePage = Math.min(parsedPage, totalPages);
      const start = (safePage - 1) * parsedLimit;

      return res.status(200).json({
        success: true,
        fallback: true,
        items: filtered.slice(start, start + parsedLimit),
        pagination: {
          total,
          page: safePage,
          limit: parsedLimit,
          totalPages,
        },
      });
    }
  })
);
app.get(
  "/api/equipment/featured",
  asyncHandler(async (_req, res) => {
    try {
      const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
      const docs = await equipmentCol
        .find({ status: "Approved" })
        .sort({ rentalCount: -1, createdAt: -1 })
        .limit(6)
        .toArray();

      return res.status(200).json({
        success: true,
        items: docs.map(serializeEquipment),
      });
    } catch {
      return res.status(200).json({
        success: true,
        fallback: true,
        items: DEFAULT_SEED_EQUIPMENT.slice(0, 6).map((item, idx) =>
          serializeEquipment({ ...item, id: `seed-${idx + 1}` })
        ),
      });
    }
  })
);

app.get(
  "/api/equipment/categories",
  asyncHandler(async (_req, res) => {
    try {
      const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
      const counts = await equipmentCol
        .aggregate([
          { $match: { status: "Approved" } },
          { $group: { _id: "$category", count: { $sum: 1 } } },
        ])
        .toArray();

      const countMap = new Map(counts.map((c) => [c._id, c.count]));
      const categories = CORE_CATEGORIES.map((name) => ({
        name,
        count: countMap.get(name) || 0,
      }));

      return res.status(200).json({ success: true, categories });
    } catch {
      const categories = CORE_CATEGORIES.map((name) => ({
        name,
        count: DEFAULT_SEED_EQUIPMENT.filter((e) => e.category === name).length,
      }));
      return res.status(200).json({ success: true, fallback: true, categories });
    }
  })
);

app.get(
  "/api/equipment/highlights",
  asyncHandler(async (_req, res) => {
    try {
      const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
      const [popularDocs, recentDocs] = await Promise.all([
        equipmentCol
          .find({ status: "Approved" })
          .sort({ rentalCount: -1 })
          .limit(4)
          .toArray(),
        equipmentCol
          .find({ status: "Approved" })
          .sort({ createdAt: -1 })
          .limit(4)
          .toArray(),
      ]);

      return res.status(200).json({
        success: true,
        popular: popularDocs.map(serializeEquipment),
        recent: recentDocs.map(serializeEquipment),
      });
    } catch {
      const mapped = DEFAULT_SEED_EQUIPMENT.map((item, idx) =>
        serializeEquipment({ ...item, id: `seed-${idx + 1}` })
      );
      return res.status(200).json({
        success: true,
        fallback: true,
        popular: [...mapped]
          .sort((a, b) => b.rentalCount - a.rentalCount)
          .slice(0, 4),
        recent: mapped.slice(0, 4),
      });
    }
  })
);

app.get(
  "/api/reviews",
  asyncHandler(async (_req, res) => {
    try {
      const reviewsCol = await getCollection(COLLECTIONS.REVIEWS);
      const docs = await reviewsCol
        .find({})
        .sort({ createdAt: -1 })
        .limit(6)
        .toArray();

      return res.status(200).json({
        success: true,
        reviews: docs.map((r) => ({
          id: String(r._id),
          customerName: r.customerName,
          role: r.role || "Verified Renter",
          rating: Number(r.rating || 5),
          equipmentName: r.equipmentName || "",
          comment: r.comment,
        })),
      });
    } catch {
      return res.status(200).json({
        success: true,
        fallback: true,
        reviews: DEFAULT_SEED_REVIEWS.map((r, idx) => ({
          id: `review-${idx + 1}`,
          ...r,
        })),
      });
    }
  })
);

function calculateRentalQuote(equipment, startDateStr, endDateStr, quantity) {
  const start = new Date(startDateStr);
  const end = new Date(endDateStr);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return { error: "Please provide valid start and end dates." };
  }
  if (end < start) {
    return { error: "Rental end date must be on or after the start date." };
  }

  const qty = Number(quantity);
  if (!Number.isInteger(qty) || qty < 1) {
    return { error: "Required quantity must be at least 1." };
  }
  if (qty > Number(equipment.availableQuantity || 0)) {
    return {
      error: `Only ${equipment.availableQuantity} unit(s) currently available.`,
    };
  }

  const diffDays = Math.ceil((end.getTime() - start.getTime()) / 86400000);
  const days = Math.max(1, diffDays);

  let billingUnits = days;
  if (equipment.rentalType === "Weekly") {
    billingUnits = Math.max(1, Math.ceil(days / 7));
  } else if (equipment.rentalType === "Monthly") {
    billingUnits = Math.max(1, Math.ceil(days / 30));
  }

  const unitPrice = Number(equipment.rentalPrice || 0);
  const totalAmount = billingUnits * unitPrice * qty;

  return {
    days,
    billingUnits,
    unitPrice,
    quantity: qty,
    rentalType: equipment.rentalType || "Daily",
    totalAmount,
  };
}

// ---------------------------------------------------------------------------
// 6. Equipment Details, Favorites & Booking Validation (Private Routes)
// ---------------------------------------------------------------------------
app.get(
  "/api/equipment/:id",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid equipment ID.",
      });
    }

    const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
    const doc = await equipmentCol.findOne({ _id: new ObjectId(id) });

    if (!doc) {
      return res.status(404).json({
        success: false,
        message: "Equipment listing not found.",
      });
    }

    if (
      doc.status !== "Approved" &&
      req.user.role !== "Admin" &&
      doc.ownerEmail !== req.user.email
    ) {
      return res.status(403).json({
        success: false,
        message: "This equipment listing is not publicly approved yet.",
      });
    }

    return res.status(200).json({
      success: true,
      equipment: serializeEquipment(doc),
    });
  })
);

app.post(
  "/api/bookings/validate",
  verifyToken,
  verifyRenter,
  asyncHandler(async (req, res) => {
    const {
      equipmentId,
      startDate,
      endDate,
      quantity,
      contactNumber,
      deliveryAddress,
    } = req.body || {};

    if (!ObjectId.isValid(equipmentId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid equipment ID.",
      });
    }
    if (!contactNumber?.trim() || !deliveryAddress?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Contact number and delivery address are required.",
      });
    }

    const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
    const equipment = await equipmentCol.findOne({
      _id: new ObjectId(equipmentId),
      status: "Approved",
    });

    if (!equipment) {
      return res.status(404).json({
        success: false,
        message: "Approved equipment listing not found.",
      });
    }

    const quote = calculateRentalQuote(equipment, startDate, endDate, quantity);
    if (quote.error) {
      return res.status(400).json({
        success: false,
        message: quote.error,
      });
    }

    return res.status(200).json({
      success: true,
      quote,
      equipment: serializeEquipment(equipment),
    });
  })
);

app.get(
  "/api/favorites",
  verifyToken,
  verifyRenter,
  asyncHandler(async (req, res) => {
    const favoritesCol = await getCollection(COLLECTIONS.FAVORITES);
    const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);

    const favDocs = await favoritesCol
      .find({ userEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();

    const objectIds = favDocs
      .map((f) => f.equipmentId)
      .filter((id) => ObjectId.isValid(id))
      .map((id) => new ObjectId(id));

    const equipDocs = objectIds.length
      ? await equipmentCol.find({ _id: { $in: objectIds } }).toArray()
      : [];
    const equipMap = new Map(equipDocs.map((e) => [String(e._id), serializeEquipment(e)]));

    const favorites = favDocs.map((f) => ({
      id: String(f._id),
      equipmentId: f.equipmentId,
      createdAt: f.createdAt,
      equipment: equipMap.get(f.equipmentId) || f.equipmentSnapshot || null,
    }));

    return res.status(200).json({
      success: true,
      favorites,
    });
  })
);

app.get(
  "/api/favorites/check/:equipmentId",
  verifyToken,
  asyncHandler(async (req, res) => {
    const { equipmentId } = req.params;
    const favoritesCol = await getCollection(COLLECTIONS.FAVORITES);
    const existing = await favoritesCol.findOne({
      userEmail: req.user.email,
      equipmentId,
    });

    return res.status(200).json({
      success: true,
      isFavorite: Boolean(existing),
    });
  })
);

app.post(
  "/api/favorites",
  verifyToken,
  verifyRenter,
  asyncHandler(async (req, res) => {
    const { equipmentId } = req.body || {};
    if (!ObjectId.isValid(equipmentId)) {
      return res.status(400).json({
        success: false,
        message: "Valid equipmentId is required.",
      });
    }

    const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
    const equipment = await equipmentCol.findOne({
      _id: new ObjectId(equipmentId),
    });
    if (!equipment) {
      return res.status(404).json({
        success: false,
        message: "Equipment not found.",
      });
    }

    const favoritesCol = await getCollection(COLLECTIONS.FAVORITES);
    const existing = await favoritesCol.findOne({
      userEmail: req.user.email,
      equipmentId,
    });

    if (existing) {
      return res.status(200).json({
        success: true,
        message: "Already in your favorites.",
        isFavorite: true,
      });
    }

    await favoritesCol.insertOne({
      userEmail: req.user.email,
      equipmentId,
      equipmentSnapshot: serializeEquipment(equipment),
      createdAt: new Date(),
    });

    return res.status(201).json({
      success: true,
      message: "Added to favorites.",
      isFavorite: true,
    });
  })
);

app.delete(
  "/api/favorites/:equipmentId",
  verifyToken,
  verifyRenter,
  asyncHandler(async (req, res) => {
    const { equipmentId } = req.params;
    const favoritesCol = await getCollection(COLLECTIONS.FAVORITES);
    await favoritesCol.deleteOne({
      userEmail: req.user.email,
      equipmentId,
    });

    return res.status(200).json({
      success: true,
      message: "Removed from favorites.",
      isFavorite: false,
    });
  })
);

// ---------------------------------------------------------------------------
// 7. Stripe Payment & Booking Confirmation Routes
// ---------------------------------------------------------------------------
function getClientOrigin(req) {
  const reqOrigin = req.headers.origin?.trim();
  if (reqOrigin && allowedOrigins.has(reqOrigin)) {
    return reqOrigin;
  }
  return (process.env.CLIENT_URL || "http://localhost:3000").replace(/\/+$/, "");
}

app.post(
  "/api/payments/create-checkout-session",
  verifyToken,
  verifyRenter,
  asyncHandler(async (req, res) => {
    if (!stripe) {
      return res.status(503).json({
        success: false,
        message: "Stripe payment gateway is not configured on the server.",
      });
    }

    const {
      equipmentId,
      startDate,
      endDate,
      quantity,
      contactNumber,
      deliveryAddress,
      notes = "",
    } = req.body || {};

    if (!ObjectId.isValid(equipmentId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid equipment ID.",
      });
    }
    if (!contactNumber?.trim() || !deliveryAddress?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Contact number and delivery address are required.",
      });
    }

    const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);
    const equipment = await equipmentCol.findOne({
      _id: new ObjectId(equipmentId),
      status: "Approved",
    });

    if (!equipment) {
      return res.status(404).json({
        success: false,
        message: "Approved equipment listing not found.",
      });
    }

    const quote = calculateRentalQuote(equipment, startDate, endDate, quantity);
    if (quote.error) {
      return res.status(400).json({
        success: false,
        message: quote.error,
      });
    }

    const bookingsCol = await getCollection(COLLECTIONS.BOOKINGS);
    const now = new Date();
    const bookingDoc = {
      customerId: req.user.id,
      customerName: req.user.name,
      customerEmail: req.user.email,
      ownerEmail: equipment.ownerEmail || "",
      ownerName: equipment.ownerName || "Verified Owner",
      equipmentId: String(equipment._id),
      equipmentName: equipment.name,
      equipmentCategory: equipment.category,
      equipmentImage: equipment.image || "",
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      days: quote.days,
      billingUnits: quote.billingUnits,
      rentalType: quote.rentalType,
      quantity: quote.quantity,
      totalAmount: quote.totalAmount,
      contactNumber: contactNumber.trim(),
      deliveryAddress: deliveryAddress.trim(),
      notes: typeof notes === "string" ? notes.trim() : "",
      paymentStatus: "Pending",
      bookingStatus: "Pending",
      bookingDate: now,
      createdAt: now,
      updatedAt: now,
    };

    const bookingInsert = await bookingsCol.insertOne(bookingDoc);
    const bookingId = String(bookingInsert.insertedId);
    const clientOrigin = getClientOrigin(req);

    try {
      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        customer_email: req.user.email,
        line_items: [
          {
            price_data: {
              currency: "bdt",
              product_data: {
                name: equipment.name,
                description: `${quote.quantity} unit(s) · ${quote.days} day(s) (${quote.rentalType})`,
                ...(equipment.image ? { images: [equipment.image] } : {}),
              },
              unit_amount: Math.round(quote.totalAmount * 100),
            },
            quantity: 1,
          },
        ],
        metadata: {
          bookingId,
          equipmentId: String(equipment._id),
          customerEmail: req.user.email,
        },
        success_url: `${clientOrigin}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${clientOrigin}/payment/cancel?booking_id=${bookingId}`,
      });

      await bookingsCol.updateOne(
        { _id: bookingInsert.insertedId },
        { $set: { stripeSessionId: session.id, updatedAt: new Date() } }
      );

      return res.status(200).json({
        success: true,
        sessionId: session.id,
        url: session.url,
        bookingId,
      });
    } catch (stripeErr) {
      await bookingsCol.deleteOne({ _id: bookingInsert.insertedId });
      throw stripeErr;
    }
  })
);

app.post(
  "/api/payments/verify",
  verifyToken,
  verifyRenter,
  asyncHandler(async (req, res) => {
    if (!stripe) {
      return res.status(503).json({
        success: false,
        message: "Stripe payment gateway is not configured.",
      });
    }

    const { sessionId } = req.body || {};
    if (!sessionId || typeof sessionId !== "string") {
      return res.status(400).json({
        success: false,
        message: "Valid Stripe sessionId is required.",
      });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (!session || session.payment_status !== "paid") {
      return res.status(400).json({
        success: false,
        message: "Stripe payment has not been completed yet.",
      });
    }

    const bookingId = session.metadata?.bookingId;
    if (!bookingId || !ObjectId.isValid(bookingId)) {
      return res.status(400).json({
        success: false,
        message: "Missing booking reference in Stripe session.",
      });
    }

    const bookingsCol = await getCollection(COLLECTIONS.BOOKINGS);
    const paymentsCol = await getCollection(COLLECTIONS.PAYMENTS);
    const equipmentCol = await getCollection(COLLECTIONS.EQUIPMENT);

    const booking = await bookingsCol.findOne({ _id: new ObjectId(bookingId) });
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: "Booking record not found.",
      });
    }
    if (booking.customerEmail !== req.user.email) {
      return res.status(403).json({
        success: false,
        message: "Forbidden: Booking belongs to another customer.",
      });
    }

    // Idempotent check if already verified
    const existingPayment = await paymentsCol.findOne({ sessionId: session.id });
    if (existingPayment) {
      return res.status(200).json({
        success: true,
        message: "Payment already verified.",
        booking: { id: String(booking._id), ...booking },
        payment: { id: String(existingPayment._id), ...existingPayment },
      });
    }

    const now = new Date();
    const transactionId = String(session.payment_intent || session.id);

    const paymentDoc = {
      sessionId: session.id,
      transactionId,
      bookingId: String(booking._id),
      equipmentId: booking.equipmentId,
      equipmentName: booking.equipmentName,
      customerEmail: booking.customerEmail,
      customerName: booking.customerName,
      ownerEmail: booking.ownerEmail || "",
      amount: Number(booking.totalAmount),
      currency: String(session.currency || "bdt").toUpperCase(),
      paymentStatus: "Paid",
      paymentMethod: "Stripe Checkout",
      paidAt: now,
      createdAt: now,
    };

    const paymentInsert = await paymentsCol.insertOne(paymentDoc);

    const updatedBooking = await bookingsCol.findOneAndUpdate(
      { _id: booking._id },
      {
        $set: {
          paymentStatus: "Paid",
          bookingStatus: "Confirmed",
          paymentIntentId: transactionId,
          paidAt: now,
          updatedAt: now,
        },
      },
      { returnDocument: "after" }
    );

    if (ObjectId.isValid(booking.equipmentId)) {
      await equipmentCol.updateOne(
        {
          _id: new ObjectId(booking.equipmentId),
          availableQuantity: { $gte: Number(booking.quantity || 1) },
        },
        {
          $inc: {
            availableQuantity: -Number(booking.quantity || 1),
            rentalCount: Number(booking.quantity || 1),
          },
          $set: { updatedAt: now },
        }
      );
    }

    return res.status(200).json({
      success: true,
      message: "Payment verified and booking confirmed!",
      booking: { id: String(updatedBooking._id), ...updatedBooking },
      payment: { id: String(paymentInsert.insertedId), ...paymentDoc },
    });
  })
);

app.post(
  "/api/payments/cancel",
  verifyToken,
  verifyRenter,
  asyncHandler(async (req, res) => {
    const { bookingId } = req.body || {};
    if (!bookingId || !ObjectId.isValid(bookingId)) {
      return res.status(200).json({ success: true, message: "Cancelled." });
    }

    const bookingsCol = await getCollection(COLLECTIONS.BOOKINGS);
    await bookingsCol.updateOne(
      {
        _id: new ObjectId(bookingId),
        customerEmail: req.user.email,
        paymentStatus: "Pending",
      },
      {
        $set: {
          paymentStatus: "Cancelled",
          bookingStatus: "Cancelled",
          updatedAt: new Date(),
        },
      }
    );

    return res.status(200).json({
      success: true,
      message: "Pending booking marked as cancelled.",
    });
  })
);

// ---------------------------------------------------------------------------
// 8. 404 & Global Error Handlers
// ---------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

app.use((err, req, res, _next) => {
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
  });
});

async function startServer() {
  app.listen(port, () => {
    console.log(`BharaDei.com server running at http://localhost:${port}`);
  });

  connectDB().catch((err) => {
    console.error("[DB] Initial MongoDB connection failed:", err.message);
  });
}

startServer();

export default app;
