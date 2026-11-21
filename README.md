# BharaDei.com — Backend API

**BharaDei.com** (*Everything You Need, Ready to Rent.*) is Bangladesh's smart equipment rental marketplace connecting equipment owners with customers across cameras, power tools, construction machinery, vehicles, agriculture gear, electronics, and event equipment.

This repository contains the **Express 5 + MongoDB** REST API server powering authentication, role-based access control (RBAC), equipment discovery, rental bookings, Stripe payments, and dashboard analytics.

---

## Live API URL

- **Backend Live URL:** [https://bhara-dei-com-backend.vercel.app](https://bhara-dei-com-backend.vercel.app)
- **Frontend Live URL:** [https://bharadei-com-frontend.vercel.app](https://bharadei-com-frontend.vercel.app)
- **Health Check:** `GET /api/health`

---

## Purpose

The BharaDei.com backend provides a secure, production-ready API layer for:
- Managing users and issuing JWT tokens across **Customer**, **Owner**, and **Admin** roles.
- Serving server-side search, multi-filter queries, sorting, and pagination on equipment listings.
- Validating rental date ranges, stock availability, and dynamic pricing.
- Processing **Stripe Checkout** payments and recording verified transactions in MongoDB.
- Calculating live platform and owner analytics, alongside automated booking lifecycle updates.

---

## Key Features

- **JWT Authentication & Role-Based Access Control (RBAC):**
  - Email/password registration & login (`bcryptjs`) + Google/BetterAuth session sync (`Customer` default role).
  - Custom Express middlewares: `verifyToken`, `verifyRenter`, `verifyOwner`, and `verifyAdmin`.
- **Server-Side Search, Filtering, Sorting & Pagination:**
  - `GET /api/equipment` supports search by name, location, category, and brand; filters by category, rental type (`Daily`, `Weekly`, `Monthly`), price range, and availability; sorting (`recent`, `price_asc`, `price_desc`); and pagination.
- **Equipment, Favorites & Booking Validation:**
  - Public home highlights (`/featured`, `/categories`, `/highlights`, `/reviews`), private equipment details (`/api/equipment/:id`), Customer favorites CRUD (`/api/favorites`), and booking quote validation (`/api/bookings/validate`).
- **Stripe Checkout & Payments Recording:**
  - Secure Stripe session creation, payment verification, atomic booking persistence, and `payments` collection logging.
- **Owner & Admin Analytics + Moderation:**
  - Owner equipment CRUD, rental tracking, and earnings analytics; Admin user role management, equipment approval/rejection, and platform-wide revenue/monthly booking metrics.
- **Automated Lifecycle & Notifications (Bonus):**
  - `node-cron` scheduled status updates after rental end dates and optional `nodemailer` completion notifications.

---

## NPM Packages Used

### Dependencies
| Package | Version | Purpose |
| --- | --- | --- |
| `express` | `^5.3.0` | Web framework & REST API routing |
| `mongodb` | `^7.9.0` | Official MongoDB Node.js driver |
| `cors` | `^2.8.6` | Origin-whitelisted Cross-Origin Resource Sharing |
| `dotenv` | `^18.0.10` | Environment variable management |
| `jsonwebtoken` | `^9.0.3` | JWT signing and verification |
| `bcryptjs` | `^3.0.3` | Password hashing and verification |
| `stripe` | `^23.1.0` | Stripe Checkout & payment verification |
| `node-cron` | `^4.6.0` | Scheduled automated booking status updates |
| `nodemailer` | `^10.6.0` | Optional automated booking email notifications |

### Dev Dependencies
| Package | Version | Purpose |
| --- | --- | --- |
| `nodemon` | `^3.1.14` | Auto-reload development server |

---

## Environment Variables

Create a `backend/.env` file based on `.env.example` (never commit `.env`):

```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
DB_NAME=bharadei
JWT_SECRET=your_strong_random_jwt_secret
CLIENT_URL=http://localhost:3000
ALLOWED_ORIGINS=http://localhost:3000
STRIPE_SECRET_KEY=your_stripe_secret_key
```

---

## Getting Started Locally

```bash
npm install
npm run dev
```

For production:

```bash
npm start
```
