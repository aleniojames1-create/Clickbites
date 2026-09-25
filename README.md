<<<<<<< HEAD
# ClickBites Full-Stack

This project continues the supplied ClickBites Calbayog City frontend instead of replacing its visual language. The original masonry food-discovery layout, orange branding, filter bar, detail-card concept, and responsive behavior are retained while the hard-coded demo data is replaced by API-backed records.

## Requirements

- Node.js 22.16+ (the server uses Node's built-in `node:sqlite` API, so no native SQLite addon is required).
- npm

## Windows Command Prompt

1. Copy `.env.example` to `.env`.
2. Change `JWT_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`.
3. Run `npm install` (or `npm run setup` for automatic Windows setup).
4. Run `npm run seed:admin` when you want to create/update the admin account.
5. In CMD window 1, run `npm run server` to start the backend on `http://localhost:4000`.
6. In CMD window 2, run `npm run dev` to start the frontend. It uses port 5173 by default and automatically tries 5174 through 5199 if 5173 is already occupied.
7. Open the URL printed by the frontend CMD window.

You can still use `npm start` as a backend-only production-style command. For a VS Code-free launch, double-click `run-clickbites.bat`; it opens separate backend and frontend CMD windows. The frontend launcher no longer assumes port 5173 is free. Use `check-clickbites.bat` for diagnostics.

## Implemented backend areas

- Account registration with unique email/mobile, JWT authorization, strong password rules, profile editing, password changes, Gmail/SMTP email OTP login, Gmail/SMTP OTP password recovery, rate limiting and bcrypt password hashing. Login OTP challenges are short-lived and bound to the initiating device.
- User addresses, notifications, carts and paginated order history.
- Multiple shops per user, shop owner management, shop approval states, products, stock, product images, buyer history and shop statistics.
- Admin dashboard, user/shop/product/order/payment views, approval/disapproval/suspension, admin-created shops linked to an existing user, revenue reports, top-shop transaction report and audit logs.
- Server-side pagination, indexes, authorization checks, validation boundaries and JSON error handling. A modular heuristic risk engine scores failed-login velocity, new IP/device, and unusual GPS movement; high-risk logins are blocked and security events are recorded.
- Image uploads are stored outside the database; the database stores their URL/path.

## Payments

The payment layer supports a provider adapter pattern with PayMongo Checkout for GCash/PayMaya-style e-wallet checkout and Maya Checkout configuration. Provider credentials are read from `.env` and are never written to the database as wallet credentials. Orders are not marked paid from frontend redirect messages alone; the backend has a payment-verification endpoint and provider webhook path.

During development, `POST /api/payments/simulate/:id` can be used only when `NODE_ENV` is not `production`. This is a local testing helper and is intentionally unavailable in production.

## Authentication and fraud-risk setup

Registration requires Gmail verification by a one-time email OTP. Login uses Gmail + password only; there is no login OTP screen. Forgot-password recovery requires a Gmail/SMTP email OTP before the password can be changed. Passwords require at least 10 characters including uppercase, lowercase, number, and special character. In development, if SMTP is not configured, the OTP is printed to the backend CMD window as `[DEV EMAIL]`; do not use this fallback in production.

### Gmail / SMTP configuration
1. Turn on 2-Step Verification for the Gmail account that will send ClickBites mail.
2. Create a Google App Password for that account.
3. Copy `.env.example` to `.env`.
4. Set `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_USER` to the Gmail address, `SMTP_PASS` to the 16-character App Password, and `SMTP_FROM` to the sender address.
5. Restart `npm run server`.
6. Never commit `.env`, your App Password, JWT secret, or payment credentials.

The anti-fraud layer is a server-side heuristic risk engine, not a claim of trained AI. It combines failed-login velocity, IP changes, device changes, login velocity, and GPS distance from the user's previous successful locations. High-risk login attempts are blocked; medium/low risk attempts continue to the email OTP challenge. Browser GPS is permission-based and can be unavailable or spoofed, so it is only one security signal, not proof of identity.

The browser sends a random per-installation device ID and, when the browser grants permission, GPS latitude/longitude and accuracy. The server stores security-event location records and compares new locations against prior successful locations using a Haversine-distance heuristic. Exact location is not exposed in public shop/buyer views. For LAN testing, browser GPS permissions may require HTTPS; localhost is the most reliable development origin.

## Important production setup

- Configure SMTP for email delivery.
- Gmail/SMTP is the mandatory authentication and recovery OTP channel; mobile/SMS is not required for account registration or login.
- Add the official payment-provider webhook configuration and production credentials.
- Set `COOKIE_SECURE=true` when cookies are introduced behind HTTPS, and use HTTPS for all production traffic.
- Move upload storage to object storage/CDN for large-scale deployment.
- Rotate all secrets and remove the example development admin password before production.

## Validation

`npm run build` checks the required frontend/backend entry points. `npm test` runs the no-network SQLite/schema smoke tests. `npm run check` prints the local Windows/Node/npm/project state. `npm run setup` creates `.env` when missing, installs dependencies when needed, and runs the project checks.

## Main API groups

`/api/auth/*`, `/api/me`, `/api/addresses`, `/api/products`, `/api/shops`, `/api/my/shops/*`, `/api/cart/*`, `/api/orders/*`, `/api/payments/*`, `/api/notifications`, `/api/admin/*`, and `/api/health`.

### Payment webhook note
PayMongo webhook signature verification uses the provider's `Paymongo-Signature` header and endpoint signing secret; configure `PAYMONGO_WEBHOOK_SECRET` and keep the webhook endpoint publicly reachable over HTTPS for real provider callbacks. PayMongo does not deliver webhooks to localhost. Maya Checkout should likewise be configured with its server webhook endpoint and sandbox credentials.

## Repairing an older V3.0 copy

If `npm run server` reports `Missing script: "server"`, the `package.json` in that copy is older than the corrected full-stack package. From the project root, run:

```cmd
fix-clickbites.bat
```

The repair tool restores these scripts without replacing the whole project:

```cmd
npm run server
npm run dev
npm run check
npm test
npm run build
npm run seed:admin
```

If `server\\server.js` or the repair scripts are also missing, replace the old `clickbites-fullstack` folder with the latest package archive instead of copying only `package.json`.

### Simple Gmail Authentication Flow

1. **Register:** Full name + Gmail + password + confirm password. No mobile number.
2. **Verify:** ClickBites sends a 6-digit OTP to the Gmail address.
3. **Finish:** Enter the OTP once; successful verification signs the user in.
4. **Login:** Gmail + password only. There is no login OTP screen.
5. **Forgot password:** Gmail + recovery OTP + new password + confirm password.

For real Gmail delivery, configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` in `.env`. For Gmail, use a Google App Password rather than the normal Gmail password.
=======
# Clickbites
>>>>>>> 4fd4d2513c133fffc133c096aca4fca0ed8b531d
