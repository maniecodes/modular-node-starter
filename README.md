# Modular Node Starter

> A production-ready, modular monolith backend built with **Express.js**, **TypeScript**, and **Prisma**. Ships with authentication, RBAC, audit logging, brute-force protection, OTP verification, and invite-based onboarding.

---

## Features

- **Modular Architecture** — Clean separation of concerns with feature modules (`auth`, `users`, `roles`, `access-control`), a core layer, and shared utilities.
- **Authentication** — JWT access + refresh token pair, refresh token rotation, and revocation. Secure logout invalidates the current refresh token.
- **OTP Verification** — Email and phone OTP flows for registration and password reset, with configurable expiry and resend support.
- **Role-Based Access Control (RBAC)** — Assign fine-grained `resource.action` permissions to roles; assign multiple roles per user. Middleware-level `authorize()` guard on every sensitive route.
- **Invite System** — Admins can invite users via email with pre-assigned roles; invitees complete registration through a secure accept-invite flow.
- **Brute-Force Protection** — PostgreSQL-backed login attempt tracker: 5 failures triggers a 15-minute lockout with advisory locking to prevent race conditions.
- **Audit Logging** — Structured NDJSON security events emitted to stdout (pipe to CloudWatch, Datadog, etc.) plus a database `audit_logs` table for role/permission changes.
- **Rate Limiting** — Separate, configurable limiters for auth and API routes.
- **Request Validation** — All inputs validated with [Zod](https://zod.dev) schemas via a reusable `validate` middleware.
- **Environment Validation** — Zod-parsed env config; the app exits on startup if any required variable is missing or malformed.
- **Email** — Nodemailer + Handlebars templates (Gmail transport pre-configured; swap freely).
- **Security Hardening** — Helmet headers, CORS, bcrypt password hashing (configurable rounds), and hashed refresh token storage.

---

## Tech Stack

| Layer      | Technology                                   |
| ---------- | -------------------------------------------- |
| Runtime    | Node.js (CommonJS)                           |
| Language   | TypeScript 6                                 |
| Framework  | Express.js 4                                 |
| ORM        | Prisma 7                                     |
| Database   | PostgreSQL (via `pg` + `@prisma/adapter-pg`) |
| Auth       | JWT (`jsonwebtoken`), bcryptjs               |
| Validation | Zod 4                                        |
| Email      | Nodemailer + Handlebars                      |
| Testing    | Jest + Supertest                             |
| Linting    | ESLint + Prettier                            |

---

## Project Structure

```
src/
├── app.ts                  # Express app setup (routes, middleware)
├── server.ts               # HTTP server entry point
├── common/                 # Shared constants, types, helpers, utils
├── core/                   # Cross-cutting concerns
│   ├── audit/              # Security events & audit log repository
│   ├── auth/               # JWT helpers, login protection, user context
│   ├── cache/              # In-memory user context cache
│   ├── config/             # Zod-validated environment config
│   ├── database/           # Prisma client singleton
│   ├── errors/             # AppError class & global error handler
│   ├── mail/               # Mail service + Handlebars templates
│   └── middleware/         # Auth, rate-limit, validate middleware
└── modules/
    ├── auth/               # Registration, login, OTP, password reset, invites
    ├── users/              # User profile management
    ├── roles/              # Role & permission CRUD + assignment
    └── access-control/     # authorize() guard, can() helper, permission keys
prisma/
├── schema.prisma
├── seed.ts
└── migrations/
```

---

## Getting Started

### Prerequisites

- Node.js ≥ 18
- PostgreSQL database
- A Gmail account (or any SMTP provider) for emails

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

Copy the example below to a `.env` file at the project root:

```env
NODE_ENV=development
PORT=3000

DATABASE_URL=postgresql://user:password@localhost:5432/mydb

APP_NAME="My App"

JWT_SECRET=your_jwt_secret_minimum_16_chars
JWT_EXPIRES_IN=7d
JWT_REFRESH_SECRET=your_refresh_secret_minimum_16_chars
JWT_REFRESH_EXPIRES_IN=30d

BCRYPT_ROUNDS=12
OTP_EXPIRES_MINUTES=10

# Optional — email delivery
GMAIL_USER=you@gmail.com
GMAIL_APP_PASSWORD=your_app_password
```

### 3. Run database migrations

```bash
npm run prisma:migrate
```

### 4. Seed the database

Seeds the default roles (`user`, `super_admin`) and permissions:

```bash
npm run db:seed
```

### 5. Start the development server

```bash
npm run dev
```

The server starts on `http://localhost:3000` (or the `PORT` you configured).

---

## API Reference

All endpoints are prefixed with `/api/v1`.

### Health

| Method | Endpoint  | Description    |
| ------ | --------- | -------------- |
| `GET`  | `/health` | Liveness check |

### Auth — `/api/v1/auth`

| Method | Endpoint           | Auth   | Description                               |
| ------ | ------------------ | ------ | ----------------------------------------- |
| `POST` | `/register`        | —      | Request registration OTP (email or phone) |
| `POST` | `/verify-otp`      | —      | Verify OTP and activate account           |
| `POST` | `/resend-otp`      | —      | Resend a new OTP                          |
| `POST` | `/login`           | —      | Login and receive access + refresh tokens |
| `POST` | `/refresh`         | —      | Exchange refresh token for new token pair |
| `POST` | `/logout`          | Bearer | Revoke the current refresh token          |
| `POST` | `/forgot-password` | —      | Send a password-reset OTP                 |
| `POST` | `/reset-password`  | —      | Reset password using the OTP token        |
| `POST` | `/accept-invite`   | —      | Accept an admin invite and set password   |

### Admin — `/api/v1/admin`

| Method | Endpoint       | Permission     | Description                           |
| ------ | -------------- | -------------- | ------------------------------------- |
| `POST` | `/invite-user` | `users.invite` | Invite a user with pre-assigned roles |

### Users — `/api/v1/users`

| Method   | Endpoint | Auth   | Description                         |
| -------- | -------- | ------ | ----------------------------------- |
| `GET`    | `/me`    | Bearer | Get the current user's profile      |
| `PATCH`  | `/me`    | Bearer | Update profile (name, email, phone) |
| `DELETE` | `/me`    | Bearer | Delete account                      |

### Roles — `/api/v1/roles`

| Method   | Endpoint                            | Permission     | Description                           |
| -------- | ----------------------------------- | -------------- | ------------------------------------- |
| `GET`    | `/`                                 | `roles.read`   | List all roles                        |
| `POST`   | `/`                                 | `roles.create` | Create a role                         |
| `GET`    | `/:id`                              | `roles.read`   | Get a role                            |
| `DELETE` | `/:id`                              | `roles.delete` | Delete a role                         |
| `GET`    | `/:id/permissions`                  | `roles.read`   | List permissions for a role           |
| `POST`   | `/:id/permissions`                  | `roles.update` | Assign a permission to a role         |
| `DELETE` | `/:id/permissions/:permissionId`    | `roles.update` | Revoke a permission from a role       |
| `POST`   | `/:id/users`                        | `roles.assign` | Assign a role to a user               |
| `DELETE` | `/:id/users/:userId`                | `roles.assign` | Revoke a role from a user             |
| `GET`    | `/users/:userId`                    | `roles.read`   | Get a user's full roles + permissions |
| `GET`    | `/users/:userId/roles`              | `roles.read`   | List a user's roles                   |
| `GET`    | `/users/:userId/has-role/:roleName` | `roles.read`   | Check if user has a role              |
| `GET`    | `/users/:userId/has-permission`     | `roles.read`   | Check if user has a permission        |

### Permissions — `/api/v1/permissions`

| Method   | Endpoint | Permission           | Description          |
| -------- | -------- | -------------------- | -------------------- |
| `GET`    | `/`      | `permissions.read`   | List all permissions |
| `POST`   | `/`      | `permissions.create` | Create a permission  |
| `DELETE` | `/:id`   | `permissions.delete` | Delete a permission  |

---

## Scripts

| Script                    | Description                                    |
| ------------------------- | ---------------------------------------------- |
| `npm run dev`             | Start dev server with hot-reload (`tsx watch`) |
| `npm run build`           | Compile TypeScript to `dist/`                  |
| `npm start`               | Run the compiled server                        |
| `npm test`                | Run all tests (serial)                         |
| `npm run test:watch`      | Run tests in watch mode                        |
| `npm run test:coverage`   | Run tests with coverage report                 |
| `npm run lint`            | Lint source files                              |
| `npm run lint:fix`        | Auto-fix lint issues                           |
| `npm run format`          | Format source with Prettier                    |
| `npm run prisma:migrate`  | Run pending migrations                         |
| `npm run prisma:generate` | Regenerate Prisma client                       |
| `npm run prisma:studio`   | Open Prisma Studio                             |
| `npm run db:seed`         | Seed default roles and permissions             |

---

## Security Notes

- Refresh tokens are stored as **hashed values** (`tokenHash`) — the raw token never touches the database.
- Refresh token **revocation** (`revokedAt`) is checked on every `/refresh` call; replayed tokens are rejected.
- Login brute-force protection uses a **PostgreSQL advisory lock** to prevent race conditions under concurrent requests.
- All environment variables are validated with Zod on startup. The server will **not start** with an invalid config.
- HTTP security headers are set by **Helmet**.

---

## License

MIT
