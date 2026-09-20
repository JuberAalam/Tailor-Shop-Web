require("dotenv").config({ override: true });

const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");

const app = express();

const prod = process.env.NODE_ENV === "production";

if (prod) {
  app.set("trust proxy", 1);
}

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(express.json({ limit: "20kb" }));

/* =========================================================
   DATABASE
========================================================= */

const db = new Database("appointments.db");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT DEFAULT '',
    phone TEXT NOT NULL,
    service TEXT NOT NULL,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    message TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    appointment_id INTEGER NOT NULL,
    event TEXT NOT NULL,
    channel TEXT NOT NULL,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function columnExists(table, column) {
  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all();

  return columns.some((c) => c.name === column);
}

if (!columnExists("appointments", "email")) {
  db.exec(`
    ALTER TABLE appointments
    ADD COLUMN email TEXT DEFAULT ''
  `);
}

if (!columnExists("appointments", "updated_at")) {
  db.exec(`
    ALTER TABLE appointments
    ADD COLUMN updated_at TEXT
  `);

  db.exec(`
    UPDATE appointments
    SET updated_at = CURRENT_TIMESTAMP
    WHERE updated_at IS NULL
  `);
}

/* =========================================================
   ADMIN CONFIG
========================================================= */

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

console.log("ENV CHECK:");
console.log(
  "ADMIN_USERNAME:",
  ADMIN_USERNAME ? "OK" : "MISSING"
);

console.log(
  "ADMIN_PASSWORD:",
  ADMIN_PASSWORD
    ? `OK (${ADMIN_PASSWORD.length} characters)`
    : "MISSING"
);

console.log(
  "SESSION_SECRET:",
  SESSION_SECRET ? "OK" : "MISSING"
);

if (
  !ADMIN_USERNAME ||
  !ADMIN_PASSWORD ||
  !SESSION_SECRET ||
  ADMIN_PASSWORD.length < 12
) {
  console.error(
    "Set ADMIN_USERNAME, ADMIN_PASSWORD (12+ chars), and SESSION_SECRET in .env"
  );

  process.exit(1);
}

const adminPasswordHash = bcrypt.hashSync(
  ADMIN_PASSWORD,
  12
);

const isProduction =
  process.env.NODE_ENV === "production";

/* =========================================================
   SESSION
========================================================= */

app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.sqlite",
      dir: ".",
    }),

    name: "royal-stitch-session",

    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,

      sameSite: "lax",

      secure:
        isProduction &&
        process.env.USE_HTTPS === "true",

      maxAge: 2 * 60 * 60 * 1000,
    },
  })
);

/* =========================================================
   LOGIN RATE LIMIT
========================================================= */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,

  limit: 10,

  standardHeaders: true,

  legacyHeaders: false,

  message: {
    error:
      "Too many login attempts. Try again later.",
  },
});

/* =========================================================
   AUTH
========================================================= */

function auth(req, res, next) {
  if (
    req.session &&
    req.session.authenticated
  ) {
    return next();
  }

  if (req.path.startsWith("/api/")) {
    return res.status(401).json({
      error: "Authentication required",
    });
  }

  return res.redirect("/admin/login");
}

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  loginLimiter,
  (req, res, next) => {
    try {
      const { user, pass } = req.body || {};

      if (
        user !== ADMIN_USERNAME ||
        typeof pass !== "string" ||
        !bcrypt.compareSync(
          pass,
          adminPasswordHash
        )
      ) {
        return res.status(401).json({
          error:
            "Invalid username or password",
        });
      }

      req.session.regenerate((err) => {
        if (err) {
          return next(err);
        }

        req.session.authenticated = true;

        req.session.username =
          ADMIN_USERNAME;

        req.session.save((saveError) => {
          if (saveError) {
            return next(saveError);
          }

          return res.json({
            ok: true,
          });
        });
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  auth,
  (req, res) => {
    req.session.destroy((error) => {
      if (error) {
        return res.status(500).json({
          error: "Logout failed",
        });
      }

      res.clearCookie(
        "royal-stitch-session"
      );

      return res.json({
        ok: true,
      });
    });
  }
);

/* =========================================================
   EMAIL CONFIGURATION
========================================================= */

const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,

      port: Number(
        process.env.SMTP_PORT || 587
      ),

      secure:
        process.env.SMTP_SECURE === "true",

      auth: {
        user: process.env.SMTP_USER,

        pass: process.env.SMTP_PASS,
      },
    })
  : null;

const shopName =
  process.env.SHOP_NAME ||
  "Royal Stitch";

const adminEmail =
  process.env.ADMIN_EMAIL || "";

const mailFrom =
  process.env.MAIL_FROM ||
  process.env.SMTP_USER ||
  "";

console.log(
  "EMAIL SMTP:",
  mailer ? "CONFIGURED" : "NOT CONFIGURED"
);

console.log(
  "CUSTOMER EMAIL:",
  mailer
    ? "AVAILABLE"
    : "DISABLED"
);

/* =========================================================
   EMAIL CONTENT
========================================================= */

function formatAppointment(
  appointment
) {
  return `${shopName}

Customer: ${appointment.name}
Email: ${appointment.email || "Not provided"}
Phone: ${appointment.phone}
Service: ${appointment.service}
Date: ${appointment.date}
Time: ${appointment.time}
Status: ${appointment.status}

${
  appointment.message
    ? `Message: ${appointment.message}`
    : ""
}`;
}

function eventText(
  event,
  appointment
) {
  const labels = {
    new: "New appointment request",

    confirmed:
      "Appointment confirmed",

    rescheduled:
      "Appointment rescheduled",

    cancelled:
      "Appointment cancelled",

    completed:
      "Appointment completed",
  };

  const intro =
    labels[event] ||
    "Appointment update";

  return `${intro} — ${shopName}

${formatAppointment(appointment)}

Thank you for choosing ${shopName}.

Please contact us if you need assistance.`;
}

/* =========================================================
   NOTIFICATION LOG
========================================================= */

function logNotification(
  appointment,
  event,
  channel,
  recipient,
  status,
  error = ""
) {
  db.prepare(`
    INSERT INTO notification_log
    (
      appointment_id,
      event,
      channel,
      recipient,
      status,
      error
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    appointment.id,
    event,
    channel,
    recipient,
    status,
    error
  );
}

/* =========================================================
   SEND EMAIL
========================================================= */

async function sendEmail(
  appointment,
  event,
  recipient,
  subject
) {
  if (!mailer) {
    console.error(
      "EMAIL ERROR: SMTP is not configured."
    );

    logNotification(
      appointment,
      event,
      "email",
      recipient || "not-configured",
      "skipped",
      "SMTP configuration missing"
    );

    return;
  }

  if (!recipient) {
    console.error(
      `EMAIL ERROR: No recipient for appointment #${appointment.id}`
    );

    logNotification(
      appointment,
      event,
      "email",
      "no-recipient",
      "skipped",
      "No email address"
    );

    return;
  }

  if (!mailFrom) {
    console.error(
      "EMAIL ERROR: MAIL_FROM is missing."
    );

    logNotification(
      appointment,
      event,
      "email",
      recipient,
      "skipped",
      "MAIL_FROM missing"
    );

    return;
  }

  try {
    const info =
      await mailer.sendMail({
        from: mailFrom,

        to: recipient,

        subject: subject,

        text: eventText(
          event,
          appointment
        ),
      });

    console.log(
      `EMAIL SENT: ${event} -> ${recipient}`
    );

    console.log(
      "Message ID:",
      info.messageId
    );

    logNotification(
      appointment,
      event,
      "email",
      recipient,
      "sent"
    );
  } catch (error) {
    console.error(
      `EMAIL FAILED: ${event} -> ${recipient}`
    );

    console.error(
      "Email error:",
      error.message
    );

    logNotification(
      appointment,
      event,
      "email",
      recipient,
      "failed",
      error.message
    );
  }
}

/* =========================================================
   SEND NOTIFICATIONS
========================================================= */

async function notify(
  event,
  appointment
) {
  const tasks = [];

  console.log(
    `\nNotification event: ${event}`
  );

  console.log(
    `Appointment ID: ${appointment.id}`
  );

  console.log(
    `Customer email: ${
      appointment.email || "NONE"
    }`
  );

  /* ADMIN EMAIL */

  if (adminEmail) {
    let subject =
      `${shopName}: Appointment update`;

    if (event === "new") {
      subject =
        `${shopName}: New booking`;
    }

    if (event === "confirmed") {
      subject =
        `${shopName}: Appointment confirmed`;
    }

    if (event === "rescheduled") {
      subject =
        `${shopName}: Appointment rescheduled`;
    }

    if (event === "cancelled") {
      subject =
        `${shopName}: Appointment cancelled`;
    }

    if (event === "completed") {
      subject =
        `${shopName}: Appointment completed`;
    }

    tasks.push(
      sendEmail(
        appointment,
        event,
        adminEmail,
        subject
      )
    );
  }

  /* CUSTOMER EMAIL */

  if (appointment.email) {
    let customerSubject =
      `${shopName}: Appointment update`;

    if (event === "new") {
      customerSubject =
        `${shopName}: Appointment request received`;
    }

    if (event === "confirmed") {
      customerSubject =
        `${shopName}: Your appointment is confirmed`;
    }

    if (event === "rescheduled") {
      customerSubject =
        `${shopName}: Your appointment has been rescheduled`;
    }

    if (event === "cancelled") {
      customerSubject =
        `${shopName}: Your appointment has been cancelled`;
    }

    if (event === "completed") {
      customerSubject =
        `${shopName}: Your appointment is completed`;
    }

    tasks.push(
      sendEmail(
        appointment,
        event,
        appointment.email,
        customerSubject
      )
    );
  } else {
    console.log(
      `No customer email found for appointment #${appointment.id}`
    );
  }

  await Promise.allSettled(tasks);
}

/* =========================================================
   CREATE APPOINTMENT
========================================================= */

app.post(
  "/api/appointments",
  async (req, res) => {
    try {
      const {
        name,
        email = "",
        phone,
        service,
        date,
        time,
        message = "",
      } = req.body || {};

      if (
        !name ||
        !phone ||
        !service ||
        !date ||
        !time
      ) {
        return res.status(400).json({
          error:
            "Name, phone, service, date and time are required",
        });
      }

      const cleanName =
        String(name).trim();

      const cleanEmail =
        String(email).trim();

      const cleanPhone =
        String(phone).trim();

      const cleanService =
        String(service).trim();

      const cleanDate =
        String(date).trim();

      const cleanTime =
        String(time).trim();

      const cleanMessage =
        String(message).trim();

      if (cleanName.length < 2) {
        return res.status(400).json({
          error:
            "Please enter a valid name",
        });
      }

      if (cleanPhone.length < 5) {
        return res.status(400).json({
          error:
            "Please enter a valid phone number",
        });
      }

      if (cleanEmail) {
        const emailRegex =
          /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (
          !emailRegex.test(cleanEmail)
        ) {
          return res.status(400).json({
            error:
              "Please enter a valid email address",
          });
        }
      }

      const result = db
        .prepare(`
          INSERT INTO appointments
          (
            name,
            email,
            phone,
            service,
            date,
            time,
            message
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          cleanName,
          cleanEmail,
          cleanPhone,
          cleanService,
          cleanDate,
          cleanTime,
          cleanMessage
        );

      const appointment =
        db
          .prepare(
            "SELECT * FROM appointments WHERE id = ?"
          )
          .get(
            result.lastInsertRowid
          );

      res.json({
        ok: true,
        id: result.lastInsertRowid,
      });

      notify(
        "new",
        appointment
      ).catch((error) => {
        console.error(
          "Notification dispatch error:",
          error
        );
      });
    } catch (error) {
      console.error(
        "Create appointment error:",
        error
      );

      res.status(500).json({
        error:
          "Could not create appointment",
      });
    }
  }
);

/* =========================================================
   GET APPOINTMENTS
========================================================= */

app.get(
  "/api/appointments",
  auth,
  (req, res) => {
    res.set(
      "Cache-Control",
      "no-store"
    );

    const appointments =
      db
        .prepare(`
          SELECT *
          FROM appointments
          ORDER BY date ASC, time ASC, id DESC
        `)
        .all();

    res.json(appointments);
  }
);

/* =========================================================
   GET NOTIFICATION LOG
========================================================= */

app.get(
  "/api/notification-log",
  auth,
  (req, res) => {
    res.set(
      "Cache-Control",
      "no-store"
    );

    const logs =
      db
        .prepare(`
          SELECT *
          FROM notification_log
          ORDER BY id DESC
          LIMIT 200
        `)
        .all();

    res.json(logs);
  }
);

/* =========================================================
   UPDATE APPOINTMENT
========================================================= */

app.patch(
  "/api/appointments/:id",
  auth,
  async (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid appointment ID",
        });
      }

      const existing =
        db
          .prepare(
            "SELECT * FROM appointments WHERE id = ?"
          )
          .get(id);

      if (!existing) {
        return res.status(404).json({
          error:
            "Appointment not found",
        });
      }

      const {
        status,
        date,
        time,
      } = req.body || {};

      const allowedStatuses = [
        "new",
        "confirmed",
        "completed",
        "cancelled",
      ];

      if (
        status !== undefined &&
        !allowedStatuses.includes(
          status
        )
      ) {
        return res.status(400).json({
          error: "Invalid status",
        });
      }

      const nextDate =
        date !== undefined
          ? String(date).trim()
          : existing.date;

      const nextTime =
        time !== undefined
          ? String(time).trim()
          : existing.time;

      const nextStatus =
        status !== undefined
          ? status
          : existing.status;

      let event = null;

      if (
        nextDate !== existing.date ||
        nextTime !== existing.time
      ) {
        event = "rescheduled";
      } else if (
        nextStatus !== existing.status
      ) {
        event = nextStatus;
      }

      db.prepare(`
        UPDATE appointments
        SET
          status = ?,
          date = ?,
          time = ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(
        nextStatus,
        nextDate,
        nextTime,
        id
      );

      const updated =
        db
          .prepare(
            "SELECT * FROM appointments WHERE id = ?"
          )
          .get(id);

      res.json({
        ok: true,
        appointment: updated,
      });

      /*
       * IMPORTANT:
       * When admin clicks Done,
       * event becomes "completed".
       * notify() then sends email
       * to appointment.email.
       */

      if (event) {
        notify(
          event,
          updated
        ).catch((error) => {
          console.error(
            "Notification dispatch error:",
            error
          );
        });
      }
    } catch (error) {
      console.error(
        "Update appointment error:",
        error
      );

      res.status(500).json({
        error:
          "Could not update appointment",
      });
    }
  }
);

/* =========================================================
   DELETE APPOINTMENT
========================================================= */

app.delete(
  "/api/appointments/:id",
  auth,
  (req, res) => {
    try {
      const id = Number(
        req.params.id
      );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid appointment ID",
        });
      }

      const appointment =
        db
          .prepare(
            "SELECT * FROM appointments WHERE id = ?"
          )
          .get(id);

      if (!appointment) {
        return res.status(404).json({
          error:
            "Appointment not found",
        });
      }

      db.prepare(
        "DELETE FROM appointments WHERE id = ?"
      ).run(id);

      console.log(
        `Appointment #${id} deleted`
      );

      return res.json({
        ok: true,
        message:
          "Appointment deleted successfully",
      });
    } catch (error) {
      console.error(
        "Delete appointment error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not delete appointment",
      });
    }
  }
);

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================================================
   ADMIN
========================================================= */

app.get(
  "/admin",
  auth,
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "admin.html"
      )
    );
  }
);

/* =========================================================
   ADMIN LOGIN PAGE
========================================================= */

app.get(
  "/admin/login",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "login.html"
      )
    );
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(error);

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      error:
        "Internal server error",
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

const PORT = Number(
  process.env.PORT || 3000
);

app.listen(PORT, () => {
  console.log(
    `Royal Stitch server running on port ${PORT}`
  );

  console.log(
    `Environment: ${
      prod
        ? "production"
        : "development"
    }`
  );

  console.log(
    `Email notifications: ${
      mailer
        ? "enabled"
        : "disabled"
    }`
  );
});