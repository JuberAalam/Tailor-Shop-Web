# Royal Stitch Secure Booking System v3

## New automated notifications
The system now supports automated notifications for:

- New appointment: admin + customer
- Confirmation: customer + admin
- Reschedule: customer + admin
- Cancellation: customer + admin

Channels:
- Email via SMTP using Nodemailer
- WhatsApp via Twilio WhatsApp API
- In-dashboard/browser notification for logged-in admins

Notifications are best-effort and logged in the `notification_log` SQLite table. Booking creation or admin updates still complete even if a provider is temporarily unavailable.

## Setup
1. Copy `.env.example` to `.env` or configure equivalent environment variables in your host.
2. Set `ADMIN_USERNAME`, `ADMIN_PASSWORD` (at least 12 characters), and `SESSION_SECRET`.
3. Configure SMTP values for email notifications.
4. Configure Twilio WhatsApp values for WhatsApp notifications. Customer phone numbers must be in international format, and Twilio/WhatsApp template or opt-in requirements may apply depending on the message and account setup.
5. Run:
   ```bash
   npm install
   npm start
   ```
6. Customer website: `http://localhost:3000`
7. Admin login: `http://localhost:3000/admin/login`

## Security and production checklist
- Use HTTPS and secure environment variables.
- Add CSRF protection before public launch.
- Use separate staff accounts and MFA for a multi-staff deployment.
- Use persistent hosting/storage for SQLite databases, or move to managed PostgreSQL.
- Verify customer consent and applicable WhatsApp messaging rules before sending automated messages.
- Test SMTP and Twilio credentials in a staging environment first.
