# ClickBites V3.3 Security Update

This release builds on the supplied ClickBites V3.x full-stack project and adds:

- Strong password + confirm-password validation.
- Mandatory SMS OTP after successful password authentication.
- Short-lived, device-bound login challenges.
- Password recovery requiring registered mobile + SMS OTP, with optional email reset artifact.
- Modular heuristic anti-fraud/risk engine for failed-login velocity, new IP/device, and unusual GPS movement.
- Security/risk event logging for authorized admin review.
- Browser GPS capture for login/profile security signals.
- Secure user location endpoint; exact location is not included in public shop/buyer serialization.
- Safer proxy trust configuration and configurable CORS origins.
- LAN-friendly frontend dev server (`0.0.0.0`) for phone testing.
- Existing `npm run server`, `npm run server:backend`, `npm run dev`, and `npm run dev:backend` scripts.

The risk layer is intentionally a transparent heuristic engine rather than a claim of a trained ML model. It is modular so a real ML service/model can replace or augment it later.

## Gmail-only authentication update

- Registration now requires **Full Name + Gmail + Password + Confirm Password** only.
- Mobile number is no longer required during registration.
- A 6-digit Gmail verification OTP is sent immediately after account creation.
- The registration flow opens a Gmail OTP verification screen with a resend option.
- Successful Gmail verification signs the user in automatically.
- Login now requires only **Gmail + Password** and does **not** show an OTP screen.
- Unverified accounts cannot log in; the UI can resend the registration verification OTP.
- Forgot Password continues to use Gmail OTP.
- Existing risk/GPS checks remain active on login.
- Existing accounts with legacy mobile numbers remain compatible; the new registration form does not ask for a mobile number.
