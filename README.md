# Password Cracking Simulation & Defense System

A mini project demonstrating **Brute Force** and **Dictionary** attacks on SHA-256 hashed passwords, with a live Login/Defense simulation.

## Project Structure

```
password-cracking-project/
├── index.html   — Main UI (5 tabs)
├── style.css    — All styling
├── app.js       — All logic (SHA-256, attacks, defense)
└── README.md    — This file
```

## How to Run in VS Code

### Option 1 — Live Server (recommended)
1. Open VS Code
2. Install the **Live Server** extension (by Ritwick Dey)
3. Open the `password-cracking-project` folder in VS Code
4. Right-click `index.html` → **"Open with Live Server"**
5. Your browser opens at `http://127.0.0.1:5500`

### Option 2 — Any local web server
```bash
# Python 3
cd password-cracking-project
python -m http.server 5500
# then open http://localhost:5500
```

> **Note:** SHA-256 uses the browser's `window.crypto.subtle` API, which requires
> either `localhost` or `https://`. Opening `index.html` directly as a `file://`
> URL may block crypto on some browsers — use Live Server to avoid this.

---

## How to Use

### 1. Register tab
- Enter a username and password (max 5 characters).
- Or click a **Quick-fill** button to add a demo user instantly.
- The SHA-256 hash and salt are stored in the in-memory database.

### 2. Database tab
- View all registered users with their **salt** and full 64-char **SHA-256 hash**.
- Notice: the plaintext password is never shown here.

### 3. Brute Force tab
- Select a target user.
- Choose a charset (a–z, a–z+0–9, alphanumeric, or with symbols).
- Click **Start brute force** — every combination is hashed and compared.
- Short passwords (2–3 chars) crack in seconds; longer ones take much longer.

### 4. Dictionary Attack tab
- Select a target user.
- The attack tries each word in the built-in wordlist one by one.
- Passwords like `sun`, `pass`, `cat` are found immediately.
- Passwords like `z9#mK` or `abc7` may not be in the list at all.

### 5. Login tab
- **Defense layers** — toggle on/off:
  - Account lockout (locks after 3 failures)
  - Rate limiting (warns after 2 failures)
  - SHA-256 + salt (shows full hash comparison in the log)
  - Anomaly detection (flags repeated failures)
- Use the dropdown to pick a registered user, type a password guess, and click **Try login**.
- The terminal log shows the full SHA-256 comparison in real time.

---

## Key Concepts Demonstrated

| Concept | Where |
|---|---|
| SHA-256 hashing with salt | Register + Database tabs |
| Why salts prevent rainbow tables | Each user has a unique salt |
| Brute force exponential growth | Brute Force tab — watch keyspace |
| Dictionary attack speed vs brute force | Dictionary tab |
| Defense-in-depth | Login tab toggles |
| Hash comparison at login | Login tab with hashing defense ON |
