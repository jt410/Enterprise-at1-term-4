"""Local web server for the school room booking system."""

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from threading import RLock
from typing import Dict, Iterable, Optional, Set
from urllib.parse import urlparse


ROOMS = ("Woodtech room", "Music room", "Middle music room", "CR1", "Library", "Gym")
DATA_FILE = Path(__file__).with_name("school_bookings.json")
PAGE_FILE = Path(__file__).with_name("index.html")
TEACHER_PIN = os.environ.get("SCHOOL_TEACHER_PIN", "teacher")


@dataclass
class Booking:
    booking_id: int
    room_id: str
    user_id: str
    start: datetime
    end: datetime
    active: bool = True


class BookingError(ValueError):
    """Raised when a booking cannot be made or changed."""


class BookingSystem:
    def __init__(self, teachers: Optional[Iterable[str]] = None, storage_path=DATA_FILE):
        self._teachers: Set[str] = set(teachers or ())
        self._bookings: Dict[int, Booking] = {}
        self._bans: Dict[str, datetime] = {}
        self._users = {}
        self._sessions = {}
        self._next_booking_id = 1
        self._lock = RLock()
        self._storage_path = Path(storage_path)
        self._load()

    @staticmethod
    def _parse_time(value):
        try:
            parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
        except ValueError as error:
            raise BookingError("Enter a valid date and time.") from error
        if not isinstance(parsed, datetime) or parsed.tzinfo is not None:
            raise BookingError("Use local date and time without a timezone.")
        return parsed

    def _load(self):
        if not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text(encoding="utf-8"))
            for item in data.get("bookings", []):
                booking = Booking(
                    item["booking_id"], item["room_id"], item["user_id"],
                    self._parse_time(item["start"]), self._parse_time(item["end"]),
                    item.get("active", True),
                )
                self._bookings[booking.booking_id] = booking
            self._next_booking_id = max(self._bookings, default=0) + 1
            self._bans = {
                name: self._parse_time(until)
                for name, until in data.get("bans", {}).items()
            }
            self._users = {
                key: {field: user[field] for field in ("name", "salt", "password_hash")}
                for key, user in data.get("users", {}).items()
            }
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise BookingError(f"Could not load booking data from {self._storage_path}.") from error

    def _save(self):
        data = {
            "bookings": [
                {**asdict(booking), "start": booking.start.isoformat(), "end": booking.end.isoformat()}
                for booking in self._bookings.values()
            ],
            "bans": {name: until.isoformat() for name, until in self._bans.items()},
            "users": self._users,
        }
        self._storage_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def _password_hash(password, salt):
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), 310_000
        ).hex()

    def register(self, name, password):
        name = name.strip()
        if not name or len(password) < 8:
            raise BookingError("Enter your name and a password of at least 8 characters.")
        key = name.casefold()
        with self._lock:
            if key in self._users:
                raise BookingError("An account already exists for that name.")
            salt = secrets.token_hex(16)
            self._users[key] = {
                "name": name,
                "salt": salt,
                "password_hash": self._password_hash(password, salt),
            }
            token = secrets.token_urlsafe(32)
            self._sessions[token] = key
            self._save()
            return token, {"name": name}

    def login(self, name, password):
        key = name.strip().casefold()
        with self._lock:
            user = self._users.get(key)
            if user is None or not hmac.compare_digest(
                self._password_hash(password, user["salt"]), user["password_hash"]
            ):
                raise BookingError("Name or password is incorrect.")
            token = secrets.token_urlsafe(32)
            self._sessions[token] = key
            return token, {"name": user["name"]}

    def user_for_session(self, token):
        with self._lock:
            user = self._users.get(self._sessions.get(token, ""))
            if user is None:
                return None
            return {"name": user["name"]}

    def logout(self, token):
        with self._lock:
            self._sessions.pop(token, None)

    def book(self, user_id, room_id, start, end, *, actor_id=None, override=False):
        user_id, room_id = user_id.strip(), room_id.strip()
        start, end = self._parse_time(start), self._parse_time(end)
        if not user_id or not room_id:
            raise BookingError("Enter your name and choose a room.")
        if room_id not in ROOMS:
            raise BookingError("Choose a room from the school room list.")
        if start <= datetime.now() or start >= end:
            raise BookingError("Choose a future start time and an end time after it.")

        actor_id = actor_id or user_id
        with self._lock:
            is_teacher = actor_id in self._teachers
            if override and not is_teacher:
                raise BookingError("Only teachers can override bookings.")
            if not is_teacher and self._bans.get(user_id.casefold(), datetime.min) > start:
                raise BookingError("This person is temporarily banned from booking.")

            room_conflicts = [
                booking for booking in self._bookings.values()
                if booking.active and booking.room_id == room_id
                and start < booking.end and booking.start < end
            ]
            if room_conflicts and not override:
                raise BookingError(f"{room_id} is already booked for that time.")

            if not override:
                for booking in self._bookings.values():
                    if booking.active and booking.user_id.casefold() == user_id.casefold():
                        if booking.start <= end and start <= booking.end:
                            raise BookingError("One person cannot make overlapping or consecutive bookings.")

            for booking in room_conflicts:
                booking.active = False
            booking = Booking(self._next_booking_id, room_id, user_id, start, end)
            self._bookings[booking.booking_id] = booking
            self._next_booking_id += 1
            self._save()
            return booking, room_conflicts

    def cancel_booking(self, booking_id, *, actor_id):
        with self._lock:
            booking = self._bookings.get(booking_id)
            if booking is None or not booking.active:
                raise BookingError("That booking is no longer active.")
            if actor_id != booking.user_id and actor_id not in self._teachers:
                raise BookingError("Only the booking owner or a teacher can cancel it.")
            booking.active = False
            self._save()

    def ban_user(self, teacher_id, user_id, until):
        until = self._parse_time(until)
        user_id = user_id.strip()
        with self._lock:
            if teacher_id not in self._teachers:
                raise BookingError("Only teachers can ban people.")
            if not user_id or until <= datetime.now():
                raise BookingError("Enter a name and a future ban expiry.")
            self._bans[user_id.casefold()] = until
            self._save()

    def unban_user(self, teacher_id, user_id):
        with self._lock:
            if teacher_id not in self._teachers:
                raise BookingError("Only teachers can remove bans.")
            self._bans.pop(user_id.strip().casefold(), None)
            self._save()

    def list_bookings(self):
        with self._lock:
            return sorted(
                (b for b in self._bookings.values() if b.active),
                key=lambda booking: (booking.start, booking.room_id),
            )


SYSTEM = BookingSystem(teachers={"teacher"})


class BookingHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, value, cookie=None):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _session_token(self):
        cookies = SimpleCookie()
        cookies.load(self.headers.get("Cookie", ""))
        session = cookies.get("qhhs_session")
        return session.value if session else ""

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    @staticmethod
    def _booking_data(booking):
        return {
            "id": booking.booking_id,
            "room": booking.room_id,
            "name": booking.user_id,
            "start": booking.start.isoformat(),
            "end": booking.end.isoformat(),
        }

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            try:
                body = PAGE_FILE.read_bytes()
            except OSError:
                self.send_error(404, "Website file not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/rooms":
            self._send_json(200, {"rooms": ROOMS})
        elif path == "/api/bookings":
            self._send_json(200, {"bookings": [self._booking_data(b) for b in SYSTEM.list_bookings()]})
        elif path == "/api/me":
            user = SYSTEM.user_for_session(self._session_token())
            self._send_json(200 if user else 401, {"user": user})
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            data = self._read_json()
            path = urlparse(self.path).path
            if path == "/api/register":
                token, user = SYSTEM.register(
                    data.get("name", ""), data.get("password", "")
                )
                self._send_json(201, {"user": user}, f"qhhs_session={token}; Path=/; HttpOnly; SameSite=Lax")
                return
            if path == "/api/login":
                token, user = SYSTEM.login(data.get("name", ""), data.get("password", ""))
                self._send_json(200, {"user": user}, f"qhhs_session={token}; Path=/; HttpOnly; SameSite=Lax")
                return
            if path == "/api/logout":
                SYSTEM.logout(self._session_token())
                self._send_json(200, {"ok": True}, "qhhs_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
                return

            is_teacher = hmac.compare_digest(str(data.get("teacher_pin", "")), TEACHER_PIN)
            user = SYSTEM.user_for_session(self._session_token())
            if path in ("/api/bookings", "/api/bookings/cancel") and not user:
                self._send_json(401, {"error": "Sign in to continue."})
                return

            if path == "/api/bookings":
                booking, replaced = SYSTEM.book(
                    user["name"], data.get("room", ""),
                    data.get("start", ""), data.get("end", ""),
                    actor_id="teacher" if is_teacher else user["name"],
                    override=bool(data.get("override")),
                )
                self._send_json(201, {
                    "booking": self._booking_data(booking),
                    "replaced": [self._booking_data(b) for b in replaced],
                })
            elif path == "/api/bookings/cancel":
                SYSTEM.cancel_booking(
                    int(data.get("id", 0)),
                    actor_id="teacher" if is_teacher else user["name"],
                )
                self._send_json(200, {"ok": True})
            elif path == "/api/teacher/ban":
                if not is_teacher:
                    raise BookingError("Enter the correct teacher PIN.")
                SYSTEM.ban_user("teacher", data.get("name", ""), data.get("until", ""))
                self._send_json(200, {"ok": True})
            elif path == "/api/teacher/unban":
                if not is_teacher:
                    raise BookingError("Enter the correct teacher PIN.")
                SYSTEM.unban_user("teacher", data.get("name", ""))
                self._send_json(200, {"ok": True})
            else:
                self.send_error(404)
        except (BookingError, ValueError, TypeError, json.JSONDecodeError) as error:
            self._send_json(400, {"error": str(error) or "Invalid request."})

def main():
    address = ("0.0.0.0", int(os.environ.get("PORT", "8000")))
    server = ThreadingHTTPServer(address, BookingHandler)
    print(f"QHHS Booking running at http://localhost:{address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()