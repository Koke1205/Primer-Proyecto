import argparse
from collections import defaultdict, deque
import hashlib
import os
import re
import secrets
import smtplib
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from getpass import getpass
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./casino.db")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Configura SECRET_KEY en el archivo .env antes de iniciar el servidor.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
EMAIL_VERIFICATION_MINUTES = 30
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_MINUTES = 15
INITIAL_BALANCE = 150_000
API_PREFIX = "/api/v1"
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5500").rstrip("/")


def db_utc_now() -> datetime:
    # SQL DateTime columns store UTC without timezone metadata.
    return datetime.now(timezone.utc).replace(tzinfo=None)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_rate_lock = threading.Lock()
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(254), unique=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    balance = Column(Integer, default=INITIAL_BALANCE, nullable=False)
    role = Column(String(20), default="player", nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    verification_token_hash = Column(String(64), nullable=True)
    verification_expires_at = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    free_spins = Column(Integer, default=0, nullable=False)
    free_spin_bet = Column(Integer, default=200, nullable=False)
    free_spin_multiplier = Column(Integer, default=1, nullable=False)


class VaultLogDB(Base):
    __tablename__ = "vault_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    game_name = Column(String(50), default="Gran Fortuna", nullable=False)
    bet_amount = Column(Integer, nullable=False)
    payout_amount = Column(Integer, nullable=False)
    ggr = Column(Integer, nullable=False)
    tax_sii = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=db_utc_now, nullable=False)


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    migrations = {
        "email": "VARCHAR(254) NULL",
        "role": "VARCHAR(20) NOT NULL DEFAULT 'player'",
        "email_verified": "BOOLEAN NOT NULL DEFAULT FALSE",
        "verification_token_hash": "VARCHAR(64) NULL",
        "verification_expires_at": "DATETIME NULL",
        "failed_login_attempts": "INTEGER NOT NULL DEFAULT 0",
        "locked_until": "DATETIME NULL",
        "free_spins": "INTEGER NOT NULL DEFAULT 0",
        "free_spin_bet": "INTEGER NOT NULL DEFAULT 200",
        "free_spin_multiplier": "INTEGER NOT NULL DEFAULT 1",
    }
    with engine.begin() as connection:
        for column, definition in migrations.items():
            if column not in user_columns:
                connection.execute(text(f"ALTER TABLE users ADD COLUMN {column} {definition}"))
        indexes = {index["name"] for index in inspect(connection).get_indexes("users")}
        if "ix_users_email" not in indexes:
            connection.execute(text("CREATE UNIQUE INDEX ix_users_email ON users (email)"))
        vault_columns = {column["name"] for column in inspect(connection).get_columns("vault_logs")}
        if "game_name" not in vault_columns:
            connection.execute(
                text("ALTER TABLE vault_logs ADD COLUMN game_name VARCHAR(50) NOT NULL DEFAULT 'Gran Fortuna'")
            )
        vault_indexes = {index["name"] for index in inspect(connection).get_indexes("vault_logs")}
        if "ix_vault_logs_user_id" not in vault_indexes:
            connection.execute(text("CREATE INDEX ix_vault_logs_user_id ON vault_logs (user_id)"))


initialize_database()


class UserRegister(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(..., min_length=12, max_length=72)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Ingresa un correo válido.")
        return value

    @field_validator("password")
    @classmethod
    def require_password_complexity(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("La contraseña no puede superar 72 bytes.")
        if not re.search(r"[a-z]", value) or not re.search(r"[A-Z]", value) or not re.search(r"\d", value):
            raise ValueError("Usa al menos una mayúscula, una minúscula y un número.")
        return value


class UserLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=72)


class VerifyEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(..., min_length=20, max_length=200)


class GamePlayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    game_type: str = Field(..., pattern="^(slot|table)$")
    game_name: str = Field(..., pattern="^(Gran Fortuna|Abismo de Perlas|Fortuna China)$")
    bet_amount: int = Field(..., ge=200, le=500_000)


app = FastAPI(title="Gran Fortuna Casino API", version="3.0.0")
allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def enforce_rate_limit(request: Request, action: str, limit: int, window_seconds: int) -> None:
    client_ip = request.client.host if request.client else "unknown"
    key = f"{action}:{client_ip}"
    now = time.monotonic()
    with _rate_lock:
        if len(_rate_buckets) > 10_000:
            expired_keys = [
                bucket_key
                for bucket_key, timestamps in _rate_buckets.items()
                if not timestamps or timestamps[-1] <= now - window_seconds
            ]
            for bucket_key in expired_keys:
                _rate_buckets.pop(bucket_key, None)
        timestamps = _rate_buckets[key]
        while timestamps and timestamps[0] <= now - window_seconds:
            timestamps.popleft()
        if len(timestamps) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Demasiados intentos. Espera antes de volver a intentarlo.",
            )
        timestamps.append(now)


def create_access_token(user: UserDB) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user.id),
            "iat": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "jti": secrets.token_urlsafe(16),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> UserDB:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sesión inválida o vencida.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not authorization or not authorization.startswith("Bearer "):
        raise credentials_error
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        subject = payload.get("sub")
        user_id = int(subject)
    except (JWTError, TypeError, ValueError):
        raise credentials_error
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if user is None:
        raise credentials_error
    if user.role != "owner" and not user.email_verified:
        raise credentials_error
    return user


def user_response(user: UserDB) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "balance": user.balance,
        "unlimited_credits": user.role == "owner",
        "free_spins": user.free_spins,
        "free_spin_multiplier": user.free_spin_multiplier,
    }


def smtp_configured() -> bool:
    return all(os.getenv(name) for name in ("SMTP_HOST", "SMTP_FROM"))


def send_verification_email(email: str, token: str) -> None:
    host = os.getenv("SMTP_HOST")
    sender = os.getenv("SMTP_FROM")
    if not host or not sender:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El registro está temporalmente deshabilitado: falta configurar el envío seguro de correo.",
        )
    port = int(os.getenv("SMTP_PORT", "587"))
    message = EmailMessage()
    message["Subject"] = "Verifica tu correo · Gran Fortuna"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        "Para activar tu cuenta, abre este enlace antes de 30 minutos:\n"
        f"{FRONTEND_URL}/auth.html?verify={token}\n\n"
        "Si no solicitaste esta cuenta, ignora este mensaje."
    )
    context = ssl.create_default_context()
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=15) as server:
            if username:
                server.login(username, password or "")
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if username:
                server.login(username, password or "")
            server.send_message(message)


@app.post(f"{API_PREFIX}/auth/register", status_code=status.HTTP_202_ACCEPTED)
def register(request: Request, user_data: UserRegister, db: Session = Depends(get_db)):
    enforce_rate_limit(request, "register", limit=5, window_seconds=3600)
    if not smtp_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El registro está temporalmente deshabilitado: el correo de verificación no está configurado.",
        )
    if db.query(UserDB).filter(
        (UserDB.username == user_data.username) | (UserDB.email == user_data.email)
    ).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No se pudo crear la cuenta con esos datos.",
        )
    raw_token = secrets.token_urlsafe(32)
    user = UserDB(
        username=user_data.username,
        email=user_data.email,
        hashed_password=pwd_context.hash(user_data.password),
        balance=INITIAL_BALANCE,
        role="player",
        email_verified=False,
        verification_token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        verification_expires_at=db_utc_now() + timedelta(minutes=EMAIL_VERIFICATION_MINUTES),
    )
    try:
        send_verification_email(user.email, raw_token)
        db.add(user)
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except (smtplib.SMTPException, OSError, ValueError) as error:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No se pudo enviar el correo de verificación. Intenta nuevamente más tarde.",
        ) from error
    except Exception:
        db.rollback()
        raise
    return {"message": "Revisa tu correo para verificar la cuenta antes de iniciar sesión."}


@app.post(f"{API_PREFIX}/auth/verify-email")
def verify_email(request: Request, verification: VerifyEmailRequest, db: Session = Depends(get_db)):
    enforce_rate_limit(request, "verify-email", limit=10, window_seconds=3600)
    token_hash = hashlib.sha256(verification.token.encode()).hexdigest()
    user = (
        db.query(UserDB)
        .filter(
            UserDB.verification_token_hash == token_hash,
            UserDB.email_verified.is_(False),
        )
        .first()
    )
    if user is None or user.verification_expires_at is None:
        raise HTTPException(status_code=400, detail="El enlace de verificación no es válido.")
    if user.verification_expires_at < db_utc_now():
        raise HTTPException(status_code=400, detail="El enlace venció. Registra la cuenta nuevamente.")
    user.email_verified = True
    user.verification_token_hash = None
    user.verification_expires_at = None
    db.commit()
    return {"message": "Correo verificado. Ya puedes iniciar sesión."}


@app.post(f"{API_PREFIX}/auth/login")
def login(request: Request, user_data: UserLogin, db: Session = Depends(get_db)):
    enforce_rate_limit(request, "login", limit=20, window_seconds=900)
    user = db.query(UserDB).filter(UserDB.username == user_data.username).first()
    if user is not None and user.locked_until and user.locked_until > db_utc_now():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Inicio de sesión temporalmente bloqueado. Intenta más tarde.",
        )
    encoded_password = user_data.password.encode("utf-8")
    password_valid = False
    if len(encoded_password) <= 72:
        if user is not None:
            password_valid = pwd_context.verify(user_data.password, user.hashed_password)
        else:
            pwd_context.dummy_verify(user_data.password)
    if user is None or not password_valid:
        if user is not None:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= LOGIN_MAX_FAILURES:
                user.failed_login_attempts = 0
                user.locked_until = db_utc_now() + timedelta(minutes=LOGIN_LOCK_MINUTES)
            db.commit()
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos.")
    if user.role != "owner" and not user.email_verified:
        raise HTTPException(status_code=403, detail="Verifica tu correo antes de iniciar sesión.")
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "user": user_response(user),
    }


@app.get(f"{API_PREFIX}/auth/me")
def current_user_profile(current_user: UserDB = Depends(get_current_user)):
    return user_response(current_user)


def _choose_symbol(rng: secrets.SystemRandom, game_name: str) -> int:
    if game_name == "Fortuna China":
        return rng.choices(range(8), weights=[8, 13, 17, 19, 18, 15, 10, 7], k=1)[0]
    return rng.choices(range(7), weights=[28, 24, 20, 15, 8, 4, 2], k=1)[0]


def _evaluate_classic_slot(grid: list[list[int]], bet: int, game_name: str) -> tuple[int, list[dict]]:
    if game_name == "Gran Fortuna":
        symbol_pays = [[0.5, 1.5, 6], [0.5, 2, 8], [1, 3, 12], [1.5, 5, 20],
                       [3, 10, 40], [6, 20, 80], [15, 50, 200]]
    else:
        symbol_pays = [[0.5, 1.5, 6], [0.5, 2, 8], [1, 3, 12], [1.5, 5, 20],
                       [3, 10, 40], [6, 20, 80], [15, 50, 200]]
    payout = 0
    wins = []
    for row in range(3):
        symbol = grid[0][row]
        count = 1
        while count < 5 and grid[count][row] == symbol:
            count += 1
        if count >= 2:
            multiplier = symbol_pays[symbol][min(count - 2, 2)]
            amount = int(bet * multiplier)
            payout += amount
            wins.append({"line": row, "symbol": symbol, "count": count, "payout": amount})
    return payout, wins


def _evaluate_china_slot(
    grid: list[list[int]], bet: int
) -> tuple[int, list[dict], int]:
    paylines = ([1, 1, 1, 1, 1], [0, 0, 0, 0, 0], [2, 2, 2, 2, 2],
                [0, 1, 2, 1, 0], [2, 1, 0, 1, 2])
    symbol_pays = ([0, 0, 12, 30, 90, 300], [0, 0, 8, 20, 60, 180],
                   [0, 0, 5, 12, 35, 100], [0, 0, 3, 8, 22, 70],
                   [0, 0, 2, 6, 18, 55], [0, 0, 1.5, 4, 12, 35],
                   [0, 0, 1, 3, 9, 25])
    payout = 0
    wins = []
    for line, pattern in enumerate(paylines):
        symbol = grid[0][pattern[0]]
        if symbol == 7:
            continue
        count = 1
        while count < 5 and grid[count][pattern[count]] == symbol:
            count += 1
        if count >= 3:
            amount = int(bet * symbol_pays[symbol][count])
            payout += amount
            wins.append({"line": line, "symbol": symbol, "count": count, "payout": amount})
    scatter_count = sum(symbol == 7 for column in grid for symbol in column)
    return payout, wins, scatter_count


@app.post(f"{API_PREFIX}/game/play")
def play_game(
    payload: GamePlayRequest,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = (
        db.query(UserDB)
        .filter(UserDB.id == current_user.id)
        .with_for_update()
        .first()
    )
    if user is None:
        raise HTTPException(status_code=401, detail="Sesión inválida o vencida.")
    is_owner = user.role == "owner"
    is_free_spin = not is_owner and user.free_spins > 0
    bet = user.free_spin_bet if is_free_spin else payload.bet_amount
    if not is_owner and not is_free_spin and user.balance < bet:
        raise HTTPException(status_code=400, detail="Saldo insuficiente en la cuenta.")
    if is_free_spin:
        user.free_spins -= 1
        spin_multiplier = user.free_spin_multiplier
    else:
        spin_multiplier = 1
        if not is_owner:
            user.balance -= bet

    rng = secrets.SystemRandom()
    if payload.game_name == "Fortuna China":
        grid = [[_choose_symbol(rng, payload.game_name) for _ in range(3)] for _ in range(5)]
        payout, wins, scatter_count = _evaluate_china_slot(grid, bet)
        payout *= spin_multiplier
        bonus_spins_added = 0
        bonus_prize_index = None
        if scatter_count >= 3:
            prizes = ((5, 1), (8, 1), (5, 2), (10, 1), (5, 3), (12, 1), (8, 2), (10, 3))
            bonus_prize_index = rng.randrange(len(prizes))
            bonus_spins_added, bonus_multiplier = prizes[bonus_prize_index]
            bonus_spins_added = min(bonus_spins_added, 100 - user.free_spins)
            user.free_spins = min(user.free_spins + bonus_spins_added, 100)
            user.free_spin_bet = bet
            user.free_spin_multiplier = max(user.free_spin_multiplier, bonus_multiplier)
    else:
        grid = [[_choose_symbol(rng, payload.game_name) for _ in range(3)] for _ in range(5)]
        payout, wins = _evaluate_classic_slot(grid, bet, payload.game_name)
        payout *= spin_multiplier
        scatter_count = 0
        bonus_spins_added = 0
        bonus_prize_index = None

    if not is_owner:
        user.balance += payout
    if user.free_spins == 0:
        user.free_spin_multiplier = 1
    ggr = max(0, bet - payout)
    log_entry = VaultLogDB(
        user_id=user.id,
        game_name=payload.game_name,
        bet_amount=bet,
        payout_amount=payout,
        ggr=ggr,
        tax_sii=int(ggr * 0.27),
    )
    db.add(log_entry)
    db.commit()
    return {
        "grid": grid,
        "payout_amount": payout,
        "wins": wins if payout > 0 else [],
        "new_user_balance": user.balance,
        "unlimited_credits": is_owner,
        "is_free_spin": is_free_spin,
        "bet_amount": bet,
        "spin_multiplier_used": spin_multiplier,
        "free_spins": user.free_spins,
        "free_spin_multiplier": user.free_spin_multiplier,
        "bonus_spins_added": bonus_spins_added,
        "bonus_prize_index": bonus_prize_index,
        "tax_reserve_sii": int(ggr * 0.27),
    }


def create_owner(username: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,50}", username):
        raise SystemExit("El usuario debe tener de 3 a 50 caracteres: letras, números, punto, guion o guion bajo.")
    password = getpass("Contraseña segura para el propietario: ")
    confirmation = getpass("Repite la contraseña: ")
    if password != confirmation:
        raise SystemExit("Las contraseñas no coinciden.")
    try:
        validated = UserRegister(
            username=username,
            email=f"{username}@owner.invalid",
            password=password,
        )
    except Exception as error:
        raise SystemExit(f"Contraseña no válida: {error}") from error
    db = SessionLocal()
    try:
        if db.query(UserDB).filter(UserDB.username == username).first():
            raise SystemExit("Ese usuario ya existe; no se modificó.")
        user = UserDB(
            username=username,
            email=validated.email,
            hashed_password=pwd_context.hash(validated.password),
            balance=INITIAL_BALANCE,
            role="owner",
            email_verified=True,
        )
        db.add(user)
        db.commit()
    finally:
        db.close()
    print(f"Cuenta de propietario creada para '{username}'. Inicia sesión desde auth.html.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Herramientas locales de administración del casino.")
    parser.add_argument("command", choices=["create-owner"])
    parser.add_argument("username", nargs="?")
    arguments = parser.parse_args()
    owner_username = arguments.username or input("Nombre de usuario del propietario: ").strip()
    create_owner(owner_username)
