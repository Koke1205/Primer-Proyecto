import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURACIÓN DE SEGURIDAD Y ENTORNO ---
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- CONEXIÓN A MYSQL (Dinero en enteros / CLP exactos) ---
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root:@localhost:3306/gran_fortuna_db")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS DE BASE DE DATOS ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    balance = Column(Integer, default=150000, nullable=False) # CLP exactos

class VaultLogDB(Base):
    __tablename__ = "vault_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    bet_amount = Column(Integer, nullable=False)
    payout_amount = Column(Integer, nullable=False)
    ggr = Column(Integer, nullable=False)
    tax_sii = Column(Integer, nullable=False) # Provisión fiscal 27% para el SII
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# --- ESQUEMAS PYDANTIC (Apuesta mínima desde 200 CLP) ---
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    username: str
    password: str

class GamePlayRequest(BaseModel):
    game_type: str = Field(..., pattern="^(slot|table)$")
    game_name: str = Field(..., max_length=50)
    bet_amount: int = Field(..., ge=200, le=500000) # Desde 200 hasta 500.000 CLP

# --- FASTAPI APP ---
app = FastAPI(title="Gran Fortuna Casino API", version="2.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token ausente o inválido")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado o corrupto")
    
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return user

@app.post("/api/v1/auth/register")
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(UserDB).filter(UserDB.username == user_data.username).first()
    if existing:
        return {"message": "El usuario ya existe"}
    
    hashed_pwd = pwd_context.hash(user_data.password)
    new_user = UserDB(username=user_data.username, hashed_password=hashed_pwd, balance=150000)
    db.add(new_user)
    db.commit()
    return {"message": "Usuario registrado con éxito"}

@app.post("/api/v1/auth/login")
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == user_data.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "balance": user.balance}

# --- MOTOR DE JUEGO SEGURO Y DINÁMICO ---
@app.post("/api/v1/game/play")
def play_game(payload: GamePlayRequest, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    # Bloqueo pesimista con with_for_update() para evitar condiciones de carrera / double spending
    user = db.query(UserDB).filter(UserDB.id == current_user.id).with_for_update().first()
    
    if user.balance < payload.bet_amount:
        raise HTTPException(status_code=400, detail="Saldo insuficiente en la cuenta")
    
    user.balance -= payload.bet_amount

    # Motor aleatorio criptográficamente seguro (secrets)
    rng = secrets.SystemRandom()
    grid = [[rng.randint(0, 5) for _ in range(3)] for _ in range(5)]
    
    # Evaluación de premios más frecuentes (desde 2 aciertos)
    payout = 0
    first_symbol = grid[0][1]
    match_count = 1
    for i in range(1, 5):
        if grid[i][1] == first_symbol:
            match_count += 1
        else:
            break
            
    if match_count >= 2:
        multipliers = {2: 1.5, 3: 4, 4: 12, 5: 35}
        payout = int(payload.bet_amount * multipliers.get(match_count, 1.5))

    user.balance += payout

    # Cumplimiento fiscal SII (27% del GGR)
    ggr = max(0, payload.bet_amount - payout)
    tax_sii = int(ggr * 0.27)

    vault_log = VaultLogDB(
        user_id=user.id,
        bet_amount=payload.bet_amount,
        payout_amount=payout,
        ggr=ggr,
        tax_sii=tax_sii
    )
    db.add(vault_log)
    db.commit()

    return {
        "grid": grid,
        "payout_amount": payout,
        "new_user_balance": user.balance,
        "tax_reserve_sii": tax_sii
    }