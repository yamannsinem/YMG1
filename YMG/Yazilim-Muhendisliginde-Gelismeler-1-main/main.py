# ===============================
# IMPORTS
# ===============================
import os
import re
import requests
import random
import datetime
from uuid import uuid4
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Counter, Gauge
from sqlalchemy import create_engine, Column, String, ForeignKey, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# GÜVENLİK KÜTÜPHANELERİ
from passlib.context import CryptContext
from jose import jwt, JWTError

app = FastAPI(title="Velora OS API", version="6.2.0")

# ===============================
# SECURITY CONFIG
# ===============================
SECRET_KEY = os.getenv("SECRET_KEY", "gizli_anahtar_varsayilan")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 Saat

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Geçersiz token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Token doğrulanamadı")

# ===============================
# METRICS & CORS & DATABASE
# ===============================
# (Bu kısımlar aynı kalacak, sadece yukarıdaki importlar ve security kısmı değişti)
REQUEST_COUNT = Counter("velora_requests", "Total Requests", ["method", "endpoint"])
TASK_GAUGE = Gauge("velora_tasks", "Active Tasks")
NOTE_GAUGE = Gauge("velora_notes", "Active Notes")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://velora:velorapass@localhost/veloradb")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ===============================
# DB MODELS (Aynı)
# ===============================
class DBUser(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String) # Artık Hashli tutulacak
    full_name = Column(String)

class DBTask(Base):
    __tablename__ = "tasks"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    title = Column(String)
    description = Column(String, nullable=True)
    is_completed = Column(Boolean, default=False)

class DBPassword(Base):
    __tablename__ = "passwords"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    account = Column(String)
    username = Column(String)
    password = Column(String)
    strength = Column(String)

class DBNote(Base):
    __tablename__ = "notes"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    title = Column(String)
    content = Column(Text)
    color = Column(String, default="#f59e0b")

class DBShoppingItem(Base):
    __tablename__ = "shopping_items"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    item = Column(String)
    is_bought = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# ===============================
# PYDANTIC MODELS (Aynı)
# ===============================
class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str
class UserLogin(BaseModel):
    email: str
    password: str
class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
class TaskUpdate(BaseModel):
    is_completed: bool
class Task(TaskCreate):
    id: str
    user_id: str
    is_completed: bool
    class Config: orm_mode = True
class PasswordCreate(BaseModel):
    account: str
    username: str
    password: str
class Password(BaseModel):
    id: str
    user_id: str
    account: str
    username: str
    password: str
    strength: str
    class Config: orm_mode = True
class NoteCreate(BaseModel):
    title: str
    content: str
    color: Optional[str] = "#f59e0b"
class Note(NoteCreate):
    id: str
    user_id: str
    class Config: orm_mode = True
class ShoppingCreate(BaseModel):
    item: str
class ShoppingItem(ShoppingCreate):
    id: str
    user_id: str
    is_bought: bool
    class Config: orm_mode = True

def analyze_password_strength(password: str) -> str:
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"\d", password): score += 1
    return ["Zayıf", "Orta", "Güçlü"][min(score, 2)]

# ===============================
# ENDPOINTS (Auth Güncellendi)
# ===============================
@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/api/quote", tags=["External"])
def get_random_quote():
    fallback = {"quote": "Başlamak için mükemmel olman gerekmez.", "author": "Velora AI"}
    try:
        url = "https://zenquotes.io/api/random"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                return {"quote": data[0]['q'], "author": data[0]['a']}
    except: pass
    return fallback

# --- AUTH (GÜNCELLENDİ) ---
@app.post("/auth/register", status_code=201, tags=["Auth"])
def register(user: UserRegister, db: Session = Depends(get_db)):
    if db.query(DBUser).filter(DBUser.email == user.email).first():
        raise HTTPException(400, "Kullanıcı zaten var")
    
    # Şifreyi Hashle
    hashed_pw = get_password_hash(user.password)
    
    new_user = DBUser(id=str(uuid4()), email=user.email, password=hashed_pw, full_name=user.full_name)
    db.add(new_user)
    db.commit()
    return {"mesaj": "Kayıt Başarılı", "user_id": new_user.id}

@app.post("/auth/login", tags=["Auth"])
def login(user: UserLogin, db: Session = Depends(get_db)):
    u = db.query(DBUser).filter(DBUser.email == user.email).first()
    
    # Kullanıcı var mı ve şifre eşleşiyor mu kontrol et
    if not u or not verify_password(user.password, u.password):
        raise HTTPException(401, "Hatalı E-posta veya Şifre")
        
    # JWT Token Üret
    access_token = create_access_token(data={"sub": u.id})
    name = u.full_name if u.full_name else "Kullanıcı"
    
    return {"mesaj": "Giriş Başarılı", "user_id": u.id, "access_token": access_token, "full_name": name}

# --- TASKS ---
@app.post("/api/tasks/{uid}", tags=["Tasks"], dependencies=[Depends(verify_token)])
def add_task(uid: str, data: TaskCreate, db: Session = Depends(get_db)):
    # Kullanıcı kontrolü JWT ile yapılıyor ama yine de db'den bakabiliriz
    t = DBTask(id=str(uuid4()), user_id=uid, **data.dict())
    db.add(t)
    db.commit()
    TASK_GAUGE.set(db.query(DBTask).count())
    return t

@app.get("/api/tasks/{uid}", response_model=List[Task], tags=["Tasks"], dependencies=[Depends(verify_token)])
def get_tasks(uid: str, db: Session = Depends(get_db)):
    return db.query(DBTask).filter(DBTask.user_id == uid).order_by(DBTask.is_completed, DBTask.title).all()

@app.put("/api/tasks/{uid}/{task_id}", tags=["Tasks"], dependencies=[Depends(verify_token)])
def update_task(uid: str, task_id: str, data: TaskUpdate, db: Session = Depends(get_db)):
    t = db.query(DBTask).filter(DBTask.id == task_id, DBTask.user_id == uid).first()
    if not t: raise HTTPException(404, "Görev yok")
    t.is_completed = data.is_completed
    db.commit()
    return t

@app.delete("/api/tasks/{uid}/{task_id}", tags=["Tasks"], dependencies=[Depends(verify_token)])
def delete_task(uid: str, task_id: str, db: Session = Depends(get_db)):
    t = db.query(DBTask).filter(DBTask.id == task_id, DBTask.user_id == uid).first()
    if t:
        db.delete(t)
        db.commit()
    return {"msg": "Silindi"}

# --- NOTES ---
@app.post("/api/notes/{uid}", tags=["Notes"], dependencies=[Depends(verify_token)])
def add_note(uid: str, data: NoteCreate, db: Session = Depends(get_db)):
    n = DBNote(id=str(uuid4()), user_id=uid, **data.dict())
    db.add(n)
    db.commit()
    NOTE_GAUGE.set(db.query(DBNote).count())
    return n

@app.get("/api/notes/{uid}", response_model=List[Note], tags=["Notes"], dependencies=[Depends(verify_token)])
def get_notes(uid: str, db: Session = Depends(get_db)):
    return db.query(DBNote).filter(DBNote.user_id == uid).all()

@app.delete("/api/notes/{uid}/{note_id}", tags=["Notes"], dependencies=[Depends(verify_token)])
def delete_note(uid: str, note_id: str, db: Session = Depends(get_db)):
    n = db.query(DBNote).filter(DBNote.id == note_id, DBNote.user_id == uid).first()
    if n: db.delete(n); db.commit()
    return {"msg": "Silindi"}

# --- SHOPPING ---
@app.post("/api/shopping/{uid}", tags=["Shopping"], dependencies=[Depends(verify_token)])
def add_shop(uid: str, data: ShoppingCreate, db: Session = Depends(get_db)):
    s = DBShoppingItem(id=str(uuid4()), user_id=uid, item=data.item)
    db.add(s)
    db.commit()
    return s

@app.get("/api/shopping/{uid}", response_model=List[ShoppingItem], tags=["Shopping"], dependencies=[Depends(verify_token)])
def get_shop(uid: str, db: Session = Depends(get_db)):
    return db.query(DBShoppingItem).filter(DBShoppingItem.user_id == uid).all()

@app.delete("/api/shopping/{uid}/{item_id}", tags=["Shopping"], dependencies=[Depends(verify_token)])
def del_shop(uid: str, item_id: str, db: Session = Depends(get_db)):
    i = db.query(DBShoppingItem).filter(DBShoppingItem.id == item_id, DBShoppingItem.user_id == uid).first()
    if i: db.delete(i); db.commit()
    return {"msg": "Silindi"}

# --- PASSWORDS ---
@app.post("/api/passwords/{uid}", tags=["Passwords"], dependencies=[Depends(verify_token)])
def add_pass(uid: str, data: PasswordCreate, db: Session = Depends(get_db)):
    s = analyze_password_strength(data.password)
    p = DBPassword(id=str(uuid4()), user_id=uid, strength=s, **data.dict())
    db.add(p); db.commit()
    return p

@app.get("/api/passwords/{uid}", response_model=List[Password], tags=["Passwords"], dependencies=[Depends(verify_token)])
def get_pass(uid: str, db: Session = Depends(get_db)):
    return db.query(DBPassword).filter(DBPassword.user_id == uid).all()