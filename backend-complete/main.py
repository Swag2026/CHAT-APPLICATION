"""
Chat App Backend
-----------------
Endpoints:
  POST /auth/signup          -> naya account banao
  POST /auth/login           -> login karo, JWT token milega
  GET  /users                -> chat karne ke liye users ki list
  GET  /messages/{other_id}  -> kisi user ke saath purani chat history
  WS   /ws/{token}           -> real-time messages (connect karte hi live chat)

Setup:
  pip install fastapi uvicorn sqlalchemy psycopg2-binary python-jose passlib bcrypt python-dotenv python-multipart --break-system-packages
  .env me DATABASE_URL aur JWT_SECRET daalo
  Run: uvicorn main:app --host 0.0.0.0 --port 8001
"""

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from pydantic import BaseModel
from typing import Dict
import json

from database import engine, get_db
from models import Base, User, Message
from auth import hash_password, verify_password, create_token, decode_token

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Chat App Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Schemas ----------

class SignupRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SendMessageRequest(BaseModel):
    receiver_id: int
    content: str


# ---------- Auth endpoints ----------

@app.post("/auth/signup")
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(400, "Ye username already liya hua hai")

    user = User(username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_token(user.id, user.username)
    return {"token": token, "user_id": user.id, "username": user.username}


@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Username ya password galat hai")

    token = create_token(user.id, user.username)
    return {"token": token, "user_id": user.id, "username": user.username}


def get_current_user(token: str, db: Session) -> User:
    data = decode_token(token)
    if not data:
        raise HTTPException(401, "Invalid ya expired token")
    user = db.query(User).filter(User.id == int(data["sub"])).first()
    if not user:
        raise HTTPException(401, "User nahi mila")
    return user


# ---------- REST endpoints ----------

@app.get("/users")
def list_users(token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    users = db.query(User).filter(User.id != me.id).all()
    return [{"id": u.id, "username": u.username} for u in users]


@app.get("/messages/{other_id}")
def get_messages(other_id: int, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    msgs = (
        db.query(Message)
        .filter(
            or_(
                and_(Message.sender_id == me.id, Message.receiver_id == other_id),
                and_(Message.sender_id == other_id, Message.receiver_id == me.id),
            )
        )
        .order_by(Message.created_at.asc())
        .all()
    )
    return [
        {
            "id": m.id,
            "sender_id": m.sender_id,
            "content": m.content,
            "file_url": m.file_url,
            "created_at": m.created_at.isoformat(),
        }
        for m in msgs
    ]


# ---------- WebSocket real-time chat ----------

# Kaun abhi online hai aur unka connection kya hai
active_connections: Dict[int, WebSocket] = {}


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    from database import SessionLocal
    db = SessionLocal()

    data = decode_token(token)
    if not data:
        await websocket.close(code=4001)
        return

    user_id = int(data["sub"])
    await websocket.accept()
    active_connections[user_id] = websocket

    try:
        while True:
            raw = await websocket.receive_text()
            payload = json.loads(raw)
            receiver_id = payload["receiver_id"]
            content = payload["content"]

            # DB me save karo
            msg = Message(sender_id=user_id, receiver_id=receiver_id, content=content)
            db.add(msg)
            db.commit()
            db.refresh(msg)

            response = {
                "id": msg.id,
                "sender_id": user_id,
                "receiver_id": receiver_id,
                "content": content,
                "created_at": msg.created_at.isoformat(),
            }

            # Agar receiver abhi online hai to turant bhej do
            if receiver_id in active_connections:
                await active_connections[receiver_id].send_text(json.dumps(response))

            # Sender ko bhi confirmation wapas bhejo (apne screen pe dikhane ke liye)
            await websocket.send_text(json.dumps(response))

    except WebSocketDisconnect:
        active_connections.pop(user_id, None)
    finally:
        db.close()


@app.get("/")
def health():
    return {"status": "ok", "message": "Chat backend chal raha hai"}
