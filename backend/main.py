"""
Chat App Backend
-----------------
Endpoints:
  POST /auth/signup          -> naya account banao
  POST /auth/login           -> login karo, JWT token milega
  GET  /users                -> chat karne ke liye users ki list (online status ke saath)
  GET  /messages/{other_id}  -> kisi user ke saath purani chat history
  WS   /ws/{token}           -> real-time messages, typing, online status, read receipts

WebSocket message types (client -> server):
  {"type": "message", "receiver_id": 5, "content": "hi"}
  {"type": "typing", "receiver_id": 5}
  {"type": "read", "other_id": 5}

WebSocket message types (server -> client):
  {"type": "message", ...}
  {"type": "typing", "sender_id": 5}
  {"type": "presence", "user_id": 5, "online": true}
  {"type": "read", "reader_id": 5, "other_id": 3}
"""

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from pydantic import BaseModel
from typing import Dict
import json
import httpx

from database import engine, get_db, SessionLocal
from models import Base, User, Group, GroupMember, Message
from auth import hash_password, verify_password, create_token, decode_token
from sqlalchemy import text

Base.metadata.create_all(bind=engine)

# ---------- Lightweight auto-migration ----------
# create_all() sirf naye tables banata hai, purane tables ke columns update nahi karta.
# Isliye purane "messages" table me jo naye columns/changes chahiye, wo yahan manually add kar rahe hain.
with engine.begin() as conn:
    conn.execute(text("ALTER TABLE messages ALTER COLUMN receiver_id DROP NOT NULL"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS group_id INTEGER"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_type VARCHAR"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name VARCHAR"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size INTEGER"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS push_token VARCHAR"))

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

class CreateGroupRequest(BaseModel):
    name: str
    member_ids: list[int]

class PushTokenRequest(BaseModel):
    push_token: str


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


@app.post("/push-token")
def save_push_token(payload: PushTokenRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    me.push_token = payload.push_token
    db.commit()
    return {"status": "ok"}


def send_push_notification(push_token: str, title: str, body: str, data: dict = None):
    """Expo ke push service ke through notification bhejta hai - background/killed app pe bhi deliver hoti hai."""
    if not push_token:
        return
    try:
        httpx.post(
            "https://exp.host/--/api/v2/push/send",
            json={
                "to": push_token,
                "title": title,
                "body": body,
                "data": data or {},
                "priority": "high",
                "sound": "default",
            },
            headers={"Content-Type": "application/json"},
            timeout=5.0,
        )
    except Exception:
        pass  # push fail ho to bhi app crash na ho


# ---------- REST endpoints ----------

@app.get("/users")
def list_users(token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    users = db.query(User).filter(User.id != me.id).all()
    return [
        {"id": u.id, "username": u.username, "online": u.id in active_connections}
        for u in users
    ]


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
            "file_type": m.file_type,
            "file_name": m.file_name,
            "file_size": m.file_size,
            "is_read": m.is_read,
            "created_at": m.created_at.isoformat(),
        }
        for m in msgs
    ]


# ---------- Group endpoints ----------

@app.post("/groups")
def create_group(payload: CreateGroupRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)

    group = Group(name=payload.name, created_by=me.id)
    db.add(group)
    db.commit()
    db.refresh(group)

    all_member_ids = set(payload.member_ids) | {me.id}
    for uid in all_member_ids:
        db.add(GroupMember(group_id=group.id, user_id=uid))
    db.commit()

    return {"id": group.id, "name": group.name}


@app.get("/groups")
def list_groups(token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)

    my_group_ids = [gm.group_id for gm in db.query(GroupMember).filter(GroupMember.user_id == me.id).all()]
    groups = db.query(Group).filter(Group.id.in_(my_group_ids)).all()

    result = []
    for g in groups:
        member_count = db.query(GroupMember).filter(GroupMember.group_id == g.id).count()
        result.append({"id": g.id, "name": g.name, "member_count": member_count})
    return result


@app.get("/groups/{group_id}/messages")
def get_group_messages(group_id: int, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)

    is_member = db.query(GroupMember).filter(
        GroupMember.group_id == group_id, GroupMember.user_id == me.id
    ).first()
    if not is_member:
        raise HTTPException(403, "Is group ke member nahi ho")

    msgs = db.query(Message).filter(Message.group_id == group_id).order_by(Message.created_at.asc()).all()
    return [
        {
            "id": m.id,
            "sender_id": m.sender_id,
            "sender_username": m.sender.username if m.sender else None,
            "content": m.content,
            "file_url": m.file_url,
            "file_type": m.file_type,
            "file_name": m.file_name,
            "file_size": m.file_size,
            "created_at": m.created_at.isoformat(),
        }
        for m in msgs
    ]


# ---------- WebSocket real-time chat ----------

active_connections: Dict[int, WebSocket] = {}


async def broadcast_presence(user_id: int, online: bool):
    """Sabko batao ki ye user online/offline hua."""
    payload = json.dumps({"type": "presence", "user_id": user_id, "online": online})
    for conn in list(active_connections.values()):
        try:
            await conn.send_text(payload)
        except Exception:
            pass


@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    db = SessionLocal()

    data = decode_token(token)
    if not data:
        await websocket.close(code=4001)
        return

    user_id = int(data["sub"])
    await websocket.accept()
    active_connections[user_id] = websocket

    await broadcast_presence(user_id, True)

    try:
        while True:
            raw = await websocket.receive_text()
            payload = json.loads(raw)
            msg_type = payload.get("type", "message")

            # ---- Naya text message (1-on-1) ----
            if msg_type == "message":
                receiver_id = payload["receiver_id"]
                content = payload.get("content")
                file_url = payload.get("file_url")
                file_type = payload.get("file_type")
                file_name = payload.get("file_name")
                file_size = payload.get("file_size")

                msg = Message(
                    sender_id=user_id,
                    receiver_id=receiver_id,
                    content=content,
                    file_url=file_url,
                    file_type=file_type,
                    file_name=file_name,
                    file_size=file_size,
                )
                db.add(msg)
                db.commit()
                db.refresh(msg)

                response = {
                    "type": "message",
                    "id": msg.id,
                    "sender_id": user_id,
                    "receiver_id": receiver_id,
                    "content": content,
                    "file_url": file_url,
                    "file_type": file_type,
                    "file_name": file_name,
                    "file_size": file_size,
                    "is_read": False,
                    "created_at": msg.created_at.isoformat(),
                }

                if receiver_id in active_connections:
                    await active_connections[receiver_id].send_text(json.dumps(response))
                await websocket.send_text(json.dumps(response))

            # ---- Naya group message ----
            elif msg_type == "group_message":
                group_id = payload["group_id"]
                content = payload.get("content")
                file_url = payload.get("file_url")
                file_type = payload.get("file_type")
                file_name = payload.get("file_name")
                file_size = payload.get("file_size")

                sender = db.query(User).filter(User.id == user_id).first()

                msg = Message(
                    sender_id=user_id,
                    group_id=group_id,
                    content=content,
                    file_url=file_url,
                    file_type=file_type,
                    file_name=file_name,
                    file_size=file_size,
                )
                db.add(msg)
                db.commit()
                db.refresh(msg)

                response = {
                    "type": "group_message",
                    "id": msg.id,
                    "group_id": group_id,
                    "sender_id": user_id,
                    "sender_username": sender.username if sender else None,
                    "content": content,
                    "file_url": file_url,
                    "file_type": file_type,
                    "file_name": file_name,
                    "file_size": file_size,
                    "created_at": msg.created_at.isoformat(),
                }

                member_ids = [
                    gm.user_id for gm in db.query(GroupMember).filter(GroupMember.group_id == group_id).all()
                ]
                for mid in member_ids:
                    if mid in active_connections:
                        await active_connections[mid].send_text(json.dumps(response))

            # ---- Voice call signaling (seedha relay karte hain, DB me kuch save nahi karte) ----
            elif msg_type in ("call_offer", "call_answer", "ice_candidate", "call_end", "call_reject"):
                receiver_id = payload.get("receiver_id")
                if receiver_id in active_connections:
                    relay = dict(payload)
                    relay["sender_id"] = user_id
                    if msg_type == "call_offer":
                        sender = db.query(User).filter(User.id == user_id).first()
                        relay["sender_username"] = sender.username if sender else "Unknown"
                    await active_connections[receiver_id].send_text(json.dumps(relay))
                elif msg_type == "call_offer":
                    # Doosra online nahi hai (WebSocket connect nahi hai) - push notification try karo
                    other_user = db.query(User).filter(User.id == receiver_id).first()
                    sender = db.query(User).filter(User.id == user_id).first()
                    if other_user and other_user.push_token:
                        send_push_notification(
                            other_user.push_token,
                            title="Incoming call",
                            body=f"{sender.username if sender else 'Someone'} is calling you",
                            data={"type": "incoming_call", "caller_id": user_id, "caller_name": sender.username if sender else "Unknown"},
                        )
                    await websocket.send_text(json.dumps({"type": "call_unavailable", "receiver_id": receiver_id}))

            # ---- "Typing..." indicator ----
            elif msg_type == "typing":
                receiver_id = payload["receiver_id"]
                if receiver_id in active_connections:
                    await active_connections[receiver_id].send_text(
                        json.dumps({"type": "typing", "sender_id": user_id})
                    )

            # ---- Read receipt ----
            elif msg_type == "read":
                other_id = payload["other_id"]
                db.query(Message).filter(
                    Message.sender_id == other_id,
                    Message.receiver_id == user_id,
                    Message.is_read == False,
                ).update({"is_read": True})
                db.commit()

                if other_id in active_connections:
                    await active_connections[other_id].send_text(
                        json.dumps({"type": "read", "reader_id": user_id, "other_id": other_id})
                    )

    except WebSocketDisconnect:
        active_connections.pop(user_id, None)
        await broadcast_presence(user_id, False)
    finally:
        db.close()


@app.get("/")
def health():
    return {"status": "ok", "message": "Chat backend chal raha hai"}
