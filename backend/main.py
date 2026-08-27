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
import os
import time
import asyncio
import httpx
from datetime import datetime, timezone, timedelta

from database import engine, get_db, SessionLocal
from models import Base, User, Group, GroupMember, Message, ChatSettings, LoveNote
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
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_url VARCHAR"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_type VARCHAR"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name VARCHAR"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_size INTEGER"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS call_status VARCHAR"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS call_type VARCHAR"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS call_duration INTEGER"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_edited BOOLEAN DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_ping BOOLEAN DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE messages ADD COLUMN IF NOT EXISTS unlock_at TIMESTAMPTZ"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS push_token VARCHAR"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS gm_gn_enabled BOOLEAN DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS gm_gn_target_id INTEGER"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_gm_sent_date VARCHAR"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_gn_sent_date VARCHAR"))

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
    access_code: str

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateGroupRequest(BaseModel):
    name: str
    member_ids: list[int]

class PushTokenRequest(BaseModel):
    push_token: str

class AvatarUpdateRequest(BaseModel):
    avatar_url: str  # base64 data-uri

class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str

class MessageEditRequest(BaseModel):
    content: str

class ChatSettingsUpdateRequest(BaseModel):
    together_since: str | None = None   # ISO date string
    mood: str | None = None             # "romantic" | "playful" | "calm" | "default"

class LoveNoteCreateRequest(BaseModel):
    receiver_id: int
    content: str

class AutoPingUpdateRequest(BaseModel):
    enabled: bool
    target_user_id: int | None = None


# ---------- Auth endpoints ----------

@app.post("/auth/signup")
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    # Security: bina invite code ke koi bhi signup karke sabki user-list nahi dekh sakta.
    # SIGNUP_ACCESS_CODE Railway environment variable me set karna hai (ek shared secret,
    # sirf apne trusted logon ko batana - jaisa koi family/friends invite code).
    expected_code = os.environ.get("SIGNUP_ACCESS_CODE")
    if expected_code and payload.access_code != expected_code:
        raise HTTPException(403, "Galat access code")

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


def parse_iso_datetime(s: str):
    """Frontend `date.toISOString()` se aane wali string "Z" suffix ke saath aati hai
    (jaise "2026-01-15T00:00:00.000Z"). Python 3.10 aur usse purane versions me
    `datetime.fromisoformat()` "Z" suffix support nahi karta (sirf "+00:00" chalta hai) -
    isliye "Z" ko manually replace karte hain taaki kisi bhi Python version pe crash na ho."""
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@app.post("/push-token")
def save_push_token(payload: PushTokenRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    me.push_token = payload.push_token
    db.commit()
    return {"status": "ok"}


@app.get("/me")
def get_my_profile(token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    return {
        "id": me.id,
        "username": me.username,
        "avatar_url": me.avatar_url,
        "created_at": me.created_at.isoformat() if me.created_at else None,
    }


@app.patch("/me/avatar")
def update_my_avatar(payload: AvatarUpdateRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    me.avatar_url = payload.avatar_url
    db.commit()
    return {"status": "ok"}


@app.post("/me/password")
def change_my_password(payload: PasswordChangeRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    if not verify_password(payload.old_password, me.password_hash):
        raise HTTPException(400, "Purana password galat hai")
    me.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"status": "ok"}


@app.get("/me/auto-ping")
def get_auto_ping(token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    return {
        "enabled": me.gm_gn_enabled,
        "target_user_id": me.gm_gn_target_id,
    }


@app.put("/me/auto-ping")
def update_auto_ping(payload: AutoPingUpdateRequest, token: str, db: Session = Depends(get_db)):
    """Roz subah/raat khud-ba-khud 'Good morning'/'Good night' ping bhejne ka setting."""
    me = get_current_user(token, db)
    me.gm_gn_enabled = payload.enabled
    me.gm_gn_target_id = payload.target_user_id
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
                "channelId": "default",  # Android ke naye notification channel se match karne ke liye
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

    result = []
    for u in users:
        last_msg = (
            db.query(Message)
            .filter(
                or_(
                    and_(Message.sender_id == me.id, Message.receiver_id == u.id),
                    and_(Message.sender_id == u.id, Message.receiver_id == me.id),
                )
            )
            .order_by(Message.created_at.desc())
            .first()
        )
        unread_count = (
            db.query(Message)
            .filter(Message.sender_id == u.id, Message.receiver_id == me.id, Message.is_read == False)
            .count()
        )

        preview = None
        if last_msg:
            if last_msg.is_deleted:
                preview = "This message was deleted"
            elif last_msg.is_ping:
                preview = f"💭 {last_msg.content}"
            elif last_msg.call_status:
                preview = f"📞 {'Voice call' if last_msg.call_type == 'voice' else 'Call'}"
            elif last_msg.file_type == "image":
                preview = "📷 Photo"
            elif last_msg.file_type == "file":
                preview = f"📄 {last_msg.file_name or 'File'}"
            else:
                preview = last_msg.content

        result.append({
            "id": u.id,
            "username": u.username,
            "online": u.id in active_connections,
            "avatar_url": u.avatar_url,
            "last_seen": u.last_seen.isoformat() if u.last_seen else None,
            "last_message": preview,
            "last_message_at": last_msg.created_at.isoformat() if last_msg else None,
            "unread_count": unread_count,
        })

    # Sabse recent activity wale sabse upar
    result.sort(key=lambda x: x["last_message_at"] or "", reverse=True)
    return result


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
    now = datetime.now(timezone.utc)
    result = []
    for m in msgs:
        # Surprise/locked message: agar main receiver hoon (sender nahi) aur unlock time abhi
        # nahi aaya, to content chupa dete hain - sirf "locked" flag + unlock time dikhta hai.
        is_locked = bool(m.unlock_at) and m.unlock_at > now and m.receiver_id == me.id
        result.append({
            "id": m.id,
            "sender_id": m.sender_id,
            "receiver_id": m.receiver_id,
            "content": None if is_locked else ("This message was deleted" if m.is_deleted else m.content),
            "file_url": None if (is_locked or m.is_deleted) else m.file_url,
            "file_type": None if (is_locked or m.is_deleted) else m.file_type,
            "file_name": None if (is_locked or m.is_deleted) else m.file_name,
            "file_size": m.file_size,
            "is_read": m.is_read,
            "is_edited": m.is_edited,
            "is_deleted": m.is_deleted,
            "is_ping": m.is_ping,
            "is_locked": is_locked,
            "unlock_at": m.unlock_at.isoformat() if m.unlock_at else None,
            "call_status": m.call_status,
            "call_type": m.call_type,
            "call_duration": m.call_duration,
            "created_at": m.created_at.isoformat(),
        })
    return result


async def broadcast_to_users(user_ids, payload: dict):
    """Ek WebSocket event ko diye gaye user_ids me se jo bhi online hain, unhe bhej deta hai."""
    text_payload = json.dumps(payload)
    for uid in user_ids:
        if uid in active_connections:
            try:
                await active_connections[uid].send_text(text_payload)
            except Exception:
                pass


def get_or_create_chat_settings(db: Session, id1: int, id2: int) -> ChatSettings:
    """Har pair ka ek hi row hota hai - id order-independent rakhne ke liye chhota/bada
    normalize kar dete hain, taaki dono taraf se query same row match kare."""
    a, b = min(id1, id2), max(id1, id2)
    row = db.query(ChatSettings).filter(ChatSettings.user_a_id == a, ChatSettings.user_b_id == b).first()
    if not row:
        row = ChatSettings(user_a_id=a, user_b_id=b)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


@app.get("/chat-settings/{other_id}")
def get_chat_settings(other_id: int, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    row = get_or_create_chat_settings(db, me.id, other_id)

    # "Together since" set nahi hai to pehle message ki date default man lete hain
    together_since = row.together_since
    if not together_since:
        first_msg = (
            db.query(Message)
            .filter(
                or_(
                    and_(Message.sender_id == me.id, Message.receiver_id == other_id),
                    and_(Message.sender_id == other_id, Message.receiver_id == me.id),
                )
            )
            .order_by(Message.created_at.asc())
            .first()
        )
        together_since = first_msg.created_at if first_msg else None

    return {
        "together_since": together_since.isoformat() if together_since else None,
        "together_since_is_custom": row.together_since is not None,
        "mood": row.mood or "default",
    }


@app.put("/chat-settings/{other_id}")
async def update_chat_settings(other_id: int, payload: ChatSettingsUpdateRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    row = get_or_create_chat_settings(db, me.id, other_id)

    if payload.together_since is not None:
        row.together_since = parse_iso_datetime(payload.together_since)
    if payload.mood is not None:
        row.mood = payload.mood
    db.commit()

    # Doosre user ko live update bhejo taaki background/mood turant sync ho
    await broadcast_to_users(
        [me.id, other_id],
        {
            "type": "chat_settings_update",
            "other_id": me.id,  # receiver ke perspective se "other_id" bhej rahe hain
            "together_since": row.together_since.isoformat() if row.together_since else None,
            "mood": row.mood or "default",
        },
    )
    return {"status": "ok"}


@app.post("/love-notes")
def create_love_note(payload: LoveNoteCreateRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    note = LoveNote(sender_id=me.id, receiver_id=payload.receiver_id, content=payload.content)
    db.add(note)
    db.commit()
    db.refresh(note)
    return {
        "id": note.id,
        "sender_id": note.sender_id,
        "receiver_id": note.receiver_id,
        "content": note.content,
        "created_at": note.created_at.isoformat(),
    }


@app.get("/love-notes/{other_id}")
def list_love_notes(other_id: int, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    notes = (
        db.query(LoveNote)
        .filter(
            or_(
                and_(LoveNote.sender_id == me.id, LoveNote.receiver_id == other_id),
                and_(LoveNote.sender_id == other_id, LoveNote.receiver_id == me.id),
            )
        )
        .order_by(LoveNote.created_at.desc())
        .all()
    )
    return [
        {
            "id": n.id,
            "sender_id": n.sender_id,
            "receiver_id": n.receiver_id,
            "content": n.content,
            "created_at": n.created_at.isoformat(),
        }
        for n in notes
    ]


@app.get("/milestones/{other_id}")
def get_milestones(other_id: int, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)

    pair_filter = or_(
        and_(Message.sender_id == me.id, Message.receiver_id == other_id),
        and_(Message.sender_id == other_id, Message.receiver_id == me.id),
    )

    first_message = db.query(Message).filter(pair_filter, Message.call_status.is_(None), Message.is_ping.is_(False)).order_by(Message.created_at.asc()).first()
    first_call = db.query(Message).filter(pair_filter, Message.call_status.isnot(None)).order_by(Message.created_at.asc()).first()
    total_messages = db.query(Message).filter(pair_filter, Message.call_status.is_(None), Message.is_ping.is_(False)).count()
    total_calls = db.query(Message).filter(pair_filter, Message.call_status.isnot(None)).count()
    total_pings = db.query(Message).filter(pair_filter, Message.is_ping.is_(True)).count()
    total_notes = (
        db.query(LoveNote)
        .filter(
            or_(
                and_(LoveNote.sender_id == me.id, LoveNote.receiver_id == other_id),
                and_(LoveNote.sender_id == other_id, LoveNote.receiver_id == me.id),
            )
        )
        .count()
    )

    settings_row = get_or_create_chat_settings(db, me.id, other_id)
    together_since = settings_row.together_since or (first_message.created_at if first_message else None)

    return {
        "together_since": together_since.isoformat() if together_since else None,
        "first_message_at": first_message.created_at.isoformat() if first_message else None,
        "first_call_at": first_call.created_at.isoformat() if first_call else None,
        "total_messages": total_messages,
        "total_calls": total_calls,
        "total_pings": total_pings,
        "total_love_notes": total_notes,
    }


def recipients_for_message(msg: Message, db: Session) -> list:
    """1-on-1 message ke liye [sender, receiver], group message ke liye group ke sabhi members."""
    if msg.group_id:
        member_ids = [gm.user_id for gm in db.query(GroupMember).filter(GroupMember.group_id == msg.group_id).all()]
        return member_ids
    ids = [msg.sender_id]
    if msg.receiver_id:
        ids.append(msg.receiver_id)
    return ids


@app.patch("/messages/{message_id}")
async def edit_message(message_id: int, payload: MessageEditRequest, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(404, "Message nahi mila")
    if msg.sender_id != me.id:
        raise HTTPException(403, "Sirf apna hi message edit kar sakte ho")
    if msg.is_deleted:
        raise HTTPException(400, "Delete ho chuka message edit nahi ho sakta")
    if msg.call_status or msg.file_url:
        raise HTTPException(400, "Sirf text message edit ho sakta hai")

    msg.content = payload.content
    msg.is_edited = True
    db.commit()

    await broadcast_to_users(
        recipients_for_message(msg, db),
        {"type": "message_edit", "id": msg.id, "content": msg.content, "sender_id": msg.sender_id, "receiver_id": msg.receiver_id, "group_id": msg.group_id},
    )
    return {"status": "ok"}


@app.delete("/messages/{message_id}")
async def delete_message(message_id: int, token: str, db: Session = Depends(get_db)):
    me = get_current_user(token, db)
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(404, "Message nahi mila")
    if msg.sender_id != me.id:
        raise HTTPException(403, "Sirf apna hi message delete kar sakte ho")

    msg.is_deleted = True
    msg.content = None
    msg.file_url = None
    db.commit()

    await broadcast_to_users(
        recipients_for_message(msg, db),
        {"type": "message_delete", "id": msg.id, "sender_id": msg.sender_id, "receiver_id": msg.receiver_id, "group_id": msg.group_id},
    )
    return {"status": "ok"}


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
        last_msg = (
            db.query(Message)
            .filter(Message.group_id == g.id)
            .order_by(Message.created_at.desc())
            .first()
        )
        preview = None
        if last_msg:
            if last_msg.is_deleted:
                preview = "This message was deleted"
            elif last_msg.file_type == "image":
                preview = "📷 Photo"
            elif last_msg.file_type == "file":
                preview = f"📄 {last_msg.file_name or 'File'}"
            else:
                preview = last_msg.content
        result.append({
            "id": g.id,
            "name": g.name,
            "member_count": member_count,
            "last_message": preview,
            "last_message_at": last_msg.created_at.isoformat() if last_msg else None,
        })
    result.sort(key=lambda x: x["last_message_at"] or "", reverse=True)
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
            "content": "This message was deleted" if m.is_deleted else m.content,
            "file_url": None if m.is_deleted else m.file_url,
            "file_type": None if m.is_deleted else m.file_type,
            "file_name": None if m.is_deleted else m.file_name,
            "file_size": m.file_size,
            "is_edited": m.is_edited,
            "is_deleted": m.is_deleted,
            "created_at": m.created_at.isoformat(),
        }
        for m in msgs
    ]


# ---------- WebSocket real-time chat ----------

active_connections: Dict[int, WebSocket] = {}


async def deliver_ping(db: Session, sender_id: int, receiver_id: int, content: str, push_title: str = "💭 Thinking of You"):
    """Ek 'ping' (Thinking of you / Good morning / Good night) banata hai aur deliver karta
    hai - WebSocket se agar receiver online hai, warna push notification se. Manual ping
    (chat se) aur daily auto Good Morning/Night dono isi function ko use karte hain."""
    msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=content, is_ping=True)
    db.add(msg)
    db.commit()
    db.refresh(msg)

    response = {
        "type": "ping",
        "id": msg.id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "content": content,
        "is_ping": True,
        "is_read": False,
        "created_at": msg.created_at.isoformat(),
    }

    if receiver_id in active_connections:
        try:
            await active_connections[receiver_id].send_text(json.dumps(response))
        except Exception:
            pass
    else:
        other_user = db.query(User).filter(User.id == receiver_id).first()
        sender = db.query(User).filter(User.id == sender_id).first()
        if other_user and other_user.push_token:
            send_push_notification(
                other_user.push_token,
                title=push_title,
                body=f"{sender.username if sender else 'Someone'}: {content}",
                data={"type": "ping"},
            )
    return msg

# user_id -> other user id jiske saath wo abhi call me hai (ringing ya connected).
# Isi se "busy" signal decide hota hai - agar koi already kisi call me hai to
# naya incoming offer relay nahi hota, seedha caller ko "call_busy" bhej dete hain.
in_call: Dict[int, int] = {}

# Same caller->receiver ke liye baar-baar "missed call" push notification na jaaye isliye
# ek chhota sa cooldown - warna agar koi jaldi-jaldi call button dabaye (ya app retry kare),
# phone pe ek saath dus-bees notification aa jaati hain (jo bug tha).
last_call_push_at: Dict[frozenset, float] = {}
CALL_PUSH_COOLDOWN_SECONDS = 25

# Active call ka meta-data track karta hai taaki call khatam hone par sahi status
# (missed / rejected / ended) ke saath DB me ek "call log" entry save ho sake -
# bilkul WhatsApp jaisा "Missed Voice Call" / "Voice Call Rejected" wala message.
# Key: frozenset({caller_id, receiver_id}) - dono id ka order-independent pair.
active_calls: Dict[frozenset, dict] = {}

# Agar receiver offline hai (app band/background), call turant fail nahi hoti - 30 second
# tak "pending" rakhte hain (jaisa asli phone call ringing karta hai). Push notification
# jaati hai isi waqt. Agar receiver isi window me app khol le (WebSocket reconnect ho),
# to yehi offer usko turant deliver ho jaata hai aur call normally connect ho jaati hai -
# WhatsApp jaisa "call chhoot rahi thi lekin app khola to abhi bhi ring kar rahi hai" wala
# behavior. Agar window khatam ho jaaye bina answer ke, tab caller ko "unavailable" batate
# hain aur missed-call log hota hai.
pending_offers: Dict[int, dict] = {}
PENDING_OFFER_TIMEOUT_SECONDS = 30


async def expire_pending_offer(receiver_id: int, pending_id: str):
    """PENDING_OFFER_TIMEOUT_SECONDS baad check karta hai ki offer abhi bhi pending hai ya
    nahi (agar receiver ne is beech reconnect karke le liya, to ye no-op ho jaayega)."""
    await asyncio.sleep(PENDING_OFFER_TIMEOUT_SECONDS)
    entry = pending_offers.get(receiver_id)
    if not entry or entry.get("pending_id") != pending_id:
        return  # already delivered ya kisi naye call se replace ho chuka hai

    caller_id = entry["caller_id"]
    pending_offers.pop(receiver_id, None)
    clear_call_state(receiver_id)
    clear_call_state(caller_id)

    key = frozenset({caller_id, receiver_id})
    info = active_calls.pop(key, None)
    db = SessionLocal()
    try:
        if info:
            await log_call_event(db, info["caller"], info["receiver"], "missed", None)
    finally:
        db.close()

    if caller_id in active_connections:
        try:
            await active_connections[caller_id].send_text(json.dumps({"type": "call_unavailable", "receiver_id": receiver_id}))
        except Exception:
            pass


async def log_call_event(db: Session, caller_id: int, receiver_id: int, status: str, duration: int = None):
    """Call khatam hone par ek Message row bana ke dono taraf broadcast karta hai."""
    msg = Message(
        sender_id=caller_id,
        receiver_id=receiver_id,
        call_status=status,
        call_type="voice",
        call_duration=duration,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    payload = json.dumps({
        "type": "call_log",
        "id": msg.id,
        "sender_id": caller_id,
        "receiver_id": receiver_id,
        "call_status": status,
        "call_type": "voice",
        "call_duration": duration,
        "created_at": msg.created_at.isoformat(),
    })
    for uid in (caller_id, receiver_id):
        if uid in active_connections:
            try:
                await active_connections[uid].send_text(payload)
            except Exception:
                pass


def clear_call_state(uid: int):
    """Dono taraf se busy-mark hata do (agar the), aur doosra user_id return karo."""
    other_id = in_call.pop(uid, None)
    if other_id is not None:
        in_call.pop(other_id, None)
    return other_id


async def broadcast_presence(user_id: int, online: bool, last_seen: str = None):
    """Sabko batao ki ye user online/offline hua."""
    payload = json.dumps({"type": "presence", "user_id": user_id, "online": online, "last_seen": last_seen})
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

    # FIX: agar is user ke liye koi call abhi bhi "pending" hai (jab offer aaya tha ye
    # offline tha), to reconnect hote hi wo offer turant deliver kar do - jaise call abhi
    # aayi ho. Isi se "app band thi, khola to call abhi bhi ring ho rahi hai" wala real
    # phone-jaisa experience milta hai, bina kisi risky native library ke.
    pending = pending_offers.pop(user_id, None)
    if pending:
        try:
            await websocket.send_text(json.dumps(pending["payload"]))
        except Exception:
            pass

    try:
        while True:
            raw = await websocket.receive_text()

            # Har message ko alag se try/except me rakhte hain - taaki ek galat/corrupt
            # message poori connection ko crash na kare aur baaki messages bhi na uden.
            try:
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
                    unlock_at_str = payload.get("unlock_at")  # surprise/locked message - ISO string, optional
                    unlock_at = parse_iso_datetime(unlock_at_str) if unlock_at_str else None

                    msg = Message(
                        sender_id=user_id,
                        receiver_id=receiver_id,
                        content=content,
                        file_url=file_url,
                        file_type=file_type,
                        file_name=file_name,
                        file_size=file_size,
                        unlock_at=unlock_at,
                    )
                    db.add(msg)
                    db.commit()
                    db.refresh(msg)

                    is_locked_for_receiver = bool(unlock_at) and unlock_at > datetime.now(timezone.utc)

                    sender_view = {
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
                        "unlock_at": unlock_at.isoformat() if unlock_at else None,
                        "is_locked": False,  # sender ko apna hi likha hua message hamesha dikhta hai
                        "client_id": payload.get("client_id"),  # offline-queue reconciliation ke liye wapas bhej dete hain
                        "created_at": msg.created_at.isoformat(),
                    }
                    receiver_view = dict(sender_view)
                    if is_locked_for_receiver:
                        receiver_view.update({
                            "content": None, "file_url": None, "file_type": None,
                            "file_name": None, "is_locked": True,
                        })

                    if receiver_id in active_connections:
                        await active_connections[receiver_id].send_text(json.dumps(receiver_view))
                    else:
                        # FIX: pehle normal text/photo messages ke liye receiver offline hone par
                        # koi push notification nahi jaati thi (sirf calls/pings ke liye thi) -
                        # isi wajah se "notification dhang se nahi aata" wali complaint thi.
                        other_user = db.query(User).filter(User.id == receiver_id).first()
                        sender = db.query(User).filter(User.id == user_id).first()
                        if other_user and other_user.push_token and not is_locked_for_receiver:
                            preview_body = content if content else ("📷 Photo" if file_type == "image" else "📄 File" if file_type == "file" else "New message")
                            send_push_notification(
                                other_user.push_token,
                                title=sender.username if sender else "New message",
                                body=preview_body,
                                data={"type": "message", "sender_id": user_id},
                            )
                    await websocket.send_text(json.dumps(sender_view))

                # ---- "Thinking of you" romantic ping - normal message jaisa hi, bas special
                # flag ke saath (chat me alag decorative card jaisa dikhta hai), aur agar
                # doosra offline hai to push notification bhi jaati hai (taaki ye "spontaneous
                # nudge" wala point miss na ho jaaye) ----
                elif msg_type == "ping":
                    receiver_id = payload["receiver_id"]
                    content = payload.get("content", "Thinking of you")
                    await deliver_ping(db, user_id, receiver_id, content)
                    await websocket.send_text(json.dumps({
                        "type": "ping", "sender_id": user_id, "receiver_id": receiver_id,
                        "content": content, "is_ping": True, "is_read": False,
                        "client_id": payload.get("client_id"),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }))

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
                        "client_id": payload.get("client_id"),
                        "created_at": msg.created_at.isoformat(),
                    }

                    member_ids = [
                        gm.user_id for gm in db.query(GroupMember).filter(GroupMember.group_id == group_id).all()
                    ]
                    group = db.query(Group).filter(Group.id == group_id).first()
                    for mid in member_ids:
                        if mid in active_connections:
                            await active_connections[mid].send_text(json.dumps(response))
                        elif mid != user_id:
                            member = db.query(User).filter(User.id == mid).first()
                            if member and member.push_token:
                                preview_body = content if content else ("📷 Photo" if file_type == "image" else "📄 File" if file_type == "file" else "New message")
                                send_push_notification(
                                    member.push_token,
                                    title=f"{sender.username if sender else 'Someone'} in {group.name if group else 'group'}",
                                    body=preview_body,
                                    data={"type": "group_message", "group_id": group_id},
                                )

                # ---- Voice call signaling (seedha relay karte hain, DB me kuch save nahi karte) ----
                elif msg_type == "call_offer":
                    receiver_id = payload.get("receiver_id")

                    # ---- Busy signal: agar caller ya receiver already kisi call me hain
                    # (ya kisi aur ka pending offer already ring kar raha hai unke liye) ----
                    if user_id in in_call or receiver_id in in_call:
                        await websocket.send_text(json.dumps({"type": "call_busy", "receiver_id": receiver_id}))

                    elif receiver_id in active_connections:
                        in_call[user_id] = receiver_id
                        in_call[receiver_id] = user_id
                        active_calls[frozenset({user_id, receiver_id})] = {
                            "caller": user_id, "receiver": receiver_id, "answered": False, "answered_at": None,
                        }
                        relay = dict(payload)
                        relay["sender_id"] = user_id
                        sender = db.query(User).filter(User.id == user_id).first()
                        relay["sender_username"] = sender.username if sender else "Unknown"
                        await active_connections[receiver_id].send_text(json.dumps(relay))

                    else:
                        # Receiver abhi offline hai - turant fail nahi karte, 30 second tak
                        # "ring" karte rehte hain (asli call jaisa). Push notification bhej
                        # dete hain; agar receiver isi window me app khol le, offer turant
                        # deliver ho jaayega (dekho: websocket connect ke turant baad wala
                        # pending_offers check).
                        in_call[user_id] = receiver_id
                        in_call[receiver_id] = user_id
                        active_calls[frozenset({user_id, receiver_id})] = {
                            "caller": user_id, "receiver": receiver_id, "answered": False, "answered_at": None,
                        }

                        sender = db.query(User).filter(User.id == user_id).first()
                        relay = dict(payload)
                        relay["sender_id"] = user_id
                        relay["sender_username"] = sender.username if sender else "Unknown"

                        pending_id = f"{user_id}-{time.time()}"
                        pending_offers[receiver_id] = {
                            "caller_id": user_id, "payload": relay, "pending_id": pending_id,
                        }
                        asyncio.create_task(expire_pending_offer(receiver_id, pending_id))

                        other_user = db.query(User).filter(User.id == receiver_id).first()
                        pair_key = frozenset({user_id, receiver_id})
                        now_ts = time.time()
                        last_sent = last_call_push_at.get(pair_key, 0)
                        if other_user and other_user.push_token and (now_ts - last_sent) > CALL_PUSH_COOLDOWN_SECONDS:
                            last_call_push_at[pair_key] = now_ts
                            send_push_notification(
                                other_user.push_token,
                                title="Incoming call",
                                body=f"{sender.username if sender else 'Someone'} is calling you",
                                data={"type": "incoming_call", "caller_id": user_id, "caller_name": sender.username if sender else "Unknown"},
                            )
                        # FIX: pehle yahan turant "call_unavailable" bhej dete the (turant fail).
                        # Ab kuch nahi bhejte - caller ki app "Ringing..." dikhati rehti hai jab
                        # tak 30-second window khatam na ho jaaye (expire_pending_offer handle
                        # karega) ya receiver reconnect na kar le.

                elif msg_type in ("call_end", "call_reject"):
                    receiver_id = payload.get("receiver_id")
                    clear_call_state(user_id)  # dono taraf se busy-mark hatao
                    pending_offers.pop(receiver_id, None)  # agar caller ne offer pending rehte hue hi cancel kar diya
                    pending_offers.pop(user_id, None)

                    key = frozenset({user_id, receiver_id})
                    info = active_calls.pop(key, None)
                    if info:
                        caller, callee = info["caller"], info["receiver"]
                        if msg_type == "call_reject":
                            status = "rejected"
                            duration = None
                        elif info["answered"]:
                            status = "ended"
                            duration = int((datetime.now(timezone.utc) - info["answered_at"]).total_seconds())
                        else:
                            status = "missed"
                            duration = None
                        await log_call_event(db, caller, callee, status, duration)

                    if receiver_id in active_connections:
                        relay = dict(payload)
                        relay["sender_id"] = user_id
                        await active_connections[receiver_id].send_text(json.dumps(relay))

                elif msg_type in ("call_answer", "ice_candidate"):
                    receiver_id = payload.get("receiver_id")
                    if msg_type == "call_answer":
                        key = frozenset({user_id, receiver_id})
                        if key in active_calls:
                            active_calls[key]["answered"] = True
                            active_calls[key]["answered_at"] = datetime.now(timezone.utc)
                    if receiver_id in active_connections:
                        relay = dict(payload)
                        relay["sender_id"] = user_id
                        await active_connections[receiver_id].send_text(json.dumps(relay))

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
                raise  # ye bahar wale except me handle hoga (normal disconnect)
            except Exception as e:
                # Koi bhi aur error (DB, bad payload, waghera) - session clean karo aur connection zinda rakho
                db.rollback()
                print(f"WS message handling error: {e}")

    except WebSocketDisconnect:
        active_connections.pop(user_id, None)

        # Last-seen timestamp save karo taaki chat header pe "last seen at HH:MM" dikha sakein,
        # aur presence broadcast me isi waqt bhej do taaki doosra user turant dekh sake
        me_row = db.query(User).filter(User.id == user_id).first()
        last_seen_iso = None
        if me_row:
            me_row.last_seen = datetime.now(timezone.utc)
            db.commit()
            last_seen_iso = me_row.last_seen.isoformat()
        await broadcast_presence(user_id, False, last_seen_iso)

        # Agar user beech call me hi disconnect hua (app band/crash/net gaya),
        # to doosre party ko bhi "call_end" bhejo aur uska busy-mark hatao -
        # warna wo hamesha "busy" dikhta rahega jab tak khud dobara open na kare.
        other_id = clear_call_state(user_id)
        if other_id:
            pending_offers.pop(other_id, None)  # caller khud disconnect hua, ab receiver ke liye offer bhi stale hai
            pending_offers.pop(user_id, None)
            key = frozenset({user_id, other_id})
            info = active_calls.pop(key, None)
            if info:
                caller, callee = info["caller"], info["receiver"]
                if info["answered"]:
                    status = "ended"
                    duration = int((datetime.now(timezone.utc) - info["answered_at"]).total_seconds())
                else:
                    status = "missed"
                    duration = None
                await log_call_event(db, caller, callee, status, duration)
            if other_id in active_connections:
                await active_connections[other_id].send_text(
                    json.dumps({"type": "call_end", "sender_id": user_id})
                )
    finally:
        db.close()


@app.get("/")
def health():
    return {"status": "ok", "message": "Chat backend chal raha hai"}


# ---------- Daily "Good Morning" / "Good Night" auto-ping ----------
# Server har minute check karta hai: IST (India) time 7:00 AM ho gaya to jitne users ne
# gm_gn_enabled kiya hai unke target ko "Good morning" ping bhej do, aur 11:00 PM ho gaya
# to "Good night". Ek din me ek hi baar bheje - last_gm_sent_date/last_gn_sent_date se
# track karte hain taaki loop dobara us minute me chale to dobara na bheje.

IST_OFFSET = timedelta(hours=5, minutes=30)


async def daily_ping_scheduler():
    while True:
        try:
            now_ist = datetime.now(timezone.utc) + IST_OFFSET
            today_str = now_ist.strftime("%Y-%m-%d")
            db = SessionLocal()
            try:
                if now_ist.hour == 7 and now_ist.minute == 0:
                    users = db.query(User).filter(User.gm_gn_enabled == True, User.gm_gn_target_id.isnot(None)).all()
                    for u in users:
                        if u.last_gm_sent_date != today_str:
                            await deliver_ping(db, u.id, u.gm_gn_target_id, "Good morning ☀️", push_title="☀️ Good Morning")
                            u.last_gm_sent_date = today_str
                            db.commit()
                elif now_ist.hour == 23 and now_ist.minute == 0:
                    users = db.query(User).filter(User.gm_gn_enabled == True, User.gm_gn_target_id.isnot(None)).all()
                    for u in users:
                        if u.last_gn_sent_date != today_str:
                            await deliver_ping(db, u.id, u.gm_gn_target_id, "Good night, sweet dreams 🌙", push_title="🌙 Good Night")
                            u.last_gn_sent_date = today_str
                            db.commit()
            finally:
                db.close()
        except Exception as e:
            print(f"daily_ping_scheduler error: {e}")
        await asyncio.sleep(60)


@app.on_event("startup")
async def start_background_tasks():
    asyncio.create_task(daily_ping_scheduler())
