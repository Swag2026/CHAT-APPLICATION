"""
Database models — SQLAlchemy use kar rahe hain PostgreSQL ke saath.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    push_token = Column(String, nullable=True)
    avatar_url = Column(Text, nullable=True)          # base64 data-uri, chhoti profile photo
    last_seen = Column(DateTime(timezone=True), nullable=True)
    # Daily "Good morning" / "Good night" auto-ping settings
    gm_gn_enabled = Column(Boolean, default=False)
    gm_gn_target_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # kisko roz bhejna hai
    last_gm_sent_date = Column(String, nullable=True)   # "YYYY-MM-DD" - dobara na bheje isi din
    last_gn_sent_date = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class GroupMember(Base):
    __tablename__ = "group_members"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=True)   # 1-on-1 ke liye
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)     # group ke liye
    content = Column(Text, nullable=True)
    file_url = Column(String, nullable=True)
    file_type = Column(String, nullable=True)
    file_name = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)
    is_delivered = Column(Boolean, default=False)
    is_read = Column(Boolean, default=False)
    call_status = Column(String, nullable=True)   # "missed" | "rejected" | "ended" (voice call log entry)
    call_type = Column(String, nullable=True)      # "voice" (video calling not implemented yet)
    call_duration = Column(Integer, nullable=True)  # seconds, only for "ended" calls
    is_edited = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)      # soft delete - "This message was deleted"
    is_ping = Column(Boolean, default=False)          # "Thinking of you" wala special romantic ping
    unlock_at = Column(DateTime(timezone=True), nullable=True)  # surprise/locked message - is time tak receiver ko content nahi dikhta
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])


class ChatSettings(Base):
    """Har 1-on-1 pair ke liye shared settings - "together since" date aur mood/theme.
    Dono users ko same row dikhta hai (order-independent), taaki dono taraf se sync rahe."""
    __tablename__ = "chat_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_a_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # chhota id
    user_b_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # bada id
    together_since = Column(DateTime(timezone=True), nullable=True)
    mood = Column(String, nullable=True)  # "romantic" | "playful" | "calm" | null (default)


class LoveNote(Base):
    """'Love Notes jar' - chhote sweet notes jo dono ek dusre ko bhejte hain,
    baad me random pull karke purani yaadein wapas dekh sakte hain."""
    __tablename__ = "love_notes"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
