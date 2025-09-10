import logging
import traceback
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from auth import hash_password, verify_password, create_access_token, verify_token
from database import Base, engine, SessionLocal
from model import User, Message
from schema import LoginRequest, SignupRequest, MessageEdit
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from typing import Dict, List
import json
import os
import uuid
import aiofiles
import asyncio

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
Base.metadata.create_all(bind=engine)
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create uploads directory
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------ AUTH ENDPOINTS ------------------
@app.post("/signup")
async def signup(request: SignupRequest, db: Session = Depends(get_db)):
    logger.info(f"Signup attempt: username={request.username}, email={request.email}")
    
    if not request.username or len(request.username) < 3:
        logger.error("Invalid username: too short or empty")
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")
    if not request.email or "@" not in request.email:
        logger.error("Invalid email format")
        raise HTTPException(status_code=400, detail="Invalid email format")
    if not request.password or len(request.password) < 6:
        logger.error("Invalid password: too short or empty")
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")

    if db.query(User).filter(User.email == request.email).first():
        logger.error(f"Email already exists: {request.email}")
        raise HTTPException(status_code=400, detail="Email already exists")
    if db.query(User).filter(User.username == request.username).first():
        logger.error(f"Username already exists: {request.username}")
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        id=str(uuid.uuid4()),
        username=request.username,
        email=request.email,
        hashed_password=hash_password(request.password),
        is_online=True,
        last_seen=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.username)
    logger.info(f"User created: ID={user.id}, Username={user.username}, Email={user.email}")
    return {
        "msg": "User created successfully",
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "access_token": token,
        "token_type": "bearer",
    }

@app.post("/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    logger.info(f"Login attempt: email={request.email}")
    
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.hashed_password):
        logger.error(f"Invalid email or password for email: {request.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user.is_online = True
    user.last_seen = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token(user.username)
    logger.info(f"User logged in: ID={user.id}, Username={user.username}")
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_online": user.is_online,
            "last_seen": user.last_seen.isoformat() if user.last_seen else None,
        },
    }

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    logger.info(f"Verifying token: {token[:10]}...")
    payload = verify_token(token)
    if not payload:
        logger.error("Invalid or expired token")
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    username = payload.get("sub")
    logger.info(f"Token payload: sub={username}")
    if not username:
        logger.error("Token missing 'sub' field")
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.error(f"User not found: {username}")
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(f"Authenticated user: ID={user.id}, Username={username}")
    return user

@app.get("/users/me")
async def read_current_user(current_user: User = Depends(get_current_user)):
    logger.info(f"Fetching current user: ID={current_user.id}, Username={current_user.username}")
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_online": current_user.is_online,
        "last_seen": current_user.last_seen.isoformat() if current_user.last_seen else None,
    }

@app.get("/users")
async def get_all_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.id != current_user.id).all()
    logger.info(f"Fetching all users for current_user ID={current_user.id}")
    response = [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_online": user.is_online,
            "last_seen": user.last_seen.isoformat() if user.last_seen else None,
        }
        for user in users
    ]
    logger.info(f"Returning users: {response}")
    return response

@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.is_online = False
    current_user.last_seen = datetime.now(timezone.utc)
    db.commit()
    logger.info(f"User logged out: ID={current_user.id}")
    return {"msg": "Logged out successfully"}

# ------------------ FILE UPLOAD ------------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    MAX_FILE_SIZE = 50 * 1024 * 1024
    file_size = 0

    file_extension = os.path.splitext(file.filename)[1].lower()
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)

    async with aiofiles.open(file_path, "wb") as f:
        while chunk := await file.read(8192):
            file_size += len(chunk)
            if file_size > MAX_FILE_SIZE:
                os.remove(file_path)
                raise HTTPException(status_code=413, detail="File too large. Maximum size is 50MB")
            await f.write(chunk)

    content_type = file.content_type
    media_type = (
        "image" if content_type.startswith("image/")
        else "video" if content_type.startswith("video/")
        else "file"
    )

    logger.info(f"File uploaded: {unique_filename}, Size={file_size}, MediaType={media_type}")
    return {
        "url": f"/files/{unique_filename}",
        "filename": file.filename,
        "size": file_size,
        "media_type": media_type,
    }

@app.get("/files/{filename}")
async def get_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path)

# ------------------ WEBSOCKET CONNECTION MANAGER ------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.user_sessions: Dict[WebSocket, str] = {}
        self.lock = asyncio.Lock()

    async def connect(self, user_id: str, websocket: WebSocket, db: Session):
        async with self.lock:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []

            if websocket not in self.active_connections[user_id]:
                self.active_connections[user_id].append(websocket)
            self.user_sessions[websocket] = user_id

            user = db.query(User).filter(User.id == user_id).first()
            if user:
                user.is_online = True
                user.last_seen = datetime.now(timezone.utc)
                db.commit()

            logger.info(f"User {user_id} connected. Total connections: {len(self.active_connections[user_id])}")

        await self.broadcast_user_status(user_id, True)

    async def disconnect(self, websocket: WebSocket, db: Session):
        async with self.lock:
            user_id = self.user_sessions.get(websocket)
            if not user_id:
                logger.warning("Disconnect called for unknown websocket")
                return

            if user_id in self.active_connections:
                try:
                    self.active_connections[user_id].remove(websocket)
                    logger.debug(f"Removed websocket for user {user_id}. Remaining connections: {len(self.active_connections[user_id])}")
                except ValueError:
                    logger.warning(f"Websocket not found in active_connections for user {user_id}")
                    pass

                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
                    user = db.query(User).filter(User.id == user_id).first()
                    if user:
                        user.is_online = False
                        user.last_seen = datetime.now(timezone.utc)
                        db.commit()
                        logger.info(f"User {user_id} is offline. Broadcasting status.")
                        await self.broadcast_user_status(user_id, False)

            if websocket in self.user_sessions:
                del self.user_sessions[websocket]

            logger.info(f"User {user_id} disconnected")

    async def broadcast_user_status(self, user_id: str, is_online: bool):
        status_message = {
            "type": "user_status",
            "user_id": str(user_id),
            "is_online": is_online,
        }
        logger.info(f"Broadcasting user status: {status_message}")

        for uid, connections in list(self.active_connections.items()):
            if uid != user_id:
                disconnected = []
                for connection in connections[:]:
                    try:
                        await connection.send_json(status_message)
                        logger.debug(f"Sent user status to {uid}: {status_message}")
                    except Exception as e:
                        logger.error(f"Failed to broadcast to user {uid}: {e}")
                        disconnected.append(connection)

                for conn in disconnected:
                    try:
                        connections.remove(conn)
                        logger.debug(f"Removed disconnected connection for user {uid}")
                    except ValueError:
                        pass

    async def send_to_user(self, user_id: str, message: dict):
        logger.info(f"Sending to user {user_id}. Active connections: {len(self.active_connections.get(user_id, []))}")
        if user_id in self.active_connections:
            disconnected = []
            for connection in self.active_connections[user_id][:]:
                try:
                    await connection.send_json(message)
                    logger.debug(f"Message sent to user {user_id}: {message}")
                except Exception as e:
                    logger.error(f"Failed to send message to user {user_id}: {e}")
                    disconnected.append(connection)

            for conn in disconnected:
                try:
                    self.active_connections[user_id].remove(conn)
                    logger.debug(f"Removed disconnected connection for user {user_id}")
                except ValueError:
                    pass
        else:
            logger.warning(f"No active connections for user {user_id}")

    async def broadcast_to_chat(self, sender_id: str, receiver_id: str, message: dict):
        logger.info(f"Broadcasting to chat: sender={sender_id}, receiver={receiver_id}, message={message}")
        await self.send_to_user(sender_id, message)
        await self.send_to_user(receiver_id, message)

manager = ConnectionManager()

# ------------------ WEBSOCKET ENDPOINT ------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    user_id = None
    db = SessionLocal()

    try:
        await websocket.accept()
        logger.info("WebSocket connection accepted")

        try:
            auth_data = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
            logger.info(f"Received auth data: {auth_data}")
        except asyncio.TimeoutError:
            logger.error("Authentication timeout")
            await websocket.send_json({"error": "Authentication timeout"})
            await websocket.close(code=1008)
            return

        if auth_data.get("type") == "auth" and auth_data.get("token"):
            token = auth_data.get("token")
            if not token:
                logger.error("No token provided")
                await websocket.send_json({"error": "Invalid authentication data"})
                await websocket.close(code=1008)
                return

            payload = verify_token(token)
            if not payload:
                logger.error("Invalid token")
                await websocket.send_json({"error": "Invalid token"})
                await websocket.close(code=1008)
                return

            username = payload.get("sub")
            if not username:
                logger.error("Token missing 'sub' field")
                await websocket.send_json({"error": "Invalid token payload"})
                await websocket.close(code=1008)
                return

            user = db.query(User).filter(User.username == username).first()
            if not user:
                logger.error(f"User not found: {username}")
                await websocket.send_json({"error": "User not found"})
                await websocket.close(code=1008)
                return

            user_id = str(user.id)
            logger.info(f"User {user_id} ({username}) authenticated")

            await manager.connect(user_id, websocket, db)

            await websocket.send_json({
                "type": "connection",
                "status": "connected",
                "user_id": str(user_id),
            })

        else:
            logger.error("Invalid authentication data")
            await websocket.send_json({"error": "Invalid authentication data"})
            await websocket.close(code=1008)
            return

        while True:
            try:
                data = await websocket.receive_json()
                logger.info(f"Received data from user {user_id}: {data.get('type')}")

                message_type = data.get("type", "message")

                if message_type == "message":
                    receiver_id = data.get("receiver_id")
                    text = data.get("text", "")
                    media_url = data.get("media_url")
                    media_type = data.get("media_type")
                    file_name = data.get("file_name")
                    temp_id = data.get("temp_id")

                    if not receiver_id:
                        logger.error("No receiver_id provided")
                        await websocket.send_json({"error": "No receiver_id provided"})
                        continue

                    receiver = db.query(User).filter(User.id == receiver_id).first()
                    if not receiver:
                        logger.error(f"Receiver not found: {receiver_id}")
                        await websocket.send_json({"error": f"Receiver {receiver_id} not found"})
                        continue

                    msg = Message(
                        id=str(uuid.uuid4()),
                        sender_id=user_id,
                        receiver_id=receiver_id,
                        text=text,
                        media_url=media_url,
                        media_type=media_type,
                        file_name=file_name,
                        created_at=datetime.now(timezone.utc),
                    )
                    db.add(msg)
                    db.commit()
                    db.refresh(msg)

                    logger.info(
                        f"Message saved: ID={msg.id}, Text={text}, Sender={user_id}, Receiver={receiver_id}, Media={media_url}"
                    )

                    message_payload = {
                        "type": "message",
                        "message_id": str(msg.id),
                        "sender_id": str(user_id),
                        "receiver_id": str(receiver_id),
                        "sender_name": user.username,
                        "text": text,
                        "media_url": media_url,
                        "media_type": media_type,
                        "file_name": file_name,
                        "edited": False,
                        "created_at": msg.created_at.isoformat(),
                        "temp_id": temp_id,
                    }

                    logger.info(f"Broadcasting message: {message_payload}")

                    await manager.broadcast_to_chat(user_id, receiver_id, message_payload)

                elif message_type == "edit":
                    message_id = data.get("message_id")
                    new_text = data.get("text")

                    if not message_id or not new_text:
                        logger.error(f"Invalid edit request: message_id={message_id}, text={new_text}")
                        await websocket.send_json({"error": "Invalid message_id or text"})
                        continue

                    msg = db.query(Message).filter(
                        Message.id == message_id,
                        Message.sender_id == user_id,
                    ).first()

                    if not msg:
                        logger.error(f"Message {message_id} not found or access denied for user {user_id}")
                        await websocket.send_json({"error": "Message not found or access denied"})
                        continue

                    msg.text = new_text
                    msg.edited = True
                    msg.edited_at = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(msg)

                    logger.info(f"Message {message_id} edited by user {user_id}")

                    edit_payload = {
                        "type": "edit",
                        "message_id": str(message_id),
                        "text": new_text,
                        "edited": True,
                        "edited_at": msg.edited_at.isoformat(),
                    }

                    await manager.broadcast_to_chat(user_id, msg.receiver_id, edit_payload)

                elif message_type == "delete":
                    message_id = data.get("message_id")

                    if not message_id:
                        logger.error("No message_id provided for delete")
                        await websocket.send_json({"error": "No message_id provided"})
                        continue

                    msg = db.query(Message).filter(
                        Message.id == message_id,
                        Message.sender_id == user_id,
                    ).first()

                    if not msg:
                        logger.error(f"Message {message_id} not found or access denied for user {user_id}")
                        await websocket.send_json({"error": "Message not found or access denied"})
                        continue

                    receiver_id = msg.receiver_id
                    db.delete(msg)
                    db.commit()

                    logger.info(f"Message {message_id} deleted by user {user_id}")

                    delete_payload = {
                        "type": "delete",
                        "message_id": str(message_id),
                    }

                    await manager.broadcast_to_chat(user_id, receiver_id, delete_payload)

                elif message_type == "typing":
                    receiver_id = data.get("receiver_id")
                    is_typing = data.get("is_typing", False)

                    typing_payload = {
                        "type": "typing",
                        "user_id": str(user_id),
                        "is_typing": is_typing,
                    }

                    await manager.send_to_user(receiver_id, typing_payload)

            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for user {user_id}")
                break
            except json.JSONDecodeError:
                logger.error("Invalid JSON received")
                await websocket.send_json({"error": "Invalid JSON data"})
                continue
            except Exception as e:
                logger.error(f"Error handling message: {str(e)}\n{traceback.format_exc()}")
                await websocket.send_json({"error": f"Server error: {str(e)}"})
                continue

    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}\n{traceback.format_exc()}")
        await websocket.send_json({"error": "WebSocket error"})
        await websocket.close(code=1008)

    finally:
        if user_id:
            await manager.disconnect(websocket, db)
        db.close()
        
# ------------------ MESSAGE ENDPOINTS ------------------
@app.get("/messages/{user_id}/{other_id}")
async def get_messages(
    user_id: str,
    other_id: str,
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    logger.info(f"get_messages called: current_user.id={current_user.id}, user_id={user_id}, other_id={other_id}, username={current_user.username}")
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            logger.error(f"User not found: {user_id}")
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        other = db.query(User).filter(User.id == other_id).first()
        if not other:
            logger.error(f"User not found: {other_id}")
            raise HTTPException(status_code=404, detail=f"User {other_id} not found")

        messages = (
            db.query(Message)
            .filter(
                ((Message.sender_id == user_id) & (Message.receiver_id == other_id))
                | ((Message.sender_id == other_id) & (Message.receiver_id == user_id))
            )
            .order_by(Message.created_at)
            .offset(skip)
            .limit(limit)
            .all()
        )

        logger.info(f"Fetched {len(messages)} messages for user_id={user_id}, other_id={other_id}")
        response = []
        for msg in messages:
            sender = db.query(User).filter(User.id == msg.sender_id).first()
            sender_name = sender.username if sender else "Unknown"
            response.append({
                "message_id": str(msg.id),
                "sender_id": str(msg.sender_id),
                "receiver_id": str(msg.receiver_id),
                "sender_name": sender_name,
                "text": msg.text,
                "media_url": msg.media_url,
                "media_type": msg.media_type,
                "file_name": msg.file_name,
                "edited": msg.edited,
                "edited_at": msg.edited_at.isoformat() if msg.edited_at else None,
                "created_at": msg.created_at.isoformat(),
            })

        logger.info(f"Returning messages: {response}")
        return response
    except Exception as e:
        logger.error(f"Error in get_messages: {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.put("/messages/{message_id}")
async def edit_message(
    message_id: str,
    request: MessageEdit,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(Message).filter(
        Message.id == message_id,
        Message.sender_id == current_user.id,
    ).first()

    if not msg:
        logger.error(f"Message {message_id} not found or access denied for user {current_user.id}")
        raise HTTPException(status_code=404, detail="Message not found or access denied")

    msg.text = request.text
    msg.edited = True
    msg.edited_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(msg)

    logger.info(f"Message {message_id} edited by user {current_user.id}")
    return {
        "message_id": str(msg.id),
        "text": msg.text,
        "edited": msg.edited,
        "edited_at": msg.edited_at.isoformat(),
    }

@app.delete("/messages/{message_id}")
async def delete_message(
    message_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(Message).filter(
        Message.id == message_id,
        Message.sender_id == current_user.id,
    ).first()

    if not msg:
        logger.error(f"Message {message_id} not found or access denied for user {current_user.id}")
        raise HTTPException(status_code=404, detail="Message not found or access denied")

    db.delete(msg)
    db.commit()

    logger.info(f"Message {message_id} deleted by user {current_user.id}")
    return {"msg": "Message deleted successfully"}

# ------------------ SEARCH MESSAGES ------------------
@app.get("/messages/search")
async def search_messages(
    query: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    messages = (
        db.query(Message)
        .filter(
            (Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id),
            Message.text.contains(query),
        )
        .order_by(Message.created_at.desc())
        .limit(50)
        .all()
    )

    logger.info(f"Search returned {len(messages)} messages for query: {query}, user: {current_user.id}")
    response = [
        {
            "message_id": str(msg.id),
            "sender_id": str(msg.sender_id),
            "receiver_id": str(msg.receiver_id),
            "sender_name": db.query(User).filter(User.id == msg.sender_id).first().username,
            "text": msg.text,
            "created_at": msg.created_at.isoformat(),
        }
        for msg in messages
    ]
    logger.info(f"Returning search results: {response}")
    return response