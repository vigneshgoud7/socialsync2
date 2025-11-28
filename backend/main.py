# main.py
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from dotenv import load_dotenv
import random
import os
import aiofiles
import uuid
from typing import List, Optional
import json

# Redis
import redis.asyncio as aioredis

# pydantic-settings (v2 style)
try:
    from pydantic_settings import BaseSettings
except Exception:
    from pydantic import BaseSettings  # type: ignore

from bson import ObjectId

# ============================================================
# FASTAPI APP INITIALIZATION
# ============================================================
app = FastAPI()


class Settings(BaseSettings):
    REDIS_URL: str = "redis://localhost:6379/0"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "allow",   # allow extra env keys like MONGO_URI, MAIL_*
    }


settings = Settings()


@app.on_event("startup")
async def startup_event_redis():
    try:
        app.state.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await app.state.redis.ping()
        print("Connected to Redis at", settings.REDIS_URL)
    except Exception as e:
        print("Warning: Redis connection failed:", e)
        app.state.redis = None


@app.on_event("shutdown")
async def shutdown_event_redis():
    if getattr(app.state, "redis", None):
        try:
            await app.state.redis.close()
            await app.state.redis.connection_pool.disconnect()
        except Exception:
            pass


async def get_redis():
    return getattr(app.state, "redis", None)


# Helper: serialize Mongo documents (ObjectId -> str)
def serialize_post(doc):
    try:
        doc = dict(doc)
    except Exception:
        pass
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    if "created_at" in doc:
        try:
            doc["created_at"] = str(doc["created_at"])
        except Exception:
            pass
    return doc


# CORS (allow your frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# CONFIGURATION
# ============================================================
SECRET_KEY = "YOUR_SUPER_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
print("Mongo URI loaded:", MONGO_URI)

client = AsyncIOMotorClient(MONGO_URI)
db = client["social_sync"]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Static uploads folder (create if not exists)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
# Serve uploads at /uploads
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ============================================================
# EMAIL CONFIG (fastapi-mail)
# ============================================================
conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME", "you@example.com"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", "password"),
    MAIL_FROM=os.getenv("MAIL_FROM", "you@example.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

# ============================================================
# MODELS
# ============================================================
class SignupRequest(BaseModel):
    username: str
    identifier: EmailStr        # email with proper format validation
    password: str
    confirm_password: str       # ensure backend also checks match


class LoginRequest(BaseModel):
    identifier: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str


class Token(BaseModel):
    access_token: str
    token_type: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: int


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str


class CheckUsernameRequest(BaseModel):
    username: str


class SendSignupOTPRequest(BaseModel):
    email: EmailStr


class MediaItem(BaseModel):
    filename: str
    saved_as: str
    url: str
    content_type: str


class CreatePostRequest(BaseModel):
    caption: str
    description: str
    tags: List[str]
    tagged_users: List[str] = []    # List of usernames
    feeling: str
    location: str
    music: str
    media: List[MediaItem]          # REQUIRED field
    created_at: datetime


# ============================================================
# HELPERS
# ============================================================
def hash_password(password: str) -> str:
    # bcrypt supports only first 72 bytes
    safe_password = password.encode("utf-8")[:72].decode("utf-8", "ignore")
    return pwd_context.hash(safe_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    safe_password = plain_password.encode("utf-8")[:72].decode("utf-8", "ignore")
    return pwd_context.verify(safe_password, hashed_password)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def validate_username_rules(username: str):
    """
    Username rules:
    - 3–20 characters
    - only letters, numbers, underscore
    """
    import re
    if len(username) < 3 or len(username) > 20:
        raise HTTPException(status_code=400, detail="Username must be 3–20 characters long")
    if not re.match(r"^[A-Za-z0-9_]+$", username):
        raise HTTPException(
            status_code=400,
            detail="Username can only contain letters, numbers, and underscore",
        )


async def check_email_not_registered(email: str):
    existing = await db.users.find_one({"identifier": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")


async def check_email_deliverable(email: str) -> bool:
    """
    Stub for real email deliverability check.
    You can integrate an external API or SMTP check here.
    For now it always returns True so it won't block signups.
    """
    return True


# ============================================================
# AUTH ENDPOINTS
# ============================================================
@app.post("/signup", status_code=201)
async def signup(data: SignupRequest):
    # Validate username rules
    validate_username_rules(data.username)

    # Ensure passwords match at backend too
    if data.password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Check if email has been verified via OTP (signup flow)
    redis = await get_redis()
    if not redis:
        raise HTTPException(status_code=500, detail="Email verification service unavailable")

    verified = await redis.get(f"signup_verified:{data.identifier}")
    if not verified:
        raise HTTPException(status_code=400, detail="Email not verified. Please verify your email with OTP first.")

    # Ensure email not already taken
    await check_email_not_registered(str(data.identifier))

    # Check username uniqueness
    existing_user = await db.users.find_one({"username": data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken.")

    hashed = hash_password(data.password)
    await db.users.insert_one({
        "username": data.username,
        "identifier": str(data.identifier),
        "password": hashed,
        "privacy_status": "public",  # Default to public, can be changed later
        "followers": [],             # List of usernames following this user
        "following": [],             # List of usernames this user follows
        "full_name": "",             # Display name (can be updated later)
        "bio": "",                   # Profile bio (max 150 chars)
        "website": "",               # Personal website URL
        "profile_picture": "",       # URL to profile picture
        "created_at": datetime.utcnow()
    })

    # Delete verification flag after successful signup
    await redis.delete(f"signup_verified:{data.identifier}")

    return {"message": "User created successfully"}


@app.post("/login", response_model=LoginResponse)
async def login(data: LoginRequest):
    user = await db.users.find_one({"identifier": data.identifier})
    if not user:
        raise HTTPException(status_code=404, detail="Account does not exist")
    if not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    token = create_access_token({"sub": user["identifier"], "username": user.get("username", "User")})

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.get("username", "User")
    }


# ============================================================
# SIGNUP HELPER ENDPOINTS (USERNAME + OTP)
# ============================================================
@app.post("/check-username")
async def check_username(data: CheckUsernameRequest):
    """Check if username is already taken, with validation rules."""
    validate_username_rules(data.username)

    existing = await db.users.find_one({"username": data.username})
    if existing:
        return {"available": False, "message": "Username already taken"}
    return {"available": True, "message": "Username available"}


@app.post("/send-signup-otp")
async def send_signup_otp(data: SendSignupOTPRequest):
    """
    Send OTP to email for signup verification.

    - Validates email format (EmailStr)
    - Optionally validates deliverability (stub)
    - Ensures email not already registered
    """
    # Ensure email is not already used
    await check_email_not_registered(str(data.email))

    # Optional: check deliverability
    if not await check_email_deliverable(str(data.email)):
        raise HTTPException(status_code=400, detail="Email appears to be invalid or unreachable")

    # Generate OTP
    otp = random.randint(100000, 999999)

    # Store OTP in Redis with 5-minute expiry
    redis = await get_redis()
    if not redis:
        raise HTTPException(status_code=500, detail="Failed to store OTP (Redis unavailable)")

    await redis.set(f"signup_otp:{data.email}", str(otp), ex=300)

    # Send email
    try:
        message = MessageSchema(
            subject="Your Signup Verification OTP",
            recipients=[str(data.email)],
            body=f"Your OTP for signup is: {otp}. It expires in 5 minutes.",
            subtype="plain"
        )
        fm = FastMail(conf)
        await fm.send_message(message)
    except Exception as e:
        print("Email error:", e)
        raise HTTPException(status_code=500, detail="Failed to send OTP email")

    return {"message": "OTP sent to email"}


@app.post("/verify-signup-otp")
async def verify_signup_otp(data: VerifyOTPRequest):
    """Verify OTP for signup."""
    redis = await get_redis()
    if not redis:
        raise HTTPException(status_code=500, detail="OTP verification unavailable")

    # Get OTP from Redis
    saved_otp = await redis.get(f"signup_otp:{data.email}")

    if not saved_otp:
        raise HTTPException(status_code=400, detail="No OTP found or OTP expired")

    # Compare OTPs
    if str(data.otp) != saved_otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Set verification flag with 10-minute expiry
    await redis.set(f"signup_verified:{data.email}", "1", ex=600)

    # Delete used OTP
    await redis.delete(f"signup_otp:{data.email}")

    return {"verified": True, "message": "Email verified successfully"}


# ============================================================
# FORGOT PASSWORD FLOW (OTP + RESET)
# ============================================================
@app.post("/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    """
    Forgot password:
    - Ensure account exists
    - Generate OTP
    - Store in Redis with TTL
    - Email to user
    """
    # check user exists
    user = await db.users.find_one({"identifier": str(data.email)})
    if not user:
        raise HTTPException(status_code=404, detail="Account does not exist")

    # generate OTP
    otp = random.randint(100000, 999999)

    # save otp to Redis
    redis = await get_redis()
    if not redis:
        raise HTTPException(status_code=500, detail="Redis issue")

    try:
        await redis.set(f"otp:{data.email}", str(otp), ex=300)
    except Exception as e:
        print("Redis error:", e)
        raise HTTPException(status_code=500, detail="Redis issue")

    # send email
    try:
        message = MessageSchema(
            subject="Your Password Reset OTP",
            recipients=[str(data.email)],
            body=f"Your OTP is: {otp}. It expires in 5 minutes.",
            subtype="plain"
        )
        fm = FastMail(conf)
        await fm.send_message(message)
    except Exception as e:
        print("Email error:", e)
        raise HTTPException(status_code=500, detail="Email sending failed")

    return {"message": "OTP sent to email"}


@app.post("/verify-otp")
async def verify_otp(data: VerifyOTPRequest):
    """
    Verify OTP for password reset.
    - Checks redis for otp:email
    - If valid, creates temporary reset_allowed key
    """
    redis = await get_redis()
    if not redis:
        raise HTTPException(status_code=500, detail="OTP verification unavailable")

    saved = await redis.get(f"otp:{data.email}")
    if not saved:
        raise HTTPException(status_code=400, detail="No OTP request found or OTP expired")

    if str(data.otp) != str(saved):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Mark reset as allowed for this email (10 minutes)
    await redis.set(f"reset_allowed:{data.email}", "1", ex=600)

    # Delete OTP since it has been used
    await redis.delete(f"otp:{data.email}")

    return {"message": "OTP verified"}


@app.post("/reset-password")
async def reset_password(data: ResetPasswordRequest):
    """
    Reset password:
    - Requires prior OTP verification (reset_allowed flag)
    """
    redis = await get_redis()
    if not redis:
        raise HTTPException(status_code=500, detail="Reset service unavailable")

    allowed = await redis.get(f"reset_allowed:{data.email}")
    if not allowed:
        raise HTTPException(status_code=400, detail="OTP not verified or verification expired")

    user = await db.users.find_one({"identifier": str(data.email)})
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")

    hashed = hash_password(data.new_password)
    await db.users.update_one({"identifier": str(data.email)}, {"$set": {"password": hashed}})

    # Delete reset flag
    await redis.delete(f"reset_allowed:{data.email}")

    return {"message": "Password updated successfully"}


# ============================================================
# BASIC ROUTES
# ============================================================
@app.get("/test-db")
async def test_db():
    collections = await db.list_collection_names()
    return {"status": "connected", "collections": collections}


@app.get("/")
def home():
    return {"message": "API is running"}


# ============================================================
# GET: Fetch all posts for FEED (with privacy + block)
# ============================================================
@app.get("/posts")
async def get_posts(current_user: str = ""):
    """
    Fetch all posts, filtered to exclude blocked users AND private accounts (unless followed).
    - Respects block system
    - Respects privacy_status on users
    """
    try:
        # 1. Get list of blocked users (both directions)
        blocked_usernames = set()
        following_list = set()

        if current_user:
            # Get current user to find who they follow
            curr_user_doc = await db.users.find_one({"username": current_user})
            if curr_user_doc:
                following_list = set(curr_user_doc.get("following", []))

            # Users current_user has blocked
            blocks_cursor = db.blocks.find({"blocker": current_user})
            async for block in blocks_cursor:
                blocked_usernames.add(block["blocked"])

            # Users who have blocked current_user
            blocked_by_cursor = db.blocks.find({"blocked": current_user})
            async for block in blocked_by_cursor:
                blocked_usernames.add(block["blocker"])

        # 2. Fetch posts excluding blocked users
        query = {}
        if blocked_usernames:
            query["username"] = {"$nin": list(blocked_usernames)}

        cursor = db.posts.find(query).sort("created_at", -1)

        posts = []
        user_cache = {}  # Cache user privacy status to avoid repeated DB calls

        async for doc in cursor:
            author = doc.get("username")

            # If author is blocked (double check), skip
            if author in blocked_usernames:
                continue

            # If author is current user or in following list, SHOW
            if author == current_user or author in following_list:
                posts.append(serialize_post(doc))
                continue

            # Otherwise, check privacy status
            if author not in user_cache:
                author_doc = await db.users.find_one({"username": author})
                if author_doc:
                    user_cache[author] = author_doc.get("privacy_status", "public")
                else:
                    user_cache[author] = "public"  # Default if user not found

            # If public, SHOW
            if user_cache[author] == "public":
                posts.append(serialize_post(doc))
            # If private and not following (already checked above), SKIP

        return posts
    except Exception as e:
        print("Error:", e)
        raise HTTPException(status_code=500, detail="Failed to fetch posts")


# ============================================================
# NEW: Create Post Endpoint
# Accepts multiple files + form fields, saves files locally and inserts metadata into MongoDB.
# ============================================================
@app.post("/create-post")
async def create_post(
    media: List[UploadFile] = File(...),   # REQUIRED
    caption: str = Form(""),
    description: str = Form(""),
    tags: str = Form(""),
    tagged_users: str = Form(""),  # JSON string of usernames
    feeling: str = Form(""),
    location: str = Form(""),
    music: str = Form(""),
    username: str = Form(...),  # REQUIRED - author username
):
    """
    Expected multipart/form-data:
      - media: array of files (images/videos/audio)
      - caption, description, tags, feeling, location, music: form fields
      - tagged_users: JSON string of usernames (e.g. '["user1", "user2"]')
      - username: author's username (REQUIRED)
    """

    # MEDIA REQUIRED CHECK
    if not media or len(media) == 0:
        raise HTTPException(status_code=400, detail="At least one media file is required")

    # USERNAME REQUIRED CHECK
    if not username or not username.strip():
        raise HTTPException(status_code=400, detail="Username is required")

    saved_files = []
    result = None

    try:
        # Save uploaded files
        for up in media:
            ext = os.path.splitext(up.filename)[1] or ""
            unique_name = f"{uuid.uuid4().hex}{ext}"
            dest_path = os.path.join(UPLOAD_DIR, unique_name)

            async with aiofiles.open(dest_path, "wb") as out_file:
                content = await up.read()
                await out_file.write(content)

            file_url = f"/uploads/{unique_name}"
            saved_files.append({
                "filename": up.filename,
                "saved_as": unique_name,
                "url": file_url,
                "content_type": up.content_type
            })

        # Parse tagged users
        parsed_tagged_users = []
        if tagged_users:
            try:
                parsed_tagged_users = json.loads(tagged_users)
                if not isinstance(parsed_tagged_users, list):
                    parsed_tagged_users = []
            except Exception:
                parsed_tagged_users = []

        # Create final document
        post_doc = {
            "username": username.strip(),  # Store author username
            "caption": caption,
            "description": description,
            "tags": [t.strip() for t in tags.split(",") if t.strip()],
            "tagged_users": parsed_tagged_users,
            "feeling": feeling,
            "location": location,
            "music": music,                 # Title / label for song
            "media": saved_files,           # REQUIRED
            "created_at": datetime.utcnow()
        }

        result = await db.posts.insert_one(post_doc)

        # Store in tagged_users collection
        if parsed_tagged_users:
            tag_docs = []
            for tagged_user in parsed_tagged_users:
                tag_docs.append({
                    "post_id": result.inserted_id,
                    "username": tagged_user,
                    "tagged_by": username.strip(),
                    "created_at": datetime.utcnow()
                })
            if tag_docs:
                await db.tagged_users.insert_many(tag_docs)

    except Exception as e:
        # Remove saved files on failure
        for f in saved_files:
            try:
                os.remove(os.path.join(UPLOAD_DIR, f["saved_as"]))
            except Exception:
                pass

        print("Error in create_post (save/insert):", e)
        raise HTTPException(status_code=500, detail="Internal server error while creating post")

    # Invalidate feed cache after creating a post (non-fatal)
    try:
        redis = await get_redis()
        if redis:
            # delete latest feed key
            await redis.delete("feed:latest")
            # delete paged keys by pattern (non-blocking)
            async for key in redis.scan_iter("feed:page:*"):
                await redis.delete(key)
    except Exception as e:
        # Log but do not fail the request if cache invalidation fails
        print("Warning: failed to invalidate feed cache:", e)

    # Successful response
    post_id = str(result.inserted_id) if result else None
    return JSONResponse(status_code=201, content={"message": "Post created", "post_id": post_id})


@app.get("/posts/{post_id}")
async def get_post(post_id: str):
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")
        post["_id"] = str(post["_id"])
        return post
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Post ID")


# ============================================================
# PUT: Update Post
# ============================================================
@app.put("/posts/{post_id}")
async def update_post(
    post_id: str,
    media: List[UploadFile] = File(None),  # Optional for update
    caption: str = Form(""),
    description: str = Form(""),
    tags: str = Form(""),
    tagged_users: str = Form(""),  # JSON string
    feeling: str = Form(""),
    location: str = Form(""),
    music: str = Form("")
):
    try:
        # Check if post exists
        existing_post = await db.posts.find_one({"_id": ObjectId(post_id)})
        if not existing_post:
            raise HTTPException(status_code=404, detail="Post not found")

        # Parse tagged users
        parsed_tagged_users = []
        if tagged_users:
            try:
                parsed_tagged_users = json.loads(tagged_users)
                if not isinstance(parsed_tagged_users, list):
                    parsed_tagged_users = []
            except Exception:
                parsed_tagged_users = []

        update_data = {
            "caption": caption,
            "description": description,
            "tags": [t.strip() for t in tags.split(",") if t.strip()],
            "tagged_users": parsed_tagged_users,
            "feeling": feeling,
            "location": location,
            "music": music,
            "updated_at": datetime.utcnow()
        }

        # Handle Media Update
        if media and len(media) > 0:
            # Delete old files (best-effort)
            old_media = existing_post.get("media", [])
            for m in old_media:
                try:
                    os.remove(os.path.join(UPLOAD_DIR, m["saved_as"]))
                except Exception:
                    pass

            # Save new files
            saved_files = []
            for up in media:
                ext = os.path.splitext(up.filename)[1] or ""
                unique_name = f"{uuid.uuid4().hex}{ext}"
                dest_path = os.path.join(UPLOAD_DIR, unique_name)

                async with aiofiles.open(dest_path, "wb") as out_file:
                    content = await up.read()
                    await out_file.write(content)

                file_url = f"/uploads/{unique_name}"
                saved_files.append({
                    "filename": up.filename,
                    "saved_as": unique_name,
                    "url": file_url,
                    "content_type": up.content_type
                })

            update_data["media"] = saved_files

        await db.posts.update_one(
            {"_id": ObjectId(post_id)},
            {"$set": update_data}
        )

        # Update tagged_users collection
        # 1. Delete old tags for this post
        await db.tagged_users.delete_many({"post_id": ObjectId(post_id)})

        # 2. Insert new tags
        if parsed_tagged_users:
            tag_docs = []
            # We need the author username. It's in existing_post['username']
            author = existing_post.get("username", "")
            for tagged_user in parsed_tagged_users:
                tag_docs.append({
                    "post_id": ObjectId(post_id),
                    "username": tagged_user,
                    "tagged_by": author,
                    "created_at": datetime.utcnow()
                })
            if tag_docs:
                await db.tagged_users.insert_many(tag_docs)

        return {"message": "Post updated successfully"}

    except Exception as e:
        print("Error updating post:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================
# INTERACTIONS: LIKES & COMMENTS
# ============================================================
class LikeRequest(BaseModel):
    username: str


class CommentRequest(BaseModel):
    username: str
    text: str


@app.post("/posts/{post_id}/like")
async def toggle_like(post_id: str, req: LikeRequest):
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        current_likes = post.get("likes", [])

        if req.username in current_likes:
            # Unlike
            await db.posts.update_one(
                {"_id": ObjectId(post_id)},
                {"$pull": {"likes": req.username}}
            )
            return {"message": "Unliked", "liked": False}
        else:
            # Like
            await db.posts.update_one(
                {"_id": ObjectId(post_id)},
                {"$addToSet": {"likes": req.username}}
            )
            return {"message": "Liked", "liked": True}

    except Exception as e:
        print("Error toggling like:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/posts/{post_id}/likes")
async def get_likes(post_id: str):
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        likes = post.get("likes", [])
        # Return list of objects for frontend consistency
        return [{"username": u} for u in likes]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Post ID")


@app.post("/posts/{post_id}/comment")
async def add_comment(post_id: str, req: CommentRequest):
    try:
        comment = {
            "username": req.username,
            "text": req.text,
            "created_at": datetime.utcnow()
        }

        await db.posts.update_one(
            {"_id": ObjectId(post_id)},
            {"$push": {"comments": comment}}
        )

        return {"message": "Comment added", "comment": comment}
    except Exception as e:
        print("Error adding comment:", e)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/posts/{post_id}/comments")
async def get_comments(post_id: str):
    try:
        post = await db.posts.find_one({"_id": ObjectId(post_id)})
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")

        comments = post.get("comments", [])
        return comments
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Post ID")


# ============================================================
# SEARCH ENDPOINT
# ============================================================
@app.get("/search")
async def search(q: str = "", current_user: str = ""):
    """
    Unified search endpoint with block filtering
    - Partial match
    - Case-insensitive
    - Returns users + posts
    """
    if not q or len(q.strip()) == 0:
        return {"users": [], "posts": []}

    try:
        query = q.strip()
        regex_pattern = {"$regex": query, "$options": "i"}

        # Get blocked users (both directions)
        blocked_usernames = set()
        if current_user:
            blocks_cursor = db.blocks.find({"blocker": current_user})
            async for block in blocks_cursor:
                blocked_usernames.add(block["blocked"])

            blocked_by_cursor = db.blocks.find({"blocked": current_user})
            async for block in blocked_by_cursor:
                blocked_usernames.add(block["blocker"])

        # Search Users (excluding blocked)
        user_query = {
            "$or": [
                {"username": regex_pattern},
                {"identifier": regex_pattern}
            ]
        }
        if blocked_usernames:
            user_query["username"] = {"$nin": list(blocked_usernames)}

        users_cursor = db.users.find(user_query).limit(10)

        users = []
        async for user in users_cursor:
            users.append({
                "_id": str(user["_id"]),
                "username": user.get("username", ""),
                "identifier": user.get("identifier", ""),
                "created_at": str(user.get("created_at", "")),
                "privacy_status": user.get("privacy_status", "public")
            })

        # Search Posts (excluding blocked users)
        post_query = {
            "$or": [
                {"caption": regex_pattern},
                {"description": regex_pattern},
                {"tags": regex_pattern}
            ]
        }
        if blocked_usernames:
            post_query["username"] = {"$nin": list(blocked_usernames)}

        posts_cursor = db.posts.find(post_query).sort("created_at", -1).limit(20)

        posts = []
        async for post in posts_cursor:
            posts.append({
                "_id": str(post["_id"]),
                "username": post.get("username", ""),
                "caption": post.get("caption", ""),
                "description": post.get("description", ""),
                "tags": post.get("tags", []),
                "media": post.get("media", []),
                "created_at": str(post.get("created_at", "")),
                "music": post.get("music", "")
            })

        return {
            "users": users,
            "posts": posts
        }

    except Exception as e:
        print("Search error:", e)
        raise HTTPException(status_code=500, detail="Search failed")


# ============================================================
# USER PROFILE ENDPOINT
# ============================================================
@app.get("/user/{username}")
async def get_user_profile(username: str, current_user: str = ""):
    """
    Get user profile with privacy-based content filtering.
    - Handles public vs private accounts
    - Hides followers/following + posts for private accounts when not followed
    """
    try:
        # Fetch the user
        user = await db.users.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        privacy_status = user.get("privacy_status", "public")
        is_following = current_user in user.get("followers", [])
        is_own_profile = (current_user == username)

        user_info = {
            "_id": str(user["_id"]),
            "username": user.get("username", ""),
            "identifier": user.get("identifier", ""),
            "privacy_status": privacy_status,
            "created_at": str(user.get("created_at", "")),
            "followers_count": len(user.get("followers", [])),
            "following_count": len(user.get("following", [])),
            "full_name": user.get("full_name", ""),
            "bio": user.get("bio", ""),
            "website": user.get("website", ""),
            "profile_picture": user.get("profile_picture", ""),
        }

        # Followers / following lists visibility
        if privacy_status == "private" and not is_following and not is_own_profile:
            user_info["followers"] = []
            user_info["following"] = []
        else:
            user_info["followers"] = user.get("followers", [])
            user_info["following"] = user.get("following", [])

        # Posts visibility
        show_posts = False
        if privacy_status == "public":
            show_posts = True
        elif is_following or is_own_profile:
            show_posts = True

        posts = []
        if show_posts:
            posts_cursor = db.posts.find({"username": username}).sort("created_at", -1)

            async for post in posts_cursor:
                posts.append({
                    "_id": str(post["_id"]),
                    "username": post.get("username", ""),
                    "caption": post.get("caption", ""),
                    "description": post.get("description", ""),
                    "tags": post.get("tags", []),
                    "feeling": post.get("feeling", ""),
                    "location": post.get("location", ""),
                    "music": post.get("music", ""),
                    "tagged_users": post.get("tagged_users", []),
                    "media": post.get("media", []),
                    "likes": post.get("likes", []),
                    "comments": post.get("comments", []),
                    "created_at": str(post.get("created_at", ""))
                })

        return {
            "user": user_info,
            "posts": posts,
            "posts_count": len(posts),
            "privacy_status": privacy_status  # convenient for frontend destructuring
        }

    except Exception as e:
        print("Error fetching user profile:", e)
        raise HTTPException(status_code=500, detail="Failed to fetch user profile")


# ============================================================
# FOLLOW / FOLLOW REQUEST SYSTEM
# ============================================================
class FollowRequest(BaseModel):
    from_user: str  # Username of requester
    to_user: str    # Username of target user


@app.post("/follow/{username}")
async def follow_user(username: str, requester: str = Form(...)):
    """
    Follow a user or send follow request based on privacy.
    - Public account: Follow immediately
    - Private account: Create follow request (pending)
    """
    try:
        # Check if target user exists
        target_user = await db.users.find_one({"username": username})
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if requester exists
        requester_user = await db.users.find_one({"username": requester})
        if not requester_user:
            raise HTTPException(status_code=404, detail="Requester not found")

        # Can't follow yourself
        if username == requester:
            raise HTTPException(status_code=400, detail="Cannot follow yourself")

        # Check if either user has blocked the other
        block_exists = await db.blocks.find_one({
            "$or": [
                {"blocker": requester, "blocked": username},
                {"blocker": username, "blocked": requester}
            ]
        })

        if block_exists:
            raise HTTPException(status_code=403, detail="Cannot follow this user")

        # Check if already following
        if requester in target_user.get("followers", []):
            return {"message": "Already following this user", "status": "following"}

        # Check if request already exists
        existing_request = await db.follow_requests.find_one({
            "from_user": requester,
            "to_user": username,
            "status": "pending"
        })

        if existing_request:
            return {"message": "Follow request already sent", "status": "requested"}

        privacy_status = target_user.get("privacy_status", "public")

        if privacy_status == "public":
            # Auto-follow for public accounts
            await db.users.update_one(
                {"username": username},
                {"$addToSet": {"followers": requester}}
            )
            await db.users.update_one(
                {"username": requester},
                {"$addToSet": {"following": username}}
            )

            return {"message": f"Now following @{username}", "status": "following"}

        else:  # private
            # Create follow request
            await db.follow_requests.insert_one({
                "from_user": requester,
                "to_user": username,
                "status": "pending",
                "created_at": datetime.utcnow()
            })

            return {"message": f"Follow request sent to @{username}", "status": "requested"}

    except HTTPException:
        raise
    except Exception as e:
        print("Error following user:", e)
        raise HTTPException(status_code=500, detail="Failed to follow user")


@app.post("/unfollow/{username}")
async def unfollow_user(username: str, requester: str = Form(...)):
    """
    Unfollow a user
    """
    try:
        # Remove from followers/following
        await db.users.update_one(
            {"username": username},
            {"$pull": {"followers": requester}}
        )
        await db.users.update_one(
            {"username": requester},
            {"$pull": {"following": username}}
        )

        return {"message": f"Unfollowed @{username}", "status": "not_following"}

    except Exception as e:
        print("Error unfollowing user:", e)
        raise HTTPException(status_code=500, detail="Failed to unfollow user")


@app.get("/follow-requests/{username}")
async def get_follow_requests(username: str):
    """
    Get pending follow requests for a user
    """
    try:
        requests_cursor = db.follow_requests.find({
            "to_user": username,
            "status": "pending"
        }).sort("created_at", -1)

        requests = []
        async for req in requests_cursor:
            requests.append({
                "_id": str(req["_id"]),
                "from_user": req["from_user"],
                "to_user": req["to_user"],
                "status": req["status"],
                "created_at": str(req["created_at"])
            })

        return {"requests": requests, "count": len(requests)}

    except Exception as e:
        print("Error fetching follow requests:", e)
        raise HTTPException(status_code=500, detail="Failed to fetch follow requests")


@app.post("/follow-request/{request_id}/accept")
async def accept_follow_request(request_id: str):
    """
    Accept a follow request
    """
    try:
        # Get the request
        request = await db.follow_requests.find_one({"_id": ObjectId(request_id)})

        if not request:
            raise HTTPException(status_code=404, detail="Request not found")

        if request["status"] != "pending":
            raise HTTPException(status_code=400, detail="Request already processed")

        # Update request status
        await db.follow_requests.update_one(
            {"_id": ObjectId(request_id)},
            {"$set": {"status": "accepted"}}
        )

        # Add to followers/following
        await db.users.update_one(
            {"username": request["to_user"]},
            {"$addToSet": {"followers": request["from_user"]}}
        )
        await db.users.update_one(
            {"username": request["from_user"]},
            {"$addToSet": {"following": request["to_user"]}}
        )

        return {"message": "Follow request accepted", "status": "accepted"}

    except HTTPException:
        raise
    except Exception as e:
        print("Error accepting follow request:", e)
        raise HTTPException(status_code=500, detail="Failed to accept request")


@app.post("/follow-request/{request_id}/reject")
async def reject_follow_request(request_id: str):
    """
    Reject a follow request
    """
    try:
        result = await db.follow_requests.update_one(
            {"_id": ObjectId(request_id), "status": "pending"},
            {"$set": {"status": "rejected"}}
        )

        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Request not found or already processed")

        return {"message": "Follow request rejected", "status": "rejected"}

    except HTTPException:
        raise
    except Exception as e:
        print("Error rejecting follow request:", e)
        raise HTTPException(status_code=500, detail="Failed to reject request")


@app.get("/follow-status/{username}")
async def get_follow_status(username: str, current_user: str):
    """
    Check if current_user follows username or has pending request
    """
    try:
        target_user = await db.users.find_one({"username": username})
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if following
        is_following = current_user in target_user.get("followers", [])

        # Check for pending request
        has_pending_request = await db.follow_requests.find_one({
            "from_user": current_user,
            "to_user": username,
            "status": "pending"
        })

        if is_following:
            return {"status": "following"}
        elif has_pending_request:
            return {"status": "requested"}
        else:
            return {"status": "not_following"}

    except HTTPException:
        raise
    except Exception as e:
        print("Error checking follow status:", e)
        raise HTTPException(status_code=500, detail="Failed to check follow status")


# ============================================================
# BLOCK SYSTEM
# ============================================================
@app.post("/block/{username}")
async def block_user(username: str, blocker: str = Form(...)):
    """
    Block a user - prevents all interactions:
    - No posts visible
    - No search
    - No messages
    - No follow in either direction
    """
    try:
        # Check if users exist
        target_user = await db.users.find_one({"username": username})
        blocker_user = await db.users.find_one({"username": blocker})

        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        if not blocker_user:
            raise HTTPException(status_code=404, detail="Blocker not found")

        # Can't block yourself
        if username == blocker:
            raise HTTPException(status_code=400, detail="Cannot block yourself")

        # Check if already blocked
        existing_block = await db.blocks.find_one({
            "blocker": blocker,
            "blocked": username
        })

        if existing_block:
            return {"message": "User already blocked", "status": "blocked"}

        # Create block
        await db.blocks.insert_one({
            "blocker": blocker,
            "blocked": username,
            "created_at": datetime.utcnow()
        })

        # Remove from followers/following if exists (both directions)
        await db.users.update_one(
            {"username": username},
            {"$pull": {"followers": blocker}}
        )
        await db.users.update_one(
            {"username": blocker},
            {"$pull": {"following": username}}
        )
        await db.users.update_one(
            {"username": blocker},
            {"$pull": {"followers": username}}
        )
        await db.users.update_one(
            {"username": username},
            {"$pull": {"following": blocker}}
        )

        # Remove any pending follow requests
        await db.follow_requests.delete_many({
            "$or": [
                {"from_user": blocker, "to_user": username},
                {"from_user": username, "to_user": blocker}
            ]
        })

        return {"message": f"Blocked @{username}", "status": "blocked"}

    except HTTPException:
        raise
    except Exception as e:
        print("Error blocking user:", e)
        raise HTTPException(status_code=500, detail="Failed to block user")


@app.post("/unblock/{username}")
async def unblock_user(username: str, blocker: str = Form(...)):
    """
    Unblock a user
    """
    try:
        result = await db.blocks.delete_one({
            "blocker": blocker,
            "blocked": username
        })

        if result.deleted_count == 0:
            return {"message": "User was not blocked", "status": "not_blocked"}

        return {"message": f"Unblocked @{username}", "status": "unblocked"}

    except Exception as e:
        print("Error unblocking user:", e)
        raise HTTPException(status_code=500, detail="Failed to unblock user")


@app.get("/blocked-users/{username}")
async def get_blocked_users(username: str):
    """
    Get list of users that this user has blocked
    """
    try:
        blocks_cursor = db.blocks.find({"blocker": username})
        blocked_users = []

        async for block in blocks_cursor:
            blocked_users.append({
                "username": block["blocked"],
                "blocked_at": str(block["created_at"])
            })

        return {"blocked_users": blocked_users, "count": len(blocked_users)}

    except Exception as e:
        print("Error fetching blocked users:", e)
        raise HTTPException(status_code=500, detail="Failed to fetch blocked users")


@app.get("/block-status/{username}")
async def check_block_status(username: str, current_user: str):
    """
    Check if current_user has blocked username or vice versa
    """
    try:
        # Check if current_user blocked username
        user_blocked_target = await db.blocks.find_one({
            "blocker": current_user,
            "blocked": username
        })

        # Check if username blocked current_user
        target_blocked_user = await db.blocks.find_one({
            "blocker": username,
            "blocked": current_user
        })

        if user_blocked_target:
            return {"status": "you_blocked", "blocked": True}
        elif target_blocked_user:
            return {"status": "blocked_you", "blocked": True}
        else:
            return {"status": "not_blocked", "blocked": False}

    except Exception as e:
        print("Error checking block status:", e)
        raise HTTPException(status_code=500, detail="Failed to check block status")
