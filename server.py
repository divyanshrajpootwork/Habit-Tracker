from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production-' + str(uuid.uuid4()))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 43200  # 30 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    username: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class Habit(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    name: str
    description: Optional[str] = None
    category: str
    frequency_type: str  # daily, weekly, custom
    frequency_value: Optional[int] = None  # for custom: times per week
    color: str = "#6366f1"
    icon: str = "target"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_archived: bool = False

class HabitCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: str
    frequency_type: str
    frequency_value: Optional[int] = None
    color: str = "#6366f1"
    icon: str = "target"

class HabitLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    habit_id: str
    user_id: str
    date: str  # YYYY-MM-DD format
    completed: bool = True
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class HabitLogCreate(BaseModel):
    habit_id: str
    date: str
    completed: bool = True
    notes: Optional[str] = None

class Reminder(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    habit_id: str
    user_id: str
    time: str  # HH:MM format
    days: List[str]  # ["monday", "tuesday", ...]
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ReminderCreate(BaseModel):
    habit_id: str
    time: str
    days: List[str]
    enabled: bool = True

class AnalyticsResponse(BaseModel):
    total_habits: int
    active_habits: int
    total_completions: int
    current_streak: int
    longest_streak: int
    completion_rate: float
    weekly_stats: List[Dict[str, Any]]
    category_stats: List[Dict[str, Any]]

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user is None:
        raise credentials_exception
    
    return User(**user)

# Auth endpoints
@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        username=user_data.username
    )
    
    user_dict = user.model_dump()
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    user_dict['password_hash'] = get_password_hash(user_data.password)
    
    await db.users.insert_one(user_dict)
    
    # Create access token
    access_token = create_access_token(data={"sub": user.id})
    
    return Token(access_token=access_token, token_type="bearer", user=user)

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if not user or not verify_password(user_data.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    user_obj = User(**user)
    access_token = create_access_token(data={"sub": user_obj.id})
    
    return Token(access_token=access_token, token_type="bearer", user=user_obj)

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# Habit endpoints
@api_router.post("/habits", response_model=Habit)
async def create_habit(habit_data: HabitCreate, current_user: User = Depends(get_current_user)):
    habit = Habit(**habit_data.model_dump(), user_id=current_user.id)
    
    habit_dict = habit.model_dump()
    habit_dict['created_at'] = habit_dict['created_at'].isoformat()
    
    await db.habits.insert_one(habit_dict)
    return habit

@api_router.get("/habits", response_model=List[Habit])
async def get_habits(current_user: User = Depends(get_current_user), include_archived: bool = False):
    query = {"user_id": current_user.id}
    if not include_archived:
        query["is_archived"] = False
    
    habits = await db.habits.find(query, {"_id": 0}).to_list(1000)
    
    for habit in habits:
        if isinstance(habit['created_at'], str):
            habit['created_at'] = datetime.fromisoformat(habit['created_at'])
    
    return habits

@api_router.get("/habits/{habit_id}", response_model=Habit)
async def get_habit(habit_id: str, current_user: User = Depends(get_current_user)):
    habit = await db.habits.find_one({"id": habit_id, "user_id": current_user.id}, {"_id": 0})
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    if isinstance(habit['created_at'], str):
        habit['created_at'] = datetime.fromisoformat(habit['created_at'])
    
    return Habit(**habit)

@api_router.put("/habits/{habit_id}", response_model=Habit)
async def update_habit(habit_id: str, habit_data: HabitCreate, current_user: User = Depends(get_current_user)):
    habit = await db.habits.find_one({"id": habit_id, "user_id": current_user.id})
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    update_data = habit_data.model_dump(exclude_unset=True)
    await db.habits.update_one({"id": habit_id}, {"$set": update_data})
    
    updated_habit = await db.habits.find_one({"id": habit_id}, {"_id": 0})
    if isinstance(updated_habit['created_at'], str):
        updated_habit['created_at'] = datetime.fromisoformat(updated_habit['created_at'])
    
    return Habit(**updated_habit)

@api_router.delete("/habits/{habit_id}")
async def delete_habit(habit_id: str, current_user: User = Depends(get_current_user)):
    result = await db.habits.delete_one({"id": habit_id, "user_id": current_user.id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    # Also delete related logs and reminders
    await db.habit_logs.delete_many({"habit_id": habit_id})
    await db.reminders.delete_many({"habit_id": habit_id})
    
    return {"message": "Habit deleted successfully"}

@api_router.patch("/habits/{habit_id}/archive")
async def archive_habit(habit_id: str, current_user: User = Depends(get_current_user)):
    result = await db.habits.update_one(
        {"id": habit_id, "user_id": current_user.id},
        {"$set": {"is_archived": True}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    return {"message": "Habit archived successfully"}

# Habit Log endpoints
@api_router.post("/logs", response_model=HabitLog)
async def create_log(log_data: HabitLogCreate, current_user: User = Depends(get_current_user)):
    # Verify habit belongs to user
    habit = await db.habits.find_one({"id": log_data.habit_id, "user_id": current_user.id})
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    # Check if log already exists
    existing_log = await db.habit_logs.find_one({
        "habit_id": log_data.habit_id,
        "user_id": current_user.id,
        "date": log_data.date
    })
    
    if existing_log:
        # Update existing log
        await db.habit_logs.update_one(
            {"id": existing_log['id']},
            {"$set": {"completed": log_data.completed, "notes": log_data.notes}}
        )
        updated_log = await db.habit_logs.find_one({"id": existing_log['id']}, {"_id": 0})
        if isinstance(updated_log['created_at'], str):
            updated_log['created_at'] = datetime.fromisoformat(updated_log['created_at'])
        return HabitLog(**updated_log)
    
    # Create new log
    log = HabitLog(**log_data.model_dump(), user_id=current_user.id)
    
    log_dict = log.model_dump()
    log_dict['created_at'] = log_dict['created_at'].isoformat()
    
    await db.habit_logs.insert_one(log_dict)
    return log

@api_router.get("/logs", response_model=List[HabitLog])
async def get_logs(
    current_user: User = Depends(get_current_user),
    habit_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
):
    query = {"user_id": current_user.id}
    if habit_id:
        query["habit_id"] = habit_id
    if start_date:
        query["date"] = {"$gte": start_date}
    if end_date:
        if "date" in query:
            query["date"]["$lte"] = end_date
        else:
            query["date"] = {"$lte": end_date}
    
    logs = await db.habit_logs.find(query, {"_id": 0}).to_list(10000)
    
    for log in logs:
        if isinstance(log['created_at'], str):
            log['created_at'] = datetime.fromisoformat(log['created_at'])
    
    return logs

@api_router.delete("/logs/{log_id}")
async def delete_log(log_id: str, current_user: User = Depends(get_current_user)):
    result = await db.habit_logs.delete_one({"id": log_id, "user_id": current_user.id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Log not found")
    
    return {"message": "Log deleted successfully"}

# Reminder endpoints
@api_router.post("/reminders", response_model=Reminder)
async def create_reminder(reminder_data: ReminderCreate, current_user: User = Depends(get_current_user)):
    # Verify habit belongs to user
    habit = await db.habits.find_one({"id": reminder_data.habit_id, "user_id": current_user.id})
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    reminder = Reminder(**reminder_data.model_dump(), user_id=current_user.id)
    
    reminder_dict = reminder.model_dump()
    reminder_dict['created_at'] = reminder_dict['created_at'].isoformat()
    
    await db.reminders.insert_one(reminder_dict)
    return reminder

@api_router.get("/reminders", response_model=List[Reminder])
async def get_reminders(current_user: User = Depends(get_current_user), habit_id: Optional[str] = None):
    query = {"user_id": current_user.id}
    if habit_id:
        query["habit_id"] = habit_id
    
    reminders = await db.reminders.find(query, {"_id": 0}).to_list(1000)
    
    for reminder in reminders:
        if isinstance(reminder['created_at'], str):
            reminder['created_at'] = datetime.fromisoformat(reminder['created_at'])
    
    return reminders

@api_router.delete("/reminders/{reminder_id}")
async def delete_reminder(reminder_id: str, current_user: User = Depends(get_current_user)):
    result = await db.reminders.delete_one({"id": reminder_id, "user_id": current_user.id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Reminder not found")
    
    return {"message": "Reminder deleted successfully"}

# Analytics endpoints
@api_router.get("/analytics", response_model=AnalyticsResponse)
async def get_analytics(current_user: User = Depends(get_current_user)):
    # Get all habits
    habits = await db.habits.find({"user_id": current_user.id}, {"_id": 0}).to_list(1000)
    active_habits = [h for h in habits if not h.get('is_archived', False)]
    
    # Get all logs
    logs = await db.habit_logs.find({"user_id": current_user.id, "completed": True}, {"_id": 0}).to_list(10000)
    
    # Calculate streaks
    today = datetime.now(timezone.utc).date()
    current_streak = 0
    longest_streak = 0
    temp_streak = 0
    
    # Sort logs by date
    sorted_dates = sorted(set(log['date'] for log in logs), reverse=True)
    
    for i, date_str in enumerate(sorted_dates):
        date = datetime.strptime(date_str, "%Y-%m-%d").date()
        expected_date = today - timedelta(days=i)
        
        if date == expected_date:
            current_streak += 1
            temp_streak += 1
        else:
            break
    
    # Calculate longest streak
    if sorted_dates:
        sorted_dates_asc = sorted(set(log['date'] for log in logs))
        temp_streak = 1
        for i in range(1, len(sorted_dates_asc)):
            prev_date = datetime.strptime(sorted_dates_asc[i-1], "%Y-%m-%d").date()
            curr_date = datetime.strptime(sorted_dates_asc[i], "%Y-%m-%d").date()
            
            if (curr_date - prev_date).days == 1:
                temp_streak += 1
                longest_streak = max(longest_streak, temp_streak)
            else:
                temp_streak = 1
        longest_streak = max(longest_streak, temp_streak)
    
    # Calculate completion rate (last 30 days)
    thirty_days_ago = (today - timedelta(days=30)).strftime("%Y-%m-%d")
    recent_logs = [log for log in logs if log['date'] >= thirty_days_ago]
    
    expected_completions = len(active_habits) * 30
    actual_completions = len(recent_logs)
    completion_rate = (actual_completions / expected_completions * 100) if expected_completions > 0 else 0
    
    # Weekly stats (last 7 days)
    weekly_stats = []
    for i in range(6, -1, -1):
        date = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        day_logs = [log for log in logs if log['date'] == date]
        weekly_stats.append({
            "date": date,
            "completions": len(day_logs)
        })
    
    # Category stats
    category_counts = {}
    for habit in active_habits:
        category = habit.get('category', 'Other')
        if category not in category_counts:
            category_counts[category] = 0
        category_counts[category] += 1
    
    category_stats = [{"category": k, "count": v} for k, v in category_counts.items()]
    
    return AnalyticsResponse(
        total_habits=len(habits),
        active_habits=len(active_habits),
        total_completions=len(logs),
        current_streak=current_streak,
        longest_streak=longest_streak,
        completion_rate=round(completion_rate, 1),
        weekly_stats=weekly_stats,
        category_stats=category_stats
    )

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
