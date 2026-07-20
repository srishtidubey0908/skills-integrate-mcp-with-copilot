"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import os
import secrets
from pathlib import Path
from typing import Dict

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(
    title="Mergington High School API",
    description="API for viewing and signing up for extracurricular activities",
)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(Path(__file__).parent, "static")),
    name="static",
)

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"],
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"],
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"],
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"],
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"],
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"],
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"],
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"],
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"],
    },
}

# In-memory user database with roles
users = {
    "admin@mergington.edu": {
        "username": "admin@mergington.edu",
        "password": "adminpass",
        "role": "admin",
    },
    "student@mergington.edu": {
        "username": "student@mergington.edu",
        "password": "studentpass",
        "role": "student",
    },
}

# Simple in-memory token store for session-style auth
sessions: Dict[str, Dict[str, str]] = {}
security = HTTPBearer()


class LoginRequest(BaseModel):
    username: str
    password: str


class ActivityPayload(BaseModel):
    description: str
    schedule: str
    max_participants: int


class User(BaseModel):
    username: str
    role: str


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    token = credentials.credentials
    session = sessions.get(token)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication credentials",
        )

    return User(username=session["username"], role=session["role"])


def require_role(required_role: str):
    def role_dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_dependency


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.post("/login")
def login(request: LoginRequest):
    user = users.get(request.username)
    if not user or user["password"] != request.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = secrets.token_urlsafe(32)
    sessions[token] = {"username": user["username"], "role": user["role"]}
    return {"access_token": token, "token_type": "bearer", "role": user["role"]}


@app.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    token = None
    authorization = None
    # The HTTPBearer dependency has already validated the header
    # We simply remove the session token by reverse lookup.
    for saved_token, session in list(sessions.items()):
        if session["username"] == current_user.username:
            token = saved_token
            break

    if token:
        sessions.pop(token, None)

    return {"message": "Logged out"}


@app.get("/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities")
def create_activity(
    activity_name: str,
    payload: ActivityPayload,
    current_user: User = Depends(require_role("admin")),
):
    if activity_name in activities:
        raise HTTPException(status_code=400, detail="Activity already exists")

    activities[activity_name] = {
        "description": payload.description,
        "schedule": payload.schedule,
        "max_participants": payload.max_participants,
        "participants": [],
    }
    return {"message": f"Created activity {activity_name}"}


@app.put("/activities/{activity_name}")
def update_activity(
    activity_name: str,
    payload: ActivityPayload,
    current_user: User = Depends(require_role("admin")),
):
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activities[activity_name].update(
        {
            "description": payload.description,
            "schedule": payload.schedule,
            "max_participants": payload.max_participants,
        }
    )
    return {"message": f"Updated activity {activity_name}"}


@app.delete("/activities/{activity_name}")
def delete_activity(
    activity_name: str,
    current_user: User = Depends(require_role("admin")),
):
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activities.pop(activity_name)
    return {"message": f"Deleted activity {activity_name}"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]

    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up",
        )

    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str):
    """Unregister a student from an activity"""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]

    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity",
        )

    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
