from sqlmodel import SQLModel, Field, Relationship, JSON, Column
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class RoleType(str, Enum):
    """Enumeration for user roles"""

    ADMIN = "admin"
    STAFF = "staff"
    USER = "user"


class UserStatus(str, Enum):
    """Enumeration for user account status"""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


# Persistent models (stored in database)
class Role(SQLModel, table=True):
    """Role model for role-based access control"""

    __tablename__ = "roles"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    name: RoleType = Field(unique=True, max_length=50)
    description: str = Field(max_length=255)
    permissions: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))  # Store permissions as JSON
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    users: List["User"] = Relationship(back_populates="role")


class User(SQLModel, table=True):
    """User model with authentication and profile information"""

    __tablename__ = "users"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, max_length=50, min_length=3)
    email: str = Field(unique=True, max_length=255, regex=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    password_hash: str = Field(max_length=255)  # Store hashed password
    first_name: str = Field(max_length=100)
    last_name: str = Field(max_length=100)
    status: UserStatus = Field(default=UserStatus.ACTIVE)
    last_login: Optional[datetime] = Field(default=None)
    login_attempts: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Foreign keys
    role_id: int = Field(foreign_key="roles.id")

    # Relationships
    role: Role = Relationship(back_populates="users")
    sessions: List["UserSession"] = Relationship(back_populates="user")
    audit_logs: List["AuditLog"] = Relationship(back_populates="user")


class UserSession(SQLModel, table=True):
    """User session tracking for security and analytics"""

    __tablename__ = "user_sessions"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    session_token: str = Field(unique=True, max_length=255)
    user_id: int = Field(foreign_key="users.id")
    ip_address: str = Field(max_length=45)  # Support IPv6
    user_agent: str = Field(max_length=512)
    is_active: bool = Field(default=True)
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_accessed: datetime = Field(default_factory=datetime.utcnow)

    # Relationships
    user: User = Relationship(back_populates="sessions")


class AuditLog(SQLModel, table=True):
    """Audit log for tracking user actions and system events"""

    __tablename__ = "audit_logs"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="users.id")
    action: str = Field(max_length=100)  # e.g., "login", "logout", "create_user", "update_role"
    resource: str = Field(max_length=100)  # e.g., "user", "role", "dashboard"
    resource_id: Optional[str] = Field(default=None, max_length=50)
    details: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))  # Additional context
    ip_address: str = Field(max_length=45)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    success: bool = Field(default=True)
    error_message: Optional[str] = Field(default=None, max_length=512)

    # Relationships
    user: Optional[User] = Relationship(back_populates="audit_logs")


class DashboardWidget(SQLModel, table=True):
    """Configuration for dashboard widgets and their permissions"""

    __tablename__ = "dashboard_widgets"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=100)
    title: str = Field(max_length=200)
    widget_type: str = Field(max_length=50)  # e.g., "card", "chart", "table"
    config: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))  # Widget configuration
    required_permissions: List[str] = Field(default=[], sa_column=Column(JSON))  # Required permissions to view
    is_active: bool = Field(default=True)
    sort_order: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class DashboardMetric(SQLModel, table=True):
    """Store dashboard metrics and statistics data"""

    __tablename__ = "dashboard_metrics"  # type: ignore[assignment]

    id: Optional[int] = Field(default=None, primary_key=True)
    metric_name: str = Field(max_length=100)
    metric_value: str = Field(max_length=255)  # Store as string to handle various data types
    metric_type: str = Field(max_length=50)  # e.g., "count", "percentage", "currency"
    category: str = Field(max_length=100)  # Group related metrics
    extra_data: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))  # Additional metric data
    recorded_at: datetime = Field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = Field(default=None)  # For caching purposes


# Non-persistent schemas (for validation, forms, API requests/responses)
class UserCreate(SQLModel, table=False):
    """Schema for creating a new user"""

    username: str = Field(max_length=50, min_length=3)
    email: str = Field(max_length=255)
    password: str = Field(min_length=8)  # Plain password, will be hashed
    first_name: str = Field(max_length=100)
    last_name: str = Field(max_length=100)
    role_id: int


class UserUpdate(SQLModel, table=False):
    """Schema for updating user information"""

    username: Optional[str] = Field(default=None, max_length=50, min_length=3)
    email: Optional[str] = Field(default=None, max_length=255)
    first_name: Optional[str] = Field(default=None, max_length=100)
    last_name: Optional[str] = Field(default=None, max_length=100)
    status: Optional[UserStatus] = Field(default=None)
    role_id: Optional[int] = Field(default=None)


class UserLogin(SQLModel, table=False):
    """Schema for user login credentials"""

    username: str = Field(max_length=50)
    password: str


class UserResponse(SQLModel, table=False):
    """Schema for user data in API responses (excludes sensitive information)"""

    id: int
    username: str
    email: str
    first_name: str
    last_name: str
    status: UserStatus
    last_login: Optional[datetime]
    created_at: datetime
    role_name: RoleType


class RoleCreate(SQLModel, table=False):
    """Schema for creating a new role"""

    name: RoleType
    description: str = Field(max_length=255)
    permissions: Dict[str, Any] = Field(default={})


class RoleUpdate(SQLModel, table=False):
    """Schema for updating role information"""

    description: Optional[str] = Field(default=None, max_length=255)
    permissions: Optional[Dict[str, Any]] = Field(default=None)


class DashboardWidgetCreate(SQLModel, table=False):
    """Schema for creating dashboard widgets"""

    name: str = Field(max_length=100)
    title: str = Field(max_length=200)
    widget_type: str = Field(max_length=50)
    config: Dict[str, Any] = Field(default={})
    required_permissions: List[str] = Field(default=[])
    sort_order: int = Field(default=0)


class DashboardWidgetUpdate(SQLModel, table=False):
    """Schema for updating dashboard widgets"""

    name: Optional[str] = Field(default=None, max_length=100)
    title: Optional[str] = Field(default=None, max_length=200)
    widget_type: Optional[str] = Field(default=None, max_length=50)
    config: Optional[Dict[str, Any]] = Field(default=None)
    required_permissions: Optional[List[str]] = Field(default=None)
    is_active: Optional[bool] = Field(default=None)
    sort_order: Optional[int] = Field(default=None)


class PasswordChange(SQLModel, table=False):
    """Schema for password change requests"""

    current_password: str
    new_password: str = Field(min_length=8)
    confirm_password: str


class MetricCreate(SQLModel, table=False):
    """Schema for creating dashboard metrics"""

    metric_name: str = Field(max_length=100)
    metric_value: str = Field(max_length=255)
    metric_type: str = Field(max_length=50)
    category: str = Field(max_length=100)
    extra_data: Dict[str, Any] = Field(default={})
    valid_until: Optional[datetime] = Field(default=None)
