import uuid
from datetime import datetime,timezone
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, DateTime, Boolean, BigInteger,ForeignKey,UniqueConstraint, Index, Enum as SqlEnum
from werkzeug.security import generate_password_hash, check_password_hash
import enum
from app.extension import db
from sqlalchemy.schema import Sequence


class Role(db.Model):
    __tablename__ = 'roles'
    role_id = Column(BigInteger, primary_key=True, autoincrement=True)
    role_name = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    role_permissions = db.relationship('RolePermission', back_populates='role', cascade='all, delete-orphan')

class Client(db.Model):
    __tablename__ = 'clients'
    client_id = Column(BigInteger, primary_key=True, autoincrement=True)
    org_name = Column(String, nullable=False)
    org_email = Column(String, nullable=False)
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    created_by = db.relationship('User', back_populates='created_clients', foreign_keys=[created_by_user_id])
    users = db.relationship('User', back_populates='client', foreign_keys='User.client_id',cascade='all, delete-orphan')  
    departments = db.relationship('Department', back_populates='client',cascade='all, delete-orphan')

class Department(db.Model):
    __tablename__ = 'departments'
    department_id = Column(BigInteger, primary_key=True, autoincrement=True)
    department_name = Column(String, nullable=False)
    client_id = Column(BigInteger, ForeignKey('clients.client_id'), nullable=False)
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint('department_name', 'client_id', name='uq_department_name_per_client'),
    )

    client = db.relationship('Client', back_populates='departments')
    created_by = db.relationship('User', back_populates='created_departments', foreign_keys=[created_by_user_id])  
    users = db.relationship('User', back_populates='department',  foreign_keys='User.department_id')
    user_permissions = db.relationship('UserPermission', back_populates='department', cascade='all, delete-orphan')



class User(db.Model):
    __tablename__ = "users"

    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    normal_user_id = Column(
    BigInteger,
    Sequence('normal_user_id_seq', start=1, increment=1),
    unique=True,
    nullable=False,
    server_default=db.text("nextval('normal_user_id_seq')")
)
    user_name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    mobile_number = Column(String, nullable=True)
    is_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=False)
    must_reset_password  = Column(Boolean, default=False)
    last_active_date = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_deactive_date = Column(DateTime, nullable=True)
    
    role_id = Column(BigInteger, ForeignKey('roles.role_id'), nullable=False)
    client_id = Column(BigInteger, ForeignKey('clients.client_id'))
    department_id = Column(BigInteger, ForeignKey('departments.department_id'))
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


    role = db.relationship('Role')
    client = db.relationship('Client', back_populates='users', foreign_keys=[client_id])
    department = db.relationship('Department', back_populates='users', foreign_keys=[department_id])
    created_by = db.relationship('User', remote_side=[user_id], back_populates='created_users', foreign_keys=[created_by_user_id])

    created_clients = db.relationship('Client', back_populates='created_by', foreign_keys=[Client.created_by_user_id])
    created_departments = db.relationship('Department', back_populates='created_by', foreign_keys=[Department.created_by_user_id])
    created_users = db.relationship('User', back_populates='created_by', foreign_keys=[created_by_user_id])
    user_permissions = db.relationship('UserPermission', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    @property
    def role_name(self):
        return self.role.role_name if self.role else None
    
    @property
    def department_name(self):
        return self.department.department_name if self.department else None

    def deactivate(self):
        self.is_active = False
        self.last_deactive_date = datetime.now(timezone.utc)

    def activate(self):
        self.is_active = True
        self.last_deactive_date = None

    def update_last_active(self):
        self.last_active_date = datetime.now(timezone.utc)


class Permission(db.Model):
    __tablename__ = 'permissions'

    permission_id = Column(BigInteger, primary_key=True, autoincrement=True)
    module_name = Column(String(50), nullable=False)         
    permission_name = Column(String(50), nullable=False)   
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)  

    __table_args__ = (
        UniqueConstraint('module_name', 'permission_name', name='uq_module_permission'),
    )

    role_permissions = db.relationship('RolePermission', back_populates='permission', cascade='all, delete-orphan')
    user_permissions = db.relationship('UserPermission', back_populates='permission', cascade='all, delete-orphan')


class ScopeEnum(enum.Enum):
    own_org = 'own_org'
    all = 'all'

class RolePermission(db.Model):
    __tablename__ = 'role_permissions'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    role_id = Column(BigInteger, ForeignKey('roles.role_id'), nullable=False)
    permission_id = Column(BigInteger, ForeignKey('permissions.permission_id'), nullable=False)
    scope = Column(SqlEnum(ScopeEnum), nullable=False, default=ScopeEnum.own_org)  # 'own_org', 'all'

    __table_args__ = (
        UniqueConstraint('role_id', 'permission_id', name='uq_role_permission'),
    )

    role = db.relationship('Role', back_populates='role_permissions')
    permission = db.relationship('Permission', back_populates='role_permissions')

class UserPermission(db.Model):
    __tablename__ = 'user_permissions'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.user_id'), nullable=False)
    department_id = Column(BigInteger, ForeignKey('departments.department_id'), nullable=False)
    permission_id = Column(BigInteger, ForeignKey('permissions.permission_id'), nullable=False)

    __table_args__ = (
        UniqueConstraint('user_id', 'permission_id', 'department_id', name='uq_user_permission_dept'),
    )
    user = db.relationship('User', back_populates='user_permissions')
    permission = db.relationship('Permission', back_populates='user_permissions')
    department = db.relationship('Department', back_populates='user_permissions')

 
















