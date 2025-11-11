type UserRole = "ADMIN" | "ANALYST" | "USER";

type Permission = string;

interface RolePermissions {
  [role: string]: Permission[];
}

const rolePermissions: RolePermissions = {
  ADMIN: [
    "create:project",
    "read:project",
    "update:project",
    "delete:project",
    "create:assessment",
    "read:assessment",
    "update:assessment",
    "delete:assessment",
    "create:finding",
    "read:finding",
    "update:finding",
    "delete:finding",
    "export:pdf",
    "export:csv",
    "export:json",
    "manage:users",
  ],
  ANALYST: [
    "create:project",
    "read:project",
    "update:project",
    "create:assessment",
    "read:assessment",
    "update:assessment",
    "create:finding",
    "read:finding",
    "update:finding",
    "export:pdf",
    "export:csv",
    "export:json",
  ],
  USER: [
    "read:project",
    "read:assessment",
    "read:finding",
    "export:pdf",
    "export:csv",
  ],
};

export function hasPermission(role: UserRole, permission: Permission): boolean {
  const permissions = rolePermissions[role];
  return permissions ? permissions.includes(permission) : false;
}

export function hasAnyPermission(
  role: UserRole,
  permissions: Permission[]
): boolean {
  return permissions.some((p) => hasPermission(role, p));
}

export function hasAllPermissions(
  role: UserRole,
  permissions: Permission[]
): boolean {
  return permissions.every((p) => hasPermission(role, p));
}
