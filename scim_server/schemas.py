"""RFC 7643 / 7644 SCIM 2.0 Pydantic models and error responses."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimName(BaseModel):
    formatted: Optional[str] = None
    familyName: Optional[str] = None
    givenName: Optional[str] = None


class ScimEmail(BaseModel):
    value: str
    type: Optional[str] = "work"
    primary: Optional[bool] = True


class ScimMeta(BaseModel):
    resourceType: str
    created: str
    lastModified: str
    location: str


class ScimUserCreate(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCIM_USER_SCHEMA])
    externalId: Optional[str] = None
    userName: str
    name: Optional[ScimName] = None
    displayName: Optional[str] = None
    emails: List[ScimEmail] = Field(default_factory=list)
    active: bool = True
    title: Optional[str] = None
    department: Optional[str] = None


class ScimPatchOperation(BaseModel):
    op: str
    path: Optional[str] = None
    value: Any = None


class ScimPatchRequest(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCIM_PATCH_SCHEMA])
    Operations: List[ScimPatchOperation]


class ScimGroupMember(BaseModel):
    value: str
    display: Optional[str] = None
    ref: Optional[str] = Field(default=None, alias="$ref")


class ScimGroupCreate(BaseModel):
    schemas: List[str] = Field(default_factory=lambda: [SCIM_GROUP_SCHEMA])
    externalId: Optional[str] = None
    displayName: str
    members: List[ScimGroupMember] = Field(default_factory=list)


def scim_error_payload(status: int, detail: str, scim_type: Optional[str] = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return body