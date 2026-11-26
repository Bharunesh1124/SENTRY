from enum import Enum
from pydantic import BaseModel, Field


class Capability(str, Enum):
    FS_READ = "FS_READ"
    FS_WRITE = "FS_WRITE"
    NET_INGRESS = "NET_INGRESS"
    NET_EGRESS = "NET_EGRESS"
    SHELL_EXEC = "SHELL_EXEC"
    DB_EXEC = "DB_EXEC"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ToolInfo(BaseModel):
    id: str
    name: str
    file: str
    line: int
    params: list[str] = Field(default_factory=list)
    framework: str = "generic"


class SinkHit(BaseModel):
    sink_name: str
    capability: Capability
    file: str
    line: int
    call_path: list[str] = Field(default_factory=list)
    tainted: bool = True
    guarded: bool = False
    guard_reason: str | None = None


class ToolReport(BaseModel):
    tool: ToolInfo
    hits: list[SinkHit] = Field(default_factory=list)

    @property
    def capabilities(self) -> set[Capability]:
        return {hit.capability for hit in self.hits}

    @property
    def active_capabilities(self) -> set[Capability]:
        """Capabilities that are both tainted (non-constant) and unguarded."""
        return {hit.capability for hit in self.hits if hit.tainted and not hit.guarded}


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    tools: list[str]
    description: str
    witness_paths: list[str] = Field(default_factory=list)
    recommendation: str


class ScanResult(BaseModel):
    target: str
    files_scanned: int
    functions_parsed: int = 0
    call_edges: int = 0
    scan_ms: float = 0.0
    tools: list[ToolReport] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    blast_radius_score: int = 0
