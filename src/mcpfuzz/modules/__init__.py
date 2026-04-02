from .path_traversal import PathTraversalModule
from .command_injection import CommandInjectionModule
from .hardcoded_secrets import HardcodedSecretsModule
from .ssrf import SSRFModule
from .auth_bypass import AuthBypassModule
from .dns_rebinding import DNSRebindingModule
from .protocol_fuzzing import ProtocolFuzzingModule
from .tool_poisoning import ToolPoisoningModule
from .rug_pull import RugPullModule
from .idor_bola import IDORBOLAModule
from .cve_checks import CVEChecksModule
from .sql_injection import SQLInjectionModule

ALL_MODULES = [
    PathTraversalModule(),
    CommandInjectionModule(),
    SQLInjectionModule(),
    HardcodedSecretsModule(),
    SSRFModule(),
    AuthBypassModule(),
    DNSRebindingModule(),
    ProtocolFuzzingModule(),
    ToolPoisoningModule(),
    RugPullModule(),
    IDORBOLAModule(),
    CVEChecksModule(),
]

MODULE_MAP = {m.module_id: m for m in ALL_MODULES}

__all__ = [
    "ALL_MODULES", "MODULE_MAP",
    "PathTraversalModule", "CommandInjectionModule", "SQLInjectionModule",
    "HardcodedSecretsModule", "SSRFModule", "AuthBypassModule", "DNSRebindingModule",
    "ProtocolFuzzingModule", "ToolPoisoningModule", "RugPullModule",
    "IDORBOLAModule", "CVEChecksModule",
]
