"""CyberShell Copilot package."""

__version__ = "0.2.0"

from cybershell.engine import SuggestionEngine
from cybershell.models import RiskLevel, ShellContext, SuggestionResult
from cybershell.policy import Policy, PolicyRegistry

__all__ = [
    "Policy",
    "PolicyRegistry",
    "RiskLevel",
    "ShellContext",
    "SuggestionEngine",
    "SuggestionResult",
    "__version__",
]
