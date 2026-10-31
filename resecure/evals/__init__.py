"""
ReSecure Evals Module: Empirical benchmarks, Reed-Solomon codec,
and automated evaluation suites comparing deterministic recovery vs AI.
"""

from resecure.evals.benchmark_cases import (
    BenchmarkCaseFactory,
    BenchmarkTestCase,
)
from resecure.evals.codec import (
    CodecVerdict,
    ProtectionPackage,
    RecoveryResult,
    ReedSolomonEngine,
)
from resecure.evals.eval_recovery_benchmark import RecoveryBenchmarkRunner
from resecure.evals.generative_simulator import (
    GenerativeRecoveryResult,
    GenerativeSimulator,
)

__all__ = [
    "BenchmarkCaseFactory",
    "BenchmarkTestCase",
    "CodecVerdict",
    "GenerativeRecoveryResult",
    "GenerativeSimulator",
    "ProtectionPackage",
    "RecoveryBenchmarkRunner",
    "RecoveryResult",
    "ReedSolomonEngine",
]
