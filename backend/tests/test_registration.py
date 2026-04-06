"""Legacy registration integration tests retired by the spec rewrite.

The old tests in this file encoded the pre-migration email-keyed registration
model. The current contract now lives in `test_spec.py`.
"""

import pytest

pytest.skip(
    "Legacy pre-migration registration tests retired; see test_spec.py",
    allow_module_level=True,
)
