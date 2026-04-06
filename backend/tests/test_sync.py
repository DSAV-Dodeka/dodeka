"""Legacy sync integration tests retired by the final spec rewrite.

The old tests in this file encoded the pre-migration email-keyed sync model.
The final contract now lives in `test_spec.py`.
"""

import pytest

pytest.skip(
    "Legacy pre-migration sync tests retired; see test_spec.py",
    allow_module_level=True,
)
