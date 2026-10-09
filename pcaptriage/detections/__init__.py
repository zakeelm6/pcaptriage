"""Detection package.

Importing this package registers all detections via the @register
decorator in each module.
"""

from . import cleartext_creds  # noqa: F401
from . import port_scan        # noqa: F401
from . import dns_tunneling    # noqa: F401
from . import beaconing        # noqa: F401
from . import suspicious_tls   # noqa: F401
from . import name_poisoning   # noqa: F401
from . import suspicious_download  # noqa: F401
from . import mass_mailing     # noqa: F401
from . import host_mismatch    # noqa: F401
from . import post_delivery    # noqa: F401

from .base import all_detections, Finding  # noqa: F401
