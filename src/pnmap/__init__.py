__version__ = "0.1.0"

import logging
# This will suppress all messages that have a lower level of seriousness than error messages.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
