import importlib
import sys

from prowler.lib.logger import logger
from prowler.providers.aws.lib.quick_inventory.quick_inventory import quick_inventory



def aws_quick_inventory(audit_info, args):
    quick_inventory(audit_info, args)
