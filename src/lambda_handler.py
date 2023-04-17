"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
from datetime import datetime, timezone
import logging
import os
from typing import Any, Optional, Union

default_log_level = "INFO"
logger = logging.getLogger()
logger.setLevel(default_log_level)


def handler(event, context) -> dict[str, Optional[str]]:
    """Process the event and generate a response.

    The event should have a task member that is one of the supported tasks.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: The result of the action.
    """
    old_log_level = None
    response: dict[str, Optional[str]] = {"timestamp": str(datetime.now(timezone.utc))}

    # Update the logging level if necessary
    new_log_level = os.environ.get("log_level", default_log_level).upper()
    if not isinstance(logging.getLevelName(new_log_level), int):
        logging.warning(
            "Invalid logging level %s. Using %s instead.",
            new_log_level,
            default_log_level,
        )
        new_log_level = default_log_level
    if logging.getLogger().getEffectiveLevel() != logging.getLevelName(new_log_level):
        old_log_level = logging.getLogger().getEffectiveLevel()
        logging.getLogger().setLevel(new_log_level)

    if old_log_level is not None:
        logging.getLogger().setLevel(old_log_level)

    return response
