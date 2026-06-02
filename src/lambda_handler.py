"""Synchronize KEV data with a Cyber Hygiene database.

Here KEV stands for Known Exploited Vulnerabilities.
"""

# Standard Python Libraries
import asyncio
import logging
import os

# Third-Party Libraries
from cyhy_kevsync import do_kev_sync

CYHY_LOG_LEVEL = "CYHY_LOG_LEVEL"


def handler(event, context) -> None:
    """Process the event and generate a response.

    The event contents are not evaluated.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: A None response which means success.
    """
    # Check if the log level is set in the environment. This is useful when we
    # want to enable debug logs early for searching and loading configurations.
    # Otherwise, the log level will be set once the configuration is loaded.
    log_level = os.getenv(CYHY_LOG_LEVEL, None)

    try:
        asyncio.run(do_kev_sync(arg_log_level=log_level))
    except Exception as err:
        # Log the exception and throw it to indicate failure of the Lambda.
        logging.exception(err)
        raise

    # Return None to indicate success of the Lambda.
    return None
