"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
import asyncio
import logging

# Third-Party Libraries
from cyhy_kevsync import do_kev_sync


def handler(event, context) -> None:
    """Process the event and generate a response.

    The event contents are not evaluated.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: A None response which means success.
    """
    try:
        asyncio.run(do_kev_sync())
    except Exception as err:
        # TODO say more maybe?
        logging.exception(err)

    # Return None to indicate success.
    return None
