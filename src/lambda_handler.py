"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
import asyncio
import logging

# Third-Party Libraries
from cyhy_kevsync import do_kev_sync


def handler(event, context) -> None:
    """Process the event and generate a response.

    The event should have a task member that is one of the supported tasks.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: The result of the action.
    """
    try:
        asyncio.run(do_kev_sync())
    except Exception as err:
        # TODO say more maybe?
        logging.exception(err)
