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
    # This only runs from a CloudWatch scheduled event invocation
    trigger_type = ""
    if (trigger_source := event.get("source", "")) != "aws.events" or (
        trigger_type := event.get("detail-type", "")
    ) != "Scheduled Event":
        logging.error(
            "Invalid invocation event: source=%s, type=%s", trigger_source, trigger_type
        )
        return

    try:
        asyncio.run(do_kev_sync())
    except Exception as err:
        # TODO say more maybe?
        logging.exception(err)
