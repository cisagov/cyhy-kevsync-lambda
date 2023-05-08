"""Simple AWS Lambda handler to verify functionality."""

# Standard Python Libraries
import asyncio
import json
import logging
import os
from typing import List, Optional, Set, Tuple
import urllib.parse
import urllib.request

# Third-Party Libraries
from beanie import Document, init_beanie
from beanie.operators import NotIn
from boto3 import client as boto3_client
from botocore.exceptions import ClientError
from motor.motor_asyncio import AsyncIOMotorClient

default_log_level = "INFO"
logger = logging.getLogger()
logger.setLevel(default_log_level)

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_COLLECTION = "cyhy"

motor_client: AsyncIOMotorClient = None
ssm_client: boto3_client = None


class KEVDoc(Document):
    """Python class that represents a KEV document."""

    id: str

    class Settings:
        """Optional settings."""

        name = DEFAULT_KEV_COLLECTION
        validate_on_save = True


async def process_kev(kev) -> str:
    """Add the provided KEV to the database and return its id."""
    cve_id = kev.get("cveID")
    if not cve_id:
        raise ValueError("JSON does not look like valid CISA KEV data.")

    kev_doc = KEVDoc(id=cve_id)
    await kev_doc.save()
    return kev_doc.id


async def remove_outdated(imported_cves: Set[str]) -> None:
    """Remove any KEV entries that were not in set of imported KEVs."""
    outdated_cves = []
    async for doc in KEVDoc.find(NotIn(KEVDoc.id, imported_cves)):
        doc.delete()
        outdated_cves.append(doc.id)

    if outdated_cves:
        logging.info(
            "The following CVEs were removed from the KEV collection: %s",
            ",".join(outdated_cves),
        )
    else:
        logging.info("No outdated CVEs to remove.")


async def process_kev_json(json_url, target_db) -> None:
    """Process the provided KEVs JSON and update the database with its contents."""
    await init_beanie(database=motor_client[target_db], document_models=[KEVDoc])

    # We disable the bandit blacklist for the urllib.request.urlopen() function
    # because the URL is either the defaul (safe) URL or one provided in the
    # Lambda configuration so we can assume it is safe.
    with urllib.request.urlopen(json_url) as response:  # nosec B310
        if response.status != 200:
            raise Exception("Failed to retrieve CISA KEV JSON.")

        kev_json = json.loads(response.read().decode("utf-8"))
        imported_cves = set()

        tasks = [
            asyncio.create_task(process_kev(kev)) for kev in kev_json["vulnerabilities"]
        ]

        for task in asyncio.as_completed(tasks):
            kev_cve = await task
            imported_cves.add(kev_cve)

        if imported_cves:
            await remove_outdated(imported_cves)


def get_ssm_parameter(parameter_name: str) -> str:
    """Retrieve the value of the provided SSM Parameter Store key."""
    try:
        resp = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except ClientError:
        logging.error("Unable to retrieve SSM Parameter Store key: %s", parameter_name)
        raise


def build_mongodb_uri(
    ssm_username: str, ssm_password: str, ssm_host: str, ssm_port: str, ssm_auth_db: str
) -> Optional[str]:
    """Build a MongoDB database URI from the provided SSM Parameter Store keys."""
    uri = None
    try:
        # Ensure the username and password are safely encoded
        username = urllib.parse.quote_plus(get_ssm_parameter(ssm_username))
        password = urllib.parse.quote_plus(get_ssm_parameter(ssm_password))
        host = get_ssm_parameter(ssm_host)
        port = get_ssm_parameter(ssm_port)
        auth_db = get_ssm_parameter(ssm_auth_db)
        uri = f"mongodb://{username}:{password}@{host}:{port}/{auth_db}"
    except ClientError as client_err:
        logging.error("Unable to create MongoDB URI.")
        logging.exception(client_err)

    return uri


def handler(event, context) -> None:
    """Process the event and generate a response.

    The event should have a task member that is one of the supported tasks.

    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: The result of the action.
    """
    old_log_level = None

    global motor_client
    global ssm_client

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

    # Set up the SSM client if necessary
    if ssm_client is None:
        ssm_client = boto3_client("ssm")

    mongodb_uri_elements: List[Tuple[str, Optional[str]]] = []

    # This only runs from a CloudWatch scheduled event invocation
    if (trigger_source := event.get("source", "")) != "aws.events" or (
        trigger_type := event.get("detail-type", "")
    ) != "Scheduled Event":
        logging.error(
            "Invalid invocation event: source=%s, type=%s", trigger_source, trigger_type
        )
        return

    # Build a list of tuples to validate and then use for the build_mongodb_uri()
    # helper function. The order of variables must match the order of arguments for
    # the helper function.
    for var in [
        "ssm_db_user",
        "ssm_db_pass",
        "ssm_db_host",
        "ssm_db_port",
        "ssm_db_authdb",
    ]:
        mongodb_uri_elements.append((var, os.environ.get(var)))

    # Check that we have all of the required variables
    if missing_variables := [k for k, v in mongodb_uri_elements if v is None]:
        logging.error("Missing required variables: %s", ",".join(missing_variables))
        return

    # Determine the database where the KEV data will be inserted
    write_db = get_ssm_parameter(os.environ.get("ssm_db_writedb", "ssm_db_authdb"))

    # Determine if a non-default KEVs JSON URL is being used
    kev_json_url = os.environ.get("json_url", DEFAULT_KEV_URL)

    # Determine if a non-default collection is being used
    db_collection = os.environ.get("ssm_db_collection")
    if db_collection is not None:
        KEVDoc.Settings.name = get_ssm_parameter(db_collection)

    # We disable mypy here because the variable is typed to have Optional[str] elements
    # but we verify that there are only str elements before this point.
    mongodb_uri = build_mongodb_uri(*[v for k, v in mongodb_uri_elements])  # type: ignore

    if mongodb_uri is None:
        logging.error("Unable to import KEV data.")
        return

    # Set up the Motor session if necessary
    if motor_client is None:
        motor_client = AsyncIOMotorClient(mongodb_uri)

    try:
        asyncio.run(process_kev_json(kev_json_url, write_db))
    except Exception as err:
        logging.error(
            "Problem encountered while processing the KEVs JSON at %s", kev_json_url
        )
        logging.exception(err)

    if old_log_level is not None:
        logging.getLogger().setLevel(old_log_level)
