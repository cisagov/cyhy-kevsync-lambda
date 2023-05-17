import os
from moto import mock_ssm
import boto3
import pytest

def get_ssm_param(ssm_parameter_name):
    session = boto3.Session()
    ssm_client = session.client("ssm")
    param = ssm_client.get_parameter(Name=ssm_parameter_name, WithDecryption=True)
    return param["Parameter"]["Value"]

@mock_ssm
def test_get_ssm_param():
    ssm = boto3.client('ssm')
    ssm.put_parameter(
        Name="/foo/bar",
        Description="A test parameter",
        Value="this is it!",
        Type="SecureString",
    )
    foo = get_ssm_param('/foo/bar')
    assert foo == "this is it!"
    
@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"


@pytest.fixture
def ssm_mock(aws_credentials):
    with mock_ssm():
        client = boto3.client("ssm")
        client.put_parameter(
            Name="/foo/bar",
            Description="A test parameter",
            Value="this is it!",
            Type="SecureString",
        )
        yield