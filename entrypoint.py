#!/usr/bin/env python3
## Original author: Ling Cong Xiang (github.com/Raphx)
##
## Modified by: Jesse Antoszyk (github.com/jcantosz)
##   Updated assume_role, and step definition YAML

"""Main entrypoint"""

import functools
import io
import json
import os

import boto3

AWS_ROLE_ARN = 'AWS_ROLE_ARN'
PARAMETERS = 'PARAMETERS'
AWS_WEB_IDENTITY_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE"


def should_assume_role(role_arn):
    """
    Handles the case when AWS_ROLE_ARN Codefresh input
    parameter is omitted, which will cause the role ARN to
    contain the literal string "${{AWS_ROLE_ARN}}".

    In this case, we do not want to assume role.
    """
    if role_arn == '${{AWS_ROLE_ARN}}':
        return False

    return True


def assume_role(role_arn):
    """
    Assume a role and return the temporary credentials.
    """

    roleSessionName='cfstep-aws-parameters-manager'
    client = boto3.client('sts')
    response = None
    # if AWS_ACCESS_KEY_ID explicitly set, take priority
    if "AWS_ACCESS_KEY_ID" in os.environ and os.environ["AWS_ACCESS_KEY_ID"]:
        print("Reading parameters from parameter access key provided")
        response = client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=roleSessionName
            )
    # If not explicitly set but there is a service acocunt token, use that
    elif AWS_WEB_IDENTITY_TOKEN_FILE in os.environ:
        print("Reading parameters from service account (IAM) token")

        webtokenPath = os.environ.get(AWS_WEB_IDENTITY_TOKEN_FILE)
        file = open(webtokenPath, mode='r')
        webtoken = file.read()
        file.close()

        response = client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=roleSessionName,
            WebIdentityToken=webtoken
        )
    else:
        raise Exception("Cannot authenticate with AWS parameters manager, ensure that you have set environment variables AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or AWS_WEB_IDENTITY_TOKEN_FILE")

    return (
            response['Credentials']['AccessKeyId'],
            response['Credentials']['SecretAccessKey'],
            response['Credentials']['SessionToken']
        )


@functools.lru_cache
def get_parameters_by_path(creds, parameter_path):
    """
    Get parameter value for a parameter from AWS parameters Manager.

    Return the parameter value response.
    """
    print('Getting parameters for {}'.format(parameter_path))

    client = boto3.client('ssm')

    if creds:
        client = boto3.client(
            'ssm',
            aws_access_key_id=creds[0],
            aws_secret_access_key=creds[1],
            aws_session_token=creds[2]
        )

    return client.get_parameters_by_path(Path=parameter_path, WithDecryption=True)


def write_to_cf_volume(results):
    """
    Write environment variables that are to be exported in
    Codefresh.
    """
    with io.open('/meta/env_vars_to_export', 'a') as file:
        file.writelines(results)


def main():
    """
    Main entrypoint.
    """
    creds = ()

    if (aws_iam_role_arn := os.environ.get(AWS_ROLE_ARN)) and should_assume_role(aws_iam_role_arn):
        creds = assume_role(aws_iam_role_arn)

    parameters = os.environ.get(PARAMETERS) or []

    results = []

    for parameter in parameters.split('|'):
        path, store_to = parameter.split('#')

        response = get_parameters_by_path(creds, path)

        print("Storing parameter value for path '{}' into ${}".format(path, store_to))
        ssm_response_data = response['Parameters']
        print("Response data {}".format(response))
        for ssm_data in ssm_response_data:
            parameter_response = json.loads(ssm_data)
            for parameter_string in parameter_response:
                # Name = parameter_string['Name']
                # Type = parameter_string['Type']
                value = parameter_string['Value']

                results.append('{}={}\n'.format(store_to, value))

    write_to_cf_volume(results)


if __name__ == '__main__':
    main()
