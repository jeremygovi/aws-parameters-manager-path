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

    response = None

    if parameter_path.endswith('/') :
        response = client.get_parameters_by_path(Path=parameter_path, WithDecryption=True, Recursive=True, MaxResults=10)
    else:
        parameters = [parameter_path]
        response = client.get_parameters(Names=parameters, WithDecryption=True)
 
    return response


def write_to_cf_volume(results):
    """
    Write environment variables that are to be exported in
    Codefresh.
    """
    write_to_file('/meta/env_vars_to_export', results )

def write_to_file(file, results):
    with io.open(file, 'a') as file:
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
        config_item_number = parameter.count('#')
        if config_item_number == 2 :
            path, store_to, target = parameter.split('#')
        elif config_item_number == 1 :
            target = 'environment'
            path, store_to = parameter.split('#')
        elif config_item_number == 0 :
            target = 'auto'
            store_to = ''
            path = parameter
        

        response = get_parameters_by_path(creds, path)

        print("Storing parameter value for path '{}' into ${}".format(path, store_to))
        parameter_response = response['Parameters']

        for parameter_string in parameter_response:            
            # Type = parameter_string['Type']
            Value = parameter_string['Value']

            if target == "file":
                write_to_file(store_to, Value )

            elif target == "auto":
                Name = parameter_string['Name'].replace('/','_').lower()
                results.append('{}={}\n'.format(Name, Value))

            elif target == "environment":
                results.append('{}={}\n'.format(store_to, Value))

    write_to_cf_volume(results)


if __name__ == '__main__':
    main()
