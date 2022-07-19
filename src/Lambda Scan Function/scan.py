#!/usr/bin/env python3

from __future__ import print_function
import json
import csv
import time
import sys
import re
import os
from datetime import datetime
from collections import Counter, OrderedDict
import botocore
import session
from mailer import *
from db import *

# --- Script controls ---

# CIS Benchmark version referenced. Only used in web report.
AWS_CIS_BENCHMARK_VERSION = "1.3"

# --- Control Parameters ---


# Control 1.1 - Days allowed since use of root account.
CONTROL_1_1_DAYS = 0


# --- Global ---



ourregion = 'us-west-1'
TotalPolicyCount = ""
PassPolicyCount = ""
FailPolicyCount = ""
account = ""
table = []
iam_sec="IAM Security"
log="Logging"
monitor="Monitoring"
store = "Storage"
network="Networking"
s3buck= "S3 Bucket"
ecc2instance = "EC2"
RDSinstance = "RDS"

aws_fsbp ={}
cis_benchmark={}
aws_cis ={}

# CIS Security Controls

# --- 1 Identity and Access Management ---
# CIS total automated 17 controls for IAM

# CIS 1.4 
def security_1_4_root_access_key_exists(credential_report):

    result = True
    comments = "Removing access keys associated with the root account limits vectors that the account can be compromised."
    NonCompliantAccounts = []
    cis_control = "1.4"
    description = "Ensure no root account access key exists"
    Severity = 'Critical'
    
    if (credential_report[0]['access_key_1_active'] == "true") or (credential_report[0]['access_key_2_active'] == "true"):
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.5
def security_1_5_mfa_root_enabled():

    result = True
    comments = "The root account is the most privileged user in an account. MFA adds an extra layer of protection on top of a user name and password. "
    NonCompliantAccounts = []
    cis_control = "1.5"
    description = "Ensure MFA is enabled for the root account"
    Severity = 'Critical'
    
    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] != 1:
        result = False
        comments = "Root account not using MFA"
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.6 
def security_1_6_hardware_mfa_root_enabled():

    result = True
    comments = "Protect the root account with a hardware MFA. A hardware MFA has a smaller attack surface than a virtual MFA."
    NonCompliantAccounts = []
    cis_control = "1.6"
    description = "Ensure hardware MFA is enabled for the root account"
    Severity = 'Critical'
    
    # First check if root uses MFA (to avoid false positives)
    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] == 1:
        pages = IAM_CLIENT.get_paginator('list_virtual_mfa_devices')
        res_iter = pages.paginate(
            AssignmentStatus='Any',
        )
        pagedResult = []
        for page in res_iter:
            for n in page['VirtualMFADevices']:
                pagedResult.append(n)
        if "mfa/root-account-mfa-device" in str(pagedResult):
            result = False
    else:
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.7
def security_1_7_avoid_root_for_admin_tasks(credential_report):

    result = True
    comments = "Minimizing the use of root account and adopting the principle of least privilege for access management reduces the risk of accidental changes and unintended disclosure of highly privileged credentials."
    NonCompliantAccounts = []
    cis_control = "1.7"
    description = "Avoid the use of the root account"
    Severity = 'Low'
    
    if "Fail" in credential_report:  # Report failure in cis_control
        sys.exit(credential_report)
    # Check if root is used in the last 24h
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    try:
        passwordDelta = (datetime.strptime(now, frm) - datetime.strptime(credential_report[0]['password_last_used'], frm))
        if (passwordDelta.days == CONTROL_1_1_DAYS) & (passwordDelta.seconds > 0):  # Used within last 24h
            result = False
    except:
        if credential_report[0]['password_last_used'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")

    try:
        accessKey1 = (datetime.strptime(now, frm) - datetime.strptime(credential_report[0]['access_key_1_last_used_date'], frm))
        if (accessKey1.days == CONTROL_1_1_DAYS) & (accessKey1.seconds > 0):  # Used within last 24h
            result = False
    except:
        if credential_report[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")
    try:
        accessKey2 = datetime.strptime(now, frm) - datetime.strptime(credential_report[0]['access_key_2_last_used_date'], frm)
        if (accessKey2.days == CONTROL_1_1_DAYS) & (accessKey2.seconds > 0):  # Used within last 24h
            result = False
    except:
        if credential_report[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.8
def security_1_8_minimum_password_policy_length(passwdPolicy):
    
    result = True
    comments = "Setting a password complexity policy increases account resiliency against brute force login attempts."
    NonCompliantAccounts = []
    cis_control = "1.8"
    Severity="Medium"
    description = "Ensure IAM password policy requires minimum length of 14 or greater"
    
    if passwdPolicy is False:
        result = False
    else:
        if passwdPolicy['MinimumPasswordLength'] < 14:
            result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 1.9 
def security_1_9_password_policy_reuse(passwdPolicy):

    result = True
    comments = "Preventing password reuse increases account resiliency against brute force login attempts, usage of stolen passwords."
    NonCompliantAccounts = []
    cis_control = "1.9"
    description = "Ensure IAM password policy prevents password reuse"
    Severity="Low"
    
    if passwdPolicy is False:
        result = False
    else:
        try:
            if passwdPolicy['PasswordReusePrevention'] == 24:
                pass
            else:
                result = False
        except:
            result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 1.10
def security_1_10_enable_mfa_on_iam_console_password(credential_report):

    result = True
    comments = " Enabling MFA provides increased security for console access because it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential."
    NonCompliantAccounts = []
    cis_control = "1.10"
    description = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
    Severity = 'Medium'
    
    for i in range(len(credential_report)):
        # Verify if the user have a password configured
        if credential_report[i]['password_enabled'] == "true":
            # Verify if password users have MFA assigned
            if credential_report[i]['mfa_active'] == "false":
                result = False
                NonCompliantAccounts.append(str(credential_report[i]['arn']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.11 
def security_1_11_no_iam_access_key_passwd_setup(credential_report):

    result = True
    comments = "Requiring the additional steps be taken by the user for programmatic access after their profile has been created will give a stronger indication of intent that access keys are necessary for their work and once the access key is established on an account, the keys may be in use somewhere in the organization."
    NonCompliantAccounts = []
    cis_control = "1.11"
    description = "Do not setup access keys during initial user setup for all IAM users that have a console password"
    Severity = 'Low'
    try:
        for user in credential_report:
            if user['password_enabled'] == "true":
                if (user['access_key_1_last_used_date'] == "NA") or (user['access_key_2_last_used_date'] == "NA") :
                    result = False
                    NonCompliantAccounts.append(user['user'])
    except Exception as e:
        result =False
        print("Exception in Security control 1.13 : ",str(e))

    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.12
def security_1_12_credentials_unused(credential_report):

    result = True
    comments = "Remove or deactivate all credentials that have been unused in 90 days or more."
    NonCompliantAccounts = []
    cis_control = "1.12"
    description = "Ensure credentials unused for 90 days or greater are disabled"
    Severity = 'Low'
    
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # check for credentails that are unused
    for i in range(len(credential_report)):
        if credential_report[i]['password_enabled'] == "true":
            try:
                dayCount = datetime.strptime(now, frm) - datetime.strptime(credential_report[i]['password_last_used'], frm)
                # Verify password have been used in the last 90 days
                if dayCount.days > 90:
                    result = False
                    NonCompliantAccounts.append(str(credential_report[i]['arn']) + ":password")
            except:
                pass  # Never used
        if credential_report[i]['access_key_1_active'] == "true":
            try:
                dayCount = datetime.strptime(now, frm) - datetime.strptime(credential_report[i]['access_key_1_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if dayCount.days > 90:
                    result = False
                    NonCompliantAccounts.append(str(credential_report[i]['arn']) + ":key1")
            except:
                pass
        if credential_report[i]['access_key_2_active'] == "true":
            try:
                dayCount = datetime.strptime(now, frm) - datetime.strptime(credential_report[i]['access_key_2_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if dayCount.days > 90:
                    result = False
                    NonCompliantAccounts.append(str(credential_report[i]['arn']) + ":key2")
            except:
                # Never used
                pass
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.13
def security_1_13_no_2_active_access_keys_iam_user():
    
    NonCompliantAccounts=[]
    access_key_lst=[]
    count =0
    result = True
    comments = "One of the best ways to protect your account is to not allow users to have multiple access keys."
    NonCompliantAccounts = []
    cis_control = "1.13"
    description = "Ensure there is only one active access key available for any single IAM user"
    Severity = 'Medium'
    try:
        user_paginator = IAM_CLIENT.get_paginator('list_users')
        access_key_paginator = IAM_CLIENT.get_paginator('list_access_keys')
        for response in user_paginator.paginate():
            for user in response['Users']:
                for response in access_key_paginator.paginate(UserName=user['UserName']):
                    for access_key in response['AccessKeyMetadata']:
                        if (access_key['Status'] == "Active"):
                            count+=1
                            access_key_lst.append(access_key['AccessKeyId'])    
                user_access_key ='user : '+access_key['UserName'] +', access_key_ids: '+ ','.join(access_key_lst)
                access_key_lst=[]
                if count > 1 :
                    result=False
                    NonCompliantAccounts.append(user_access_key)
                count=0
    except Exception as e:
        result = False
        print("Exception in Security control 1.13 : ",str(e))

    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 1.14 
def security_1_14_access_keys_rotated(credential_report):

    result = True
    comments = "Rotating access keys reduces the chance for an access key that is associated with a compromised or terminated account to be used. Rotate access keys to ensure that data can't be accessed with an old key that might have been lost, cracked, or stolen."
    NonCompliantAccounts = []
    cis_control = "1.14"
    description = "Ensure access keys are rotated every 90 days or less"
    Severity = 'Medium'
    
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credential_report)):
        if credential_report[i]['access_key_1_active'] == "true":
            try:
                dayCount = datetime.strptime(now, frm) - datetime.strptime(credential_report[i]['access_key_1_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if dayCount.days > 90:
                    result = False
                    NonCompliantAccounts.append(str(credential_report[i]['arn']) + ":unrotated key1")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(credential_report[i]['access_key_1_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(credential_report[i]['access_key_1_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    NonCompliantAccounts.append(str(credential_report[i]['arn']) + ":unused key1")
            except:
                pass
        if credential_report[i]['access_key_2_active'] == "true":
            try:
                dayCount = datetime.strptime(now, frm) - datetime.strptime(credential_report[i]['access_key_2_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if dayCount.days > 90:
                    result = False
                    NonCompliantAccounts.append(str(credential_report[i]['arn']) + ":unrotated key2")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(credential_report[i]['access_key_2_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(credential_report[i]['access_key_2_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    NonCompliantAccounts.append(str(credential_report[i]['arn']) + ":unused key2")
            except:
                pass
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: " + str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.15 
def security_1_15_only_group_policies_on_iam_users():

    result = True
    comments = "IAM users must inherit permissions from IAM groups or roles."
    NonCompliantAccounts = []
    cis_control = "1.15"
    description = "IAM users should not have IAM policies attached"
    Severity = "Low"
    
    paginator = IAM_CLIENT.get_paginator('list_users')
    response_iterator = paginator.paginate()
    pagedResult = []
    for page in response_iterator:
        for n in page['Users']:
            pagedResult.append(n)
    NonCompliantAccounts = []
    for n in pagedResult:
        policies = IAM_CLIENT.list_user_policies(
            UserName=n['UserName'],
            MaxItems=1
        )
        if policies['PolicyNames'] != []:
            result = False
            NonCompliantAccounts.append(str(n['Arn']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 1.16
def security_1_16_no_admin_priv_policies():

    result = True
    comments = "Providing full administrative privileges instead of restricting to the minimum set of permissions that the user is required to do exposes the resources to potentially unwanted actions."
    NonCompliantAccounts = []
    cis_control = "1.16"
    description = "Ensure IAM policies that allow full administrative privileges are not created"
    Severity = 'Critical'
    
    NonCompliantAccounts = []
    paginator = IAM_CLIENT.get_paginator('list_policies')
    response_iterator = paginator.paginate(
        Scope='Local',
        OnlyAttached=False,
    )
    pagedResult = []
    for page in response_iterator:
        for n in page['Policies']:
            pagedResult.append(n)
    for m in pagedResult:
        policy = IAM_CLIENT.get_policy_version(
            PolicyArn=m['Arn'],
            VersionId=m['DefaultVersionId']
        )

        statements = []
        # a policy may contain a single statement, a single statement in an array, or multiple statements in an array
        if isinstance(policy['PolicyVersion']['Document']['Statement'], list):
            for statement in policy['PolicyVersion']['Document']['Statement']:
                statements.append(statement)
        else:
            statements.append(policy['PolicyVersion']['Document']['Statement'])

        for n in statements:
            # a policy statement has to contain either an Action or a NotAction
            if 'Action' in n.keys() and n['Effect'] == 'Allow':
                if ("'*'" in str(n['Action']) or str(n['Action']) == "*") and ("'*'" in str(n['Resource']) or str(n['Resource']) == "*"):
                    result = False
                    NonCompliantAccounts.append(str(m['Arn']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.17
def security_1_17_ensure_support_roles():

    result = True
    comments = "Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow."
    NonCompliantAccounts = []
    cis_control = "1.17"
    description = "Ensure a support role has been created to manage incidents with AWS Support"
    Severity = 'Low'
    
    NonCompliantAccounts = []
    try:
        response = IAM_CLIENT.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
        )
        if (len(response['PolicyGroups']) + len(response['PolicyUsers']) + len(response['PolicyRoles'])) == 0:
            result = False
    except:
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 1.19
def security_1_19_expired_SSL_TLS_certificates():

    response = IAM_CLIENT.list_server_certificates()
    current_date = datetime.now()
    result = True
    comments = "Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can damage the credibility of the application/website behind the ELB."
    NonCompliantCerts = []
    cis_control = "1.19"
    description = "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed"
    Severity = "Low"
    try:
        if len(response['ServerCertificateMetadataList']) > 0:
            for cert in response['ServerCertificateMetadataList']:
                expire_date = cert['Expiration'].replace(tzinfo=None)
                days = (expire_date - current_date).total_seconds()
                days_left =divmod(days, 24 * 60 * 60)[0]
                if int(days_left) < 1:
                    NonCompliantCerts.append(cert['ServerCertificateName'])
    except Exception as e:
        result = False
        print("Exception in Security control 1.19 : ",str(e))
    if(len(NonCompliantCerts)!=0):
        result=False
        comments = comments + "<B><br>NonCompliantCertificates</B> :: "+ str(NonCompliantCerts)
    return {'Result': result, 'comments': comments, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 1.20
def security_1_20_Bucket_PublicAccess_check():

    status=False
    response=None
    NonCompliantS3 =[]
    comments="Amazon S3 public access block is designed to provide controls across an entire AWS account or at the individual S3 bucket level to ensure that objects never have public access. "
    cis_control="1.20"
    description="Ensure that S3 Buckets are configured with 'Block Public Access'."
    Severity= "Medium"
    s3_response = S3_CLIENT.list_buckets()
    try:
        if len(s3_response['Buckets'])>0:
            buckets = s3_response['Buckets']
            for bucket in buckets:
                try:
                    response = S3_CLIENT.get_public_access_block(
                        Bucket=bucket['Name']
                    )
                    if( response['PublicAccessBlockConfiguration']):
                        status = response['PublicAccessBlockConfiguration']['BlockPublicAcls'] &response['PublicAccessBlockConfiguration']['IgnorePublicAcls'] & response['PublicAccessBlockConfiguration']['BlockPublicPolicy'] & response['PublicAccessBlockConfiguration']['RestrictPublicBuckets']
                    if(status==False):
                        NonCompliantS3.append(bucket['Name']) 
                except botocore.exceptions.ClientError as e:
                        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                            status = False
                            NonCompliantS3.append(bucket['Name'])
    except Exception as e:
        print("No Buckets Exception in security control 1.20 : ",str(e))
        status = False

    if(len(NonCompliantS3)!=0):
        status = False
        comments = comments + "<B><br>NonCompliantS3</B> :: "+ str(NonCompliantS3)
    return {'Result': status, 'comments': comments, 'NonCompliantAccounts': NonCompliantS3, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

#CIS 1.21
def security_1_21_Access_Analyzer():

    result = True
    comments = "AWS IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity.This lets you identify unintended access to your resources and data."
    NonCompliantAnalyzers = []
    cis_control = "1.21"
    description = "Ensure that IAM Access analyzer is enabled."
    Severity = "Low"
    
    try:
        client = boto3_session.client('accessanalyzer')
        response = client.list_analyzers()
        if len(response['analyzers'])>0:
            for analyzer in response['analyzers']:
                if analyzer['status'] != 'ACTIVE':
                    NonCompliantAnalyzers.append(analyzer['arn'])
        else:
            result =False
            comments = "No Access Analyzers Identified."
    except Exception as e:
        result=False
        print('Exception in security control 1.21 : ',str(e))
    if len(NonCompliantAnalyzers)!=0:
        result = False
        comments = comments + "<B><br>NonCompliantAnalyzers</B> :: "+ str(NonCompliantAnalyzers)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAnalyzers, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS IAM Controls END


# 2 Storage
# CIS total automated 3 controls for storage


# CIS 2.1.1
def security_2_1_1_s3_EncryptionCheck(): 
    result=False
    response=None
    NonCompliantS3 = []
    comments="S3 Buckets should be configured with server-side encryption to protect data at rest. Buckets other than the ones used for 'Server Access Log' can use SSE-KMS to encrypt, the server access log buckets should be encrypted with SS-S3 default encryption."
    cis_control="2.1.1"
    description="Ensure all S3 buckets employ encryption-at-rest."
    Severity= "Medium"
    s3_response = S3_CLIENT.list_buckets()
    try:
        if len(s3_response['Buckets'])>0:
            buckets = s3_response['Buckets']
            for bucket in buckets:
                try:
                    response = S3_CLIENT.get_bucket_encryption(
                        Bucket=bucket['Name']
                    )
                    #print(response['ServerSideEncryptionConfiguration'])
                    if 'ServerSideEncryptionConfiguration' in response:
                        result = True
                    else:
                        result= False
                        NonCompliantS3.append(bucket['Name'])
                except botocore.exceptions.ClientError as e:
                        if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                            result = False
                            if(bucket['Name'] not in NonCompliantS3):
                                NonCompliantS3.append(bucket['Name']) 
                        else:
                            raise
        else:
            result = True
            comments = "No S3 buckets Found."
    except Exception as e:
        print(str(e))
    if(len(NonCompliantS3)!=0):
        result = False
        comments = comments + "<B><br>NonCompliantS3</B> :: "+ str(NonCompliantS3)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantS3, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 2.1.2  
def security_2_1_1_SslPolicyCheck():
    # print(bucket)
    result=False
    sslsocket = False
    response=None
    NonCompliantS3 = []
    comments="S3 buckets should have policies that require all requests to only accept transmission of data over HTTPS "
    cis_control="2.1.2"
    description="Ensure S3 Bucket Policy allows HTTPS requests."
    Severity= "Medium"
    s3_response = S3_CLIENT.list_buckets()
    i=0
    try:
        if len(s3_response['Buckets'])>0:
            buckets = s3_response['Buckets']
            for bucket in buckets:
                sslsocket = False
                try:
                    response = S3_CLIENT.get_bucket_policy(
                            #AccountId= get_aws_account_number(),
                        Bucket=bucket['Name']    )
                except Exception as e:
                    if 'NoSuchBucket' in str(e):
                        # print (e)
                        if(bucket['Name'] not in NonCompliantS3):
                            NonCompliantS3.append(bucket['Name'])
                    else:
                        raise
                if response is not None:
                    policy = json.loads(response['Policy'])
                    # print(type(policy),policy)
                    for s in policy['Statement']:
                        try:
                            # print(s)   
                            if(s['Effect'].lower()=='deny' and s['Condition']['Bool']['aws:SecureTransport'].lower()=='false'):
                                # print("here")
                                result=True
                                sslsocket = True
                        except Exception as e:
                            if 'Bool' in str(e):
                                result = False
                                if(bucket['Name'] not in NonCompliantS3):
                                    NonCompliantS3.append(bucket['Name']) 
                    if sslsocket !=True:
                        result = False
                        if(bucket['Name'] not in NonCompliantS3):
                            NonCompliantS3.append(bucket['Name'])
                else:
                    result = False
                    if(bucket['Name'] not in NonCompliantS3):
                        NonCompliantS3.append(bucket['Name'])
        else:
            result = True
            comments = "No S3 buckets Found."
    except Exception as e:
        print(str(e))
    if(len(NonCompliantS3)!=0):
        result = False
        comments = comments + "<B><br>NonCompliantS3</B> :: "+ str(NonCompliantS3)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantS3, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 2.2.1
def security_2_2_EBSVolumeEncryptCheck(regions):
    result = True
    comments = "Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken."
    NonCompliantEc2 = []
    cis_control = "2.2.1"
    description = " Ensure EBS volume encryption is enabled."
    Severity = 'Medium'
    for r in regions:
        tmp_lst=[]
        EC2_CLIENT = boto3_session.client('ec2',region_name=r)
        response = EC2_CLIENT.describe_volumes()
        try:
            if len(response['Volumes']) >0 :
                for m in response['Volumes']:
                    if( m['Encrypted'] == False):
                        result = False
                        tmp_lst.append(m['VolumeId'])
                tmp_dct= "<b>Region :</b> "+r+" <b>VolumeIds :</b> "+','.join(tmp_lst)+"<br>"
                NonCompliantEc2.append(tmp_dct)
            else:
                comments = comments + "No EBS Volumes Found in the region : "+r
        except Exception as e:
            print(str(e))
            
    if(len(NonCompliantEc2)!=0):
        comments = comments + "<B><br>NonCompliant EBS Volumes</B> :: "+str(NonCompliantEc2)
    return {'Result': result, 'comments': comments, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}


# 3 Logging
# CIS total automated 11 controls for logging


# CIS 3.1
def security_3_1_cloud_trail_all_regions(cloudtrails):

    result = False
    comments = "Cloud Trail enables security analysis, resource change tracking, and compliance auditing."
    NonCompliantAccounts = []
    cis_control = "3.1"
    description = "Ensure CloudTrail is enabled in all regions"
    Severity="Critical"
    if(len(cloudtrails)!=0):
        for m, n in cloudtrails.items():
            for o in n:
                if o['IsMultiRegionTrail']:
                    client = boto3_session.client('cloudtrail', region_name=m)
                    response = client.get_trail_status(
                        Name=o['TrailARN']
                    )
                    if response['IsLogging'] is True:
                        result = True
                        break
                    else:
                        NonCompliantAccounts.append(m)
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliant Regions</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 3.2 
def security_3_2_cloudtrail_validation(cloudtrails):

    result = True
    comments = "CloudTrails log file validation is enabled"
    NonCompliantAccounts = []
    cis_control = "3.2"
    description = "Ensure CloudTrail log file validation is enabled"
    Severity="Low"
    if len(cloudtrails)>0:
        for m, n in cloudtrails.items():
            for o in n:
                if o['LogFileValidationEnabled'] is False:
                    result = False
                    comments = "CloudTrails without log file validation discovered"
                    NonCompliantAccounts.append(str(o['TrailARN']))
        NonCompliantAccounts = set(NonCompliantAccounts)
        NonCompliantAccounts = list(NonCompliantAccounts)
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 3.3
def security_3_3_cloudtrail_public_bucket(cloudtrails):

    result = True
    comments = "S3 bucket CloudTrail is not publicly accessible"
    NonCompliantAccounts = []
    Severity="Critical"
    cis_control = "3.3"
    description = "Ensure the S3 bucket CloudTrail logs is not publicly accessible"
    if len(cloudtrails)>0:   
        for m, n in cloudtrails.items():
            for o in n:
                #  We only want to check cases where there is a bucket
                if "S3BucketName" in str(o):
                    try:
                        response = S3_CLIENT.get_bucket_acl(Bucket=o['S3BucketName'])
                        for p in response['Grants']:
                            # print("Grantee is " + str(p['Grantee']))
                            if re.search(r'(global/AllUsers|global/AuthenticatedUsers)', str(p['Grantee'])):
                                result = False
                                NonCompliantAccounts.append(str(o['TrailARN']) + "<B>:PublicBucket</B>")
                                if "Publically" not in comments:
                                    comments = "Publically accessible CloudTrail bucket discovered."
                    except Exception as e:
                        result = False
                        if "AccessDenied" in str(e):
                            NonCompliantAccounts.append(str(o['TrailARN']) + "<B>:AccessDenied</B>")
                            if "Missing" not in comments:
                                comments = "Missing permissions to verify bucket ACL. "
                        elif "NoSuchBucket" in str(e):
                            NonCompliantAccounts.append(str(o['TrailARN']) + "<B>:NoBucket</B>")
                            if "Trailbucket" not in comments:
                                comments = "Trailbucket doesn't exist. "
                        else:
                            NonCompliantAccounts.append(str(o['TrailARN']) + "<B>:CannotVerify</B>")
                            if "Cannot" not in comments:
                                comments = "Cannot verify bucket ACL. "
                else:
                    result = False
                    NonCompliantAccounts.append(str(o['TrailARN']) + "NoS3Logging")
                    comments = "Cloudtrail not configured to log to S3. "
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 3.4
def security_3_4_integrate_cloudtrail_cloudwatch_logs(cloudtrails):

    result = True
    comments = "CloudTrail trails is integrated with CloudWatch Logs"
    NonCompliantAccounts = []
    cis_control = "3.4"
    description = "Ensure CloudTrail trails are integrated with CloudWatch Logs"
    Severity = "Low"
    if len(cloudtrails) > 0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if "arn:aws:logs" in o['CloudWatchLogsLogGroupArn']:
                        pass
                    else:
                        result = False
                        comments = "CloudTrails without CloudWatch Logs discovered"
                        NonCompliantAccounts.append(str(o['TrailARN']))
                except:
                    result = False
                    comments = "Unable to Fetch CloudTrails Integrated with CloudWatch Logs Status for:" +str(o['TrailARN'])
        
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 3.5
def security_3_5_ensure_config_all_regions(regions):

    result = True
    comments = ""
    NonCompliantAccounts = []
    cis_control = "3.5"
    description = "Ensure AWS Config is enabled in all regions"
    Severity = 'Medium'
    
    count = 0
    #regions = [regions]
    globalConfigCapture = False  # Only one region needs to capture global events
    for n in regions:
        count = 0
        configClient = boto3_session.client('config', region_name=n)
        response = configClient.describe_configuration_recorder_status()
        # Get recording status
        if response['ConfigurationRecordersStatus'] != "":
            try:
                if not response['ConfigurationRecordersStatus'][0]['recording'] is True:
                    count = count + 1
            except:
                result = False
                comments = "Unable to Fetch Config details<B>:: "+str(n)+"</B><br>"

        # Verify that each region is capturing all events
        response = configClient.describe_configuration_recorders()
        if response['ConfigurationRecorders'] != "":
            try:
                if not response['ConfigurationRecorders'][0]['recordingGroup']['allSupported'] is True:
                    count = count + 1
                    
            except:
                pass  # This indicates that Config is disabled in the region and will be captured above.

            # Check if region is capturing global events. Fail is verified later since only one region needs to capture them.
            try:
                if not response['ConfigurationRecorders'][0]['recordingGroup']['includeGlobalResourceTypes'] is True:
                    count = count + 1
            except:
                pass

        # Verify the delivery channels
        response = configClient.describe_delivery_channel_status()
        if response['DeliveryChannelsStatus'] != "":
            try:
                if response['DeliveryChannelsStatus'][0]['configHistoryDeliveryInfo']['lastStatus'] != "SUCCESS":
                    count = count + 1
                    
            except:
                pass  # Will be captured by earlier rule
            try:
                if response['DeliveryChannelsStatus'][0]['configStreamDeliveryInfo']['lastStatus'] != "SUCCESS":
                    count = count + 1
                    
            except:
                pass  # Will be captured by earlier rule

        if count > 0:
            break
    # Verify that global events is captured by any region
    if count > 0:
        result = True
        comments =comments + "Config enabled in all regions, capturing all/global events or delivery channel errors"
    else:
        result = False
        comments = comments + "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
        NonCompliantAccounts.append("Global:NotRecording, SNS:Recording")
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 3.6
def security_3_6_cloudtrail_bucket_access_log(cloudtrails):

    result = True
    comments = "S3 bucket access logging is enabled on the CloudTrail S3 bucket"
    NonCompliantAccounts = []
    cis_control = "3.6"
    description = "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
    Severity = 'Low'
    
    if(len(cloudtrails)!=0): 
        for m, n in cloudtrails.items():
            for o in n:
                # it is possible to have a cloudtrail configured with a nonexistant bucket
                try:
                    response = S3_CLIENT.get_bucket_logging(Bucket=o['S3BucketName'])
                except:
                    result = False
                    comments = "Cloudtrail not configured to log to S3. "
                    NonCompliantAccounts.append(str(o['TrailARN']))
                try:
                    if response['LoggingEnabled']:
                        pass
                except Exception as e:
                    result = False
                    comments = "Unable to Fetch the CloudTrail S3 bucket Status for : <B>Trail:" + str(o['TrailARN']) + " - S3Bucket:" + str(o['S3BucketName'] +"</B>")
        if(len(NonCompliantAccounts)!=0):
            comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 3.7
def security_3_7_cloudtrail_log_kms_encryption(cloudtrails):

    result = True
    comments = "CloudTrail logs are encrypted at rest using KMS CMKs"
    NonCompliantAccounts = []
    cis_control = "3.7"
    description = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
    Severity = "Medium"
    
    if(len(cloudtrails)!=0): 
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['KmsKeyId']:
                        pass
                except:
                    result = False
                    comments = "CloudTrail not using KMS CMK for encryption discovered"
                    NonCompliantAccounts.append("<B>Trail:" + str(o['TrailARN'])+"</B>")
        if(len(NonCompliantAccounts)!=0):
            comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 3.8
def security_3_8_kms_cmk_rotation(regions):

    result = True
    comments = "Rotation for customer created CMKs is enable"
    NonCompliantAccounts = []
    cis_control = "3.8"
    description = "Ensure rotation for customer created CMKs is enabled"
    Severity = "High"
    
    #regions = [regions]
    for n in regions:
        kms_client = boto3_session.client('kms', region_name=n)
        paginator = kms_client.get_paginator('list_keys')
        response_iterator = paginator.paginate()
        for page in response_iterator:
            for n in page['Keys']:
                # print('Key:id: ',n)
                try:
                    rotationStatus = kms_client.get_key_rotation_status(KeyId=n['KeyId'])
                    keyState=kms_client.describe_key(KeyId=n['KeyId'])
                    if(keyState['KeyMetadata']['KeyState'] == 'Enabled'):
                        if rotationStatus['KeyRotationEnabled'] is False:
                            keyDescription = kms_client.describe_key(KeyId=n['KeyId'])
                            # print("Key Description : ",keyDescription)
                            if "Default master key that protects my" not in str(keyDescription['KeyMetadata']['Description']):  # Ignore service keys
                                result = False
                                comments = "KMS CMK rotation not enabled"
                                NonCompliantAccounts.append("Key:" + str(keyDescription['KeyMetadata']['Arn']))
                    # else:
                    #     print("Disabled Key Found",n['KeyId'])
                    #     pass
                except Exception as e:
                    # print("except: ",e)
                    comments = "Unable to access KMS CMK property for the <B>Key/Key-Id: "+str(n)+"</B>"
                    #pass  # Ignore keys without permission, for example ACM key
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}   

# CIS 3.9
def security_3_9_vpc_flow_logs_enabled(regions):

    result = True
    comments = "VPC flow logging is enabled in all VPCs"
    NonCompliantAccounts = []
    cis_control = "3.9"
    description = "Ensure VPC flow logging is enabled in all VPCs"
    Severity = 'High'
    
    #regions = [regions]
    for n in regions:
        
        client = boto3_session.client('ec2', region_name=n)
        flowlogs = client.describe_flow_logs(
            #  No paginator support in boto atm.
        )
        activeLogs = []
        for m in flowlogs['FlowLogs']:
            if "vpc-" in str(m['ResourceId']):
                activeLogs.append(m['ResourceId'])
        vpcs = client.describe_vpcs(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available',
                    ]
                },
            ]
        )
        for m in vpcs['Vpcs']:
            if not str(m['VpcId']) in str(activeLogs):
                result = False
                comments = "VPC without active VPC Flow Logs found"
                NonCompliantAccounts.append(str(n) + " : " + str(m['VpcId']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 3.10
def security_3_10_write_events_cloudtrail(cloudtrails):

    result = True
    comments = "Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events."
    NonCompliantTrails = []
    cis_control = "3.10"
    description = "Ensure that Object-level logging for write events is enabled for S3 bucket."
    Severity = 'Medium'
    if(len(cloudtrails)!=0):
        for m,n in cloudtrails.items():
            for o in n:
                try:
                    client = boto3_session.client('cloudtrail',region_name=m)
                    event_list= client.get_event_selectors(TrailName = o['Name'])
                    for event in event_list['EventSelectors']:
                        if event['ReadWriteType'] == 'WriteOnly' or event['ReadWriteType'] == 'All':
                            if len(event['DataResources']) == 0:
                                result = False
                                NonCompliantTrails.append(o['Name'])
                    if len(NonCompliantTrails)!=0:
                        result=False
                        comments = comments + "<B><br>NonCompliantTrails</B> :: "+ str(NonCompliantTrails)
                except Exception as e:
                    print("Exception in security control "+cis_control+" :: ",str(e))
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    return {'Result': result, 'comments': comments, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}


# CIS 3.11
def security_3_11_read_events_cloudtrail(cloudtrails):
    
    result = True
    comments = "Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events."
    NonCompliantTrails = []
    cis_control = "3.11"
    description = "Ensure that Object-level logging for read events is enabled for S3 bucket."
    Severity = 'Medium'

    if(len(cloudtrails)!=0):     
        for m,n in cloudtrails.items():
            for o in n:
                try:
                    client = boto3_session.client('cloudtrail',region_name=m)
                    event_list= client.get_event_selectors(TrailName = o['Name'])
                    for event in event_list['EventSelectors']:
                        if event['ReadWriteType'] == 'ReadOnly' or event['ReadWriteType'] == 'All':
                            if len(event['DataResources']) == 0:
                                result = False
                                NonCompliantTrails.append(o['Name'])
                    if len(NonCompliantTrails)!=0:
                        result=False
                        comments = comments + "<B><br>NonCompliantTrails</B> :: "+ str(NonCompliantTrails)
                except Exception as e:
                    print("Exception in security control "+cis_control+" :: ",str(e))
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    return {'Result': result, 'comments': comments, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# 4 Monitoring 
# CIS total automated 15 controls for Monitoring


# CIS 4.1 
def security_4_1_unauthorized_api_calls_metric_filter(cloudtrails):

    result = False
    NonCompliantAccounts = []
    cis_control = "4.1"
    description = "Ensure log metric filter unauthorized api calls"
    Severity = 'Medium'
    comments = "Incorrect log metric alerts for unauthorized_api_calls."
    group = ""
    if len(cloudtrails) > 0:

        for m, n in cloudtrails.items():
            # print(cloudtrails.items())
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        
                        for p in filters['metricFilters']:
                            # print(p['metricTransformations'])
                            
                            patterns = ["\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)", "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                
                                # print(response)
                                # print(response['MetricAlarms'])
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except Exception as e:
                    pass
            
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 4.2 
def security_4_2_console_signin_no_mfa_metric_filter(cloudtrails):

    result = False
    NonCompliantAccounts = []
    cis_control = "4.2"
    description = "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
    Severity = 'Medium'
    comments = "Incorrect log metric alerts for management console signin without MFA"
    group = ""
    if len(cloudtrails) > 0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        # print("going")
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except Exception as e:
                    pass
        
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 4.3 
def security_4_3_root_account_usage_metric_filter(cloudtrails):

    result = False
    NonCompliantAccounts = []
    cis_control = "4.3"
    description = "Ensure a log metric filter and alarm exist for root usage"
    Severity = 'Medium'
    comments = "Incorrect log metric alerts for root usage"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.userIdentity\.type\s*=\s*\"?Root", "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS", "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
        
    else:
        comments = "No CloudTrail Logs Found"
        result = False
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# IS 4.4
def security_4_4_iam_policy_change_metric_filter(cloudtrails):

    result = False
    NonCompliantAccounts = []
    cis_control = "4.4"
    description = "Ensure a log metric filter and alarm exist for IAM changes"
    Severity = "Medium"
    comments = "Incorrect log metric alerts for IAM policy changes"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass

    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Description': description, 'ControlId': cis_control, 'Severity': Severity}

# CIS 4.5
def security_4_5_cloudtrail_configuration_changes_metric_filter(cloudtrails):

    result = False
    NonCompliantAccounts = []
    cis_control = "4.5"
    description = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
    Severity = 'Medium'
    comments = "Incorrect log metric alerts for CloudTrail configuration changes"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.6
def security_4_6_console_auth_failures_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.6"
    description = "Ensure a log metric filter and alarm exist for console auth failures"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for console auth failures"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.7
def security_4_7_disabling_or_scheduled_deletion_of_customers_cmk_metric_filter(cloudtrails):

    result = False
    NonCompliantAccounts = []
    cis_control = "4.7"
    description = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.8
def security_4_8_s3_bucket_policy_changes_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.8"
    description = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.9
def security_4_9_aws_config_configuration_changes_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.9"
    description = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
    Severity = "Medium"
    comments = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
    group = ""
    if len(cloudtrails)>0:
        
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.10
def security_4_10_security_group_changes_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.10"
    description = "Ensure a log metric filter and alarm exist for security group changes"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for security group changes"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.11
def security_4_11_nacl_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.11"
    description = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.12
def security_4_12_changes_to_network_gateways_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.12"
    description = "Ensure a log metric filter and alarm exist for changes to network gateways"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for changes to network gateways"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                                
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.13
def security_4_13_changes_to_route_tables_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.13"
    description = "Ensure a log metric filter and alarm exist for route table changes"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for route table changes"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.14
def security_4_14_changes_to_vpc_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.14"
    description = "Ensure a log metric filter and alarm exist for VPC changes"
    Severity = 'Medium'
    comments = "Ensure a log metric filter and alarm exist for VPC changes"
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)", "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 4.15
def security_4_15_aws_org_changes_metric_filter(cloudtrails):
    
    result = False
    NonCompliantAccounts = []
    cis_control = "4.15"
    description = " Ensure a log metric filter and alarm exists for AWS Organizations changes."
    Severity = 'Medium'
    comments = "Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches."
    group = ""
    if len(cloudtrails)>0:

        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3_session.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?organizations\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptHandshake(\"|\)|\s)","\$\.eventName\s*\"=\s*\"?AttachPolicy(\"|\)|\s)","\$\.eventName\s*=\s*\"?CreateAccount(\"|\)|\s)","\$\.eventName\s*=\s*\"?CreateOrganizationalUnit(\"|\)|\s)","\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)","\$\.eventName\s*=\s*\"?DeclineHandshake(\"|\)|\s)","\$\.eventName\s*=\s*\"?DeleteOrganization(\"|\)|\s)","\$\.eventName\s*=\s*\"?DeleteOrganizationalUnit(\"|\)|\s)","\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)","\$\.eventName\s*=\s*\"?DetachPolicy(\"|\)|\s)","\$\.eventName\s*=\s*\"?DisablePolicyType(\"|\)|\s)","\$\.eventName\s*=\s*\"?EnablePolicyType(\"|\)|\s)","\$\.eventName\s*=\s*\"?InviteAccountToOrganization(\"|\)|\s)","\$\.eventName\s*=\s*\"?LeaveOrganization(\"|\)|\s)","\$\.eventName\s*=\s*\"?MoveAccount(\"|\)|\s)","\$\.eventName\s*=\s*\"?RemoveAccountFromOrganization(\"|\)|\s)","\$\.eventName\s*=\s*\"?UpdatePolicy(\"|\)|\s)","\$\.eventName\s*=\s*\"?UpdateOrganizationalUnit(\"|\)|\s)"]
                            if find_pattern(patterns, str(p['filterPattern'])):
                                cwclient = boto3_session.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )
                                if (len(response['MetricAlarms'])!=0):
                                    snsClient = boto3_session.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )
                                    

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                                    else:
                                        NonCompliantAccounts.append(group) 
                                    
                                else:
                                    comments = comments + "<br> :: No Alarm Exists for:: "+str(group)
                                    NonCompliantAccounts.append(group)
                except:
                    pass
    else:
        comments = "No CloudTrail Logs Found"
        result = False    
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliantLists</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}


# 5 Networking
# CIS total automated 4 controls for Networking

# CIS 5.1
def security_5_1_ssh_not_public(regions):

    result = True
    comments = "No security groups allowing Ingress found"
    NonCompliantAccounts = []
    cis_control = "5.1"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
    Severity = 'High'
    
    #regions = [regions]
    for n in regions:
        client = boto3_session.client('ec2', region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 22 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            comments = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            NonCompliantAccounts.append("<br><b>Region : </b>"+str(n) + " <b>Groups :</b> " + str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            comments = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            NonCompliantAccounts.append("<br><b>Region : </b>"+str(n) + " <b>Groups :</b> " + str(m['GroupId']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliant Security Groups</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 5.2
def security_5_2_rdp_not_public(regions):

    result = True
    comments = "No security groups allow ingress from 0.0.0.0/0 to port 3389"
    NonCompliantAccounts = []
    cis_control = "5.2"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
    Severity = 'High'
    
    #regions = [regions]
    for n in regions:
        client = boto3_session.client('ec2', region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 3389 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            comments = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            NonCompliantAccounts.append("<br><b>Region : </b>"+str(n) + " <b>Groups :</b> " + str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            comments = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            NonCompliantAccounts.append("<br><b>Region : </b>"+str(n) + " <b>Groups :</b> " + str(m['GroupId']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliant Security Groups</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 5.3
def security_5_3_flow_logs_enabled_on_all_vpc(regions):
    
    result = True
    comments = "VPC flow logging is enabled in all VPCs"
    NonCompliantAccounts = []
    cis_control = "5.3"
    description = "Ensure VPC flow logging is enabled in all VPCs"
    Severity = 'High'
    
    #regions = [regions]
    for n in regions:
        client = boto3_session.client('ec2', region_name=n)
        flowlogs = client.describe_flow_logs(
            #  No paginator support in boto atm.
        )
        activeLogs = []
        for m in flowlogs['FlowLogs']:
            if "vpc-" in str(m['ResourceId']):
                activeLogs.append(m['ResourceId'])
        vpcs = client.describe_vpcs(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available',
                    ]
                },
            ]
        )
        for m in vpcs['Vpcs']:
            if not str(m['VpcId']) in str(activeLogs):
                result = False
                comments = "VPC without active VPC Flow Logs found"
                NonCompliantAccounts.append("<br><b>Region : </b>"+str(n) + " <b>Groups :</b> " + str(m['VpcId']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliant VPCs</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# CIS 5.4 Ensure the default security group of every VPC restricts all traffic (Scored)
def security_5_4_default_security_groups_restricts_traffic(regions):
    
    result = True
    comments = "The default security group of every VPC restricts all traffic."
    NonCompliantAccounts = []
    cis_control = "5.4"
    description = "Ensure the default security group of every VPC restricts all traffic"
    Severity = 'Medium'
    #regions = [regions]
    
    for n in regions:
        client = boto3_session.client('ec2', region_name=n)
        response = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [
                        'default',
                    ]
                },
            ]
        )
        for m in response['SecurityGroups']:
            if not (len(m['IpPermissions']) + len(m['IpPermissionsEgress'])) == 0:
                result = False
                comments = "Default security groups with ingress or egress rules discovered"
                NonCompliantAccounts.append("<br><b>Region : </b>"+str(n) + " <b>Groups :</b> " + str(m['GroupId']))
    if(len(NonCompliantAccounts)!=0):
        comments = comments + "<B><br>NonCompliant Groups</B> :: "+ str(NonCompliantAccounts)
    return {'Result': result, 'comments': comments, 'NonCompliantAccounts': NonCompliantAccounts, 'Severity': Severity, 'Description': description, 'ControlId': cis_control}

# --- Main functions ---

def get_credential_report():

    x = 0
    status = ""
    while IAM_CLIENT.generate_credential_report()['State'] != "COMPLETE":
        time.sleep(2)
        x += 1
        # If no credentail report is delivered within this time fail the check.
        if x > 10:
            status = "Fail: rootUse - no CredentialReport available."
            break
    if "Fail" in status:
        return status
    response = IAM_CLIENT.get_credential_report()
    report = []
    reader = csv.DictReader(response['Content'].decode('utf-8').splitlines(), delimiter=',')
    #reader = csv.DictReader(response['Content'].splitlines(), delimiter=',')
    for row in reader:
        report.append(row)

    # Verify if root key's never been used, if so add N/A
    try:
        if report[0]['access_key_1_last_used_date']:
            pass
    except:
        report[0]['access_key_1_last_used_date'] = "N/A"
    try:
        if report[0]['access_key_2_last_used_date']:
            pass
    except:
        report[0]['access_key_2_last_used_date'] = "N/A"
    return report

def get_account_password_policy(boto3_session):
    
    IAM_CLIENT = boto3_session.client('iam')
    try:
        response = IAM_CLIENT.get_account_password_policy()
        return response['PasswordPolicy']
    except Exception as e:
        if "cannot be found" in str(e):
            return False

def get_aws_regions():
    
    client = EC2_CLIENT
    regions=[]
    region_response = client.describe_regions()
    # region_response = {
    #     'Regions' : [
    #         {'RegionName': 'ap-south-1'
    #         }
    #     ]
    #     }
    for region in region_response['Regions']:
        #s = region['RegionName']
        # bad_chars = ['[', ']' ]
        # for i in bad_chars :
        #     s = s.replace(i, '')
        regions.append(region['RegionName'])
        
    return regions

#------ Change the regions field--------- #

def get_aws_cloudTrails(regions):

    trails = dict()
    for n in regions:
        client = boto3_session.client('cloudtrail', region_name=n)
        response = client.describe_trails()
        temp = []
        for m in response['trailList']:
            if m['IsMultiRegionTrail'] is True:
                if m['HomeRegion'] == n:
                    temp.append(m)
            else:
                temp.append(m)
        if len(temp) > 0:
            trails[n] = temp
    return trails
    

def find_pattern(pattern, target):
    """Summary
    Returns:
        TYPE: Description
    """
    result = True
    for n in pattern:
        if not re.search(n, target):
            result = False
            break
    return result

def get_aws_account_number(boto3_session):
    client = boto3_session.client("sts")
    account_number = client.get_caller_identity()["Account"]
    return account_number

def set_evaluation(invokeEvent, mainEvent, annotation):

    configClient = boto3_session.client('config')
    if len(annotation) > 0:
        configClient.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': mainEvent['accountId'],
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': str(annotation),
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=mainEvent['resultToken']
        )
    else:
        configClient.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': mainEvent['accountId'],
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=mainEvent['resultToken']
        )

def gen_html(controlResult, account, FailPolicyCount, PassPolicyCount, TotalPolicyCount):

    global table
    # shortReport = shortAnnotation(controlResult)
    # res = json.loads(shortReport)
    Critical = str(get_Severity_Count(controlResult,'Critical'))
    High = str(get_Severity_Count(controlResult,'High'))
    Medium = str(get_Severity_Count(controlResult,'Medium'))
    Low = str(get_Severity_Count(controlResult,'Low'))
    FailPolicyCount = str(get_Failed_Policy_Count(controlResult))
    PassPolicyCount = str(int(TotalPolicyCount) - int(FailPolicyCount))
    table.append("""<!DOCTYPE html>
                    <html>
                    <head>
                        <title>sample</title>
                        <style type="text/css">
                                body{
                                    background: #5e5d5d;
                                }
                                .main{
                                    background: rgba(245,245,245,1);
                                    opacity: 1;
                                    position: relative;
                                }
                                .header{
                                    width: 100%;
                                    height: 142px;
                                    background: rgba(255,255,255,1);
                                    opacity: 1;
                                    position: relative;
                                    top: 0px;
                                    left: 0px;
                                    box-shadow: 0px 4px 4px rgba(0, 0, 0, 0.05999999865889549);
                                    overflow: hidden;
                                }
                                .ai-header{
                                    width: 250px;
                                    height: 56px;
                                    /*background: url(../images/v1_4.png);*/
                                    background-repeat: no-repeat;
                                    background-position: center center;
                                    background-size: cover;
                                    opacity: 1;
                                    position: absolute;
                                    top: 43px;
                                    left: 86px;
                                    overflow: hidden;
                                }
                                .axiom-text{
                                    width: 131px;
                                    color: rgba(33,64,154,1);
                                    position: relative;
                                    top: 0px;
                                    left: 0px;
                                    font-family: Open Sans;
                                    font-weight: ExtraBold;
                                    font-size: 41px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .io-text {
                                    width: 44px;
                                    color: rgba(39,170,225,1);
                                    position: absolute;
                                    top: 0px;
                                    left: 127   px;
                                    font-family: Open Sans;
                                    font-weight: SemiBold;
                                    font-size: 41px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .ai-desc{
                                    color: rgba(33,64,154,1);
                                    position: absolute;
                                    top: 50px;
                                    right: 100px;
                                    font-family: IBM Plex Sans;
                                    font-weight: Light;
                                    font-size: 42px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .report-body{
                                    background: rgba(245,245,245,1);
                                    opacity: 1;
                                    /*position: relative;*/
                                }
                                .report-details{
                                    height: 114px;
                                    background: rgba(33,64,154,1);
                                    opacity: 1;
                                    margin: 30px 100px;
                                    left: 0px;
                                    right: 0px;
                                    background-repeat: no-repeat;
                                    background-position: center center;
                                    background-size: cover;
                                    opacity: 1;
                                    overflow: hidden;
                                }
                                .report-head-text{
                                    width: 341px;
                                    color: rgba(255,255,255,1);
                                    position: absolute;
                                    top: 28px;
                                    left: 24px;
                                    font-family: IBM Plex Sans;
                                    font-weight: Regular;
                                    font-size: 24px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .details{
                                    width: 758px;
                                    height: 75px;
                                    background: url(../images/v1_10.png);
                                    background-repeat: no-repeat;
                                    background-position: center center;
                                    background-size: cover;
                                    opacity: 1;
                                    position: absolute;
                                    top: 17px;
                                    left: 435px;
                                    overflow: hidden;
                                }
                                .report-info-head{
                                    width: 141px;
                                    color: rgba(255,255,255,1);
                                    position: absolute;
                                    top: 22px;
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 18px;
                                    opacity: 0.3499999940395355;
                                    text-align: left;
                                }
                                .rh-sub-section{
                                    position: absolute;
                                }
                                .scan-info{
                                    left: 475px;
                                }
                                .host-info{
                                    left: 775px;
                                }
                                .report-sub-head{
                                    width: 78px;
                                    color: rgba(39,170,225,1);
                                    position: absolute;
                                    top: 52px;
                                    left: 0px;
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 12px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .report-sub-text{
                                    width: 218px;
                                    color: rgba(255,255,255,1);
                                    position: absolute;
                                    top: 66px;
                                    left: 0px;
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 18px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .vul-categories{
                                    margin-bottom: 50px;
                                }
                                .label{
                                    width: 139px;
                                    height: 96px;
                                    /*background: rgba(255,255,255,1);*/
                                    position: relative;
                                    opacity: 1;
                                    border: 1px solid rgba(219,219,219,1);
                                    margin: 0px 10px;
                                    align-items: center;
                                    justify-content: center;
                                }
                                .label-top{
                                    width: 100%;
                                    height: 10px;
                                    background: black;
                                    position: absolute;
                                    top: 0px;
                                }
                                .selected-cat{
                                    background: rgba(255,255,255,1);
                                }
                                .selected-cat:after {
                                  content: '';
                                  position: absolute;
                                  left: 1px;
                                  top: 96px;
                                  left: 55px;
                                  border-top: 15px solid white;
                                  border-left: 15px solid transparent;
                                  border-right: 15px solid transparent;
                                }
                                .count{
                                    text-align: center;
                                    color: rgba(0,0,0,1);
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 32px;
                                }
                                .category{
                                    color: rgba(88,88,88,1);
                                    font-family: IBM Plex Sans;
                                    font-weight: Regular;
                                    font-size: 18px;
                                    opacity: 1;
                                    text-align: center;
                                }
                    
                                .label-critical{
                                    background: rgb(243, 36, 0);
                                }
                                .label-high{
                                    background: rgba(135, 211, 124, 1);
                                }
                                .label-medium{
                                    background: rgba(232,193,52,1);
                                }
                                .cat-high{
                                    color: rgba(224,91,67,1) !important;
                                }
                                .cat-critical{
                                    color: rgba(246, 71, 71, 1) !important;
                                }
                                .cat-medium{
                                    color: rgba(232,193,52,1) !important;
                                }
                                .cat-low{
                                    color: rgba(101,175,123,1) !important;
                                }
                                .hi-sub-sec{
                                    position: absolute;
                                }
                                .ip-sec{
                                    left: 196px;
                                }
                                .os-sec{
                                    left: 410px;
                                }
                                .sub-sec {
                                    margin: 0px 100px;
                                }
                                .vul-sec{
                                    top: 192px;
                                }
                                .passed-sec{
                                    top: 300px
                                }
                                .other-sec{
                                    top: 600px;
                                }
                                .row-heading{
                    				width: 187px;
                    			    opacity: 1;
                    			    margin-top: -2px;
                    			    margin-bottom: 15px;
                                }
                                .sec-heading{
                                    width: auto;
                                    color: rgba(0,0,0,1);
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 18px;
                                    opacity: 1;
                                    text-align: left;
                                    margin-top: 40px;
                                    margin-bottom: 15px;
                                }
                                .table-sec{
                                    width: 100%;
                                    background: white;
                                    padding: 30px;
                                }
                                .table-sec-heading{
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 28px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .passed-text{
                                    color: rgba(81,175,109,1);
                                }
                                .other-text{
                                    color: rgba(70,123,235,1);
                                }
                                .d-flex {
                                    display: flex;
                                }
                                .all-table .table-body{
                                    height: 360px;
                                    overflow: auto;
                                }
                                .table-head{
                                    border-bottom: 1px solid black;
                                    height: 50px;
                                    align-items: center;
                                }
                                .row{
                                    height: auto;
                                    align-items: center;
                                }
                                .label-high1{
                                    background: rgba(224,91,67,1);
                                }
                                .vul-col-ano{
                                    width: 22%;
                                    padding:0px 30px;
                                }
                                .vul-col-sta{
                                    width: 10%;
                                
                                }
                                .vul-col-sev{
                                    width: 10%;
                                    text-align: left;
                                }
                                .vul-col-bp{
                                    width: 8%;
                                    padding-left: 10px;
                                }
                                .vul-col-com{
                                    width: 49%;
                                }
                                .col-bp{
                                    width: 15%;
                                    padding-left: 10px;
                                }
                                .col-val{
                                    width: 15%;
                                    padding: 0px 50px;
                                }
                                .col-com{
                                    width: 36%;
                                }
                                .blue-row{
                                    background: rgba(246,248,255,1);
                                }
                                .table-thd{
                                    color: rgba(0,0,0,1);
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 19px;
                                    opacity: 0.6000000238418579;
                                    text-align: left;
                                }
                                .table-td{
                                    color: rgba(0,0,0,1);
                                    font-family: IBM Plex Sans;
                                    font-weight: SemiBold;
                                    font-size: 16px;
                                    opacity: 1;
                                    text-align: left;
                                }
                                .button4 {
                                    background-color: white;
                                    color: black;
                                    border: 2px solid #e7e7e7;
                                }
                                .Hover:hover {
                                    background-color: lightsteelblue;
                                    color: black;
                                }

                                .hidden {
                                    display: none;
                                }
                        </style>
                        <link href="https://fonts.googleapis.com/css?family=Open+Sans&amp;display=swap" rel="stylesheet">
                        <link href="https://fonts.googleapis.com/css?family=IBM+Plex+Sans&amp;display=swap" rel="stylesheet">
                    </head>
                    <body>
                        <div class="main">
                            <div class="header">
                                <div class="ai-header">
                                    <span class="axiom-text">Axiom</span>
                                    <span class="io-text">IO</span>
                                </div>
                                <span class="ai-desc">Security Automation Simplified</span>
                            </div>
                            <div class="report-body">
                                <div class="report-details">
                                        <div class="rh-sub-section">
                                            <span class="report-head-text">AWS Security Best Practices </span>
                                        </div>
                                        <div class="rh-sub-section scan-info">
                                            <div class="report-info-head">Scan information</div>
                                            <div class="report-sub-head">Date</div>
                                            <div class="report-sub-text">"""+time.strftime("%c %Z")+"""</div>
                                        </div>
                                        <div class="rh-sub-section host-info">
                                            <span class="report-info-head">AWS Account</span>
                                            <div class="hi-sub-sec dns-sec">
                                                <span class="report-sub-head">Number</span>
                                                <span class="report-sub-text">"""+get_aws_account_number(boto3_session)+"""</span>
                                            </div>
                                        </div>
                                </div>
                                <div class="sub-sec vul-sec">
                                    <div class="sec-heading">Policy Compliance</div>
                                    <div class="vul-categories d-flex">
                                        <div class="all d-flex label Hover "onclick="filterSelection('all')">
                                            <div>
                                                <div class="count">"""+TotalPolicyCount+"""</div>
                                                <div class="category">All</div>
                                            </div>
                                        </div>
                                        <div class="critical d-flex label Hover "onclick="filterSelection('Failed')">
                                            <div class="label-top label-critical"></div>
                                            <div>
                                                <div class="count cat-critical">"""+FailPolicyCount+"""</div>
                                                <div class="category">Non-Compliant</div>
                                            </div>
                                        </div>
                                        <div class="high d-flex label Hover "onclick="filterSelection('Passed')">
                                            <div class="label-top label-high"></div>
                                            <div>
                                                <div class="count cat-low">"""+PassPolicyCount+"""</div>
                                                <div class="category">Compliant</div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="sec-heading">
                                        <div class="cat-critical">* Failed Policies Based on Severity</div>
                                    </div>
                                    <div class="vul-categories d-flex">
                                        <div class="high d-flex label Hover "onclick="filterSelection('Critical')">
                                            <div class="label-top label-critical"></div>
                                            <div>
                                                <div class="count cat-critical">"""+Critical+"""</div>
                                                <div class="category">Critical</div>
                                            </div>
                                        </div>
                                        <div class="critical d-flex label Hover "onclick="filterSelection('High')">
                                            <div class="label-top label-high1"></div>
                                            <div>
                                                <div class="count cat-high">"""+High+"""</div>
                                                <div class="category">High</div>
                                            </div>
                                        </div>
                                        <div class="high d-flex label Hover "onclick="filterSelection('Medium')">
                                            <div class="label-top label-medium"></div>
                                            <div>
                                                <div class="count cat-medium">"""+Medium+"""</div>
                                                <div class="category">Medium</div>
                                            </div>
                                        </div>
                                        <div class="high d-flex label Hover "onclick="filterSelection('Low')">
                                            <div class="label-top label-high"></div>
                                            <div>
                                                <div class="count cat-low">"""+Low+"""</div>
                                                <div class="category">Low</div>
                                            </div>
                                        </div>
                                    </div>""")

def printTable(controlResult,heading):
        global table
        table.append("""	<div class="table-sec">
                            <div class="table-sec-heading all-text">""" + heading + """</div>
                            <div class="table all-table">
                                <div class="d-flex table-head">
                                    <div class="vul-col-bp table-thd" style="
                                        width: 80px;
                                    ">Policy Id</div>
                                    <div class="vul-col-ano table-thd" style="
                                                                                height: 20.333;
                                                                                width: 229.562px;
                                                                            ">Description</div>
                                    <div class="vul-col-sta table-thd" style="
                                                                            width: 102.458px;
                                                                        ">Status</div>
                                    <div class="vul-col-sev table-thd" style="
                                        width: 105.688px;
                                    ">Severity</div>
                                    <div class="vul-col-com table-thd">Comments/Recommendations</div>
                                </div>
                                <div class="table-body"> """)
        #for m, _ in enumerate(controlResult):
        for n in range(len(controlResult)):
                if(n%2 == 0):
                    table.append("""    <div class="d-flex row">
                                            <div class="vul-col-bp table-td">"""+controlResult[n]['ControlId']+"""</div>
                                            <div class="vul-col-ano table-td">"""+controlResult[n]['Description']+"""</div>""")
                else:
                    table.append("""    <div class="d-flex row blue-row">
                                            <div class="vul-col-bp table-td">"""+controlResult[n]['ControlId']+"""</div>
                                            <div class="vul-col-ano table-td">"""+controlResult[n]['Description']+"""</div>""")
                if (controlResult[n]['Result'] == True):
                    table.append("""<div class="vul-col-sta table-td cat-low">Passed</div>""")
                elif(controlResult[n]['Result'] == False):
                    table.append("""<div class="vul-col-sta table-td cat-critical">Failed</div>""")
                else:
                    table.append("""<div class="vul-col-sta table-td"></div>""")
                if (controlResult[n]['Severity']=='Critical'):
                    table.append(""" <div class="vul-col-sev table-td cat-critical">"""+controlResult[n]['Severity']+"""</div>""")
                elif(controlResult[n]['Severity']=='High'):
                    table.append(""" <div class="vul-col-sev table-td cat-high">"""+controlResult[n]['Severity']+"""</div>""")
                elif(controlResult[n]['Severity']=='Medium'):
                    table.append(""" <div class="vul-col-sev table-td cat-medium">"""+controlResult[n]['Severity']+"""</div>""")
                elif(controlResult[n]['Severity']=='Low'):
                    table.append(""" <div class="vul-col-sev table-td cat-low">"""+controlResult[n]['Severity']+"""</div>""")
                else:
                    table.append(""" <div class="vul-col-sev table-td"></div>""")

                table.append(""" <div class="vul-col-com table-td">"""+controlResult[n]['comments']+"""</div>
                                    </div>
                                    <div class = "row-heading"></div>""")
                
        table.append(""" </div>
                            </div>
                            </div> <div class="sec-heading"></div>""")

def printFooter():
        global table
        table.append("""   </div> </div>               
                            </div>
                            <script>
                            filterSelection("all");
        function filterSelection(c) {
            var x, i,sev,sta;
            x = document.getElementsByClassName("d-flex row");
            if (c == "all")
            {
                for (i = 0; i < x.length; i++) 
                {
                    w3RemoveClass(x[i], "hidden");
                }
            }
            else 
            {
                for (i = 0; i < x.length; i++) 
                {
                    sev = x[i].getElementsByClassName("vul-col-sev table-td")[0].innerHTML;
                    sta = x[i].getElementsByClassName("vul-col-sta table-td")[0].innerHTML;
                    if(sev.length == 0)
                    {
                        continue;
                    }
                    w3RemoveClass(x[i], "hidden");
                    if (c != "Passed" && c != "Failed")
                     {
                        if (sev.toUpperCase() != c.toUpperCase())
                        {
                            w3AddClass(x[i], "hidden");
                        }
                    }
                    else {
                        if (sta.toUpperCase() != c.toUpperCase())
                        {
                            w3AddClass(x[i], "hidden");
                        }
                    }
                    if (sev.toUpperCase() == c.toUpperCase()) 
                    {
                        if (sta != "Failed") 
                        {
                            w3AddClass(x[i], "hidden");
                        }
                    }
                }
            }
            return;
        }
        // Add Hidden to Particular Class
        function w3AddClass(element, name) {
            var i, arr1, arr2;
            arr1 = element.className.split(" ");
            arr2 = name.split(" ");
            for (i = 0; i < arr2.length; i++) {
                if (arr1.indexOf(arr2[i]) == -1) { element.className += " " + arr2[i]; }

            }
            return;
        }
        // Remove Hidden to particular Class
        function w3RemoveClass(element, name) {
            var i, arr1, arr2;
            arr1 = element.className.split(" ");
            arr2 = name.split(" ");
            for (i = 0; i < arr2.length; i++) {
                while (arr1.indexOf(arr2[i]) > -1) {
                    arr1.splice(arr1.indexOf(arr2[i]), 1);
                }
            }
            element.className = arr1.join(" ");
            return;
        }

        // Add active class to the current button (highlight it)
        var btnContainer = document.getElementById("myBtnContainer");
        var btns = btnContainer.getElementsByClassName("btn");
        for (var i = 0; i < btns.length; i++) {
            btns[i].addEventListener("click", function () {
                var current = document.getElementsByClassName("active");
                current[0].className = current[0].className.replace(" active", "");
                this.className += " active";
            });
        }
                        </script>  
                        </body>
                        </html>""")
        #print(table)
        

def get_Failed_Policy_Count(controlResult):
    count = 0
    for m, _ in enumerate(controlResult):
        for n in range(len(controlResult[m])):          
            if controlResult[m][n]['Result'] is False:
                count = count + 1
    return count

def get_Severity_Count(controlResult,severity):
    """Summary
    Args:
        controlResult (TYPE): Description
    Returns:
        TYPE: Description
    """
    Count = 0
    for m, _ in enumerate(controlResult):
        for n in range(len(controlResult[m])):
            if controlResult[m][n]['Severity'] == severity:
                if controlResult[m][n]['Result'] == False:
                    Count += 1
    return Count

def AWS_CIS(event,context):

    global boto3_session,IAM_CLIENT,S3_CLIENT,EC2_CLIENT,RDS_CLIENT

    requestId = event['requestId']
    # cognitoId = event['cognitoId']
    access_type = event['access_type']
    access_input = event['access_input']
    email= event['email']
    boto3_session = session.get_boto3_session(requestId,access_type,access_input)

    session_client = boto3_session.client('sts')
    print(session_client.get_caller_identity())

    IAM_CLIENT = boto3_session.client('iam')
    S3_CLIENT = boto3_session.client('s3')
    EC2_CLIENT = boto3_session.client('ec2')
    RDS_CLIENT = boto3_session.client('rds')

    # Globally used resources
    region_list = get_aws_regions()
    try:
        credential_report = get_credential_report()
    except Exception as e:
        if 'Throttling' in str(e):
            print("Run The Script once again")
            exit(0)
        print(str(e))

    passwdPolicy = get_account_password_policy(boto3_session)
    cloudtrails = get_aws_cloudTrails(region_list)
    account_number = get_aws_account_number(boto3_session)

    iam_security=[]

    iam_security.append(security_1_4_root_access_key_exists(credential_report))
    iam_security.append(security_1_5_mfa_root_enabled())
    iam_security.append(security_1_6_hardware_mfa_root_enabled())
    iam_security.append(security_1_7_avoid_root_for_admin_tasks(credential_report))
    iam_security.append(security_1_8_minimum_password_policy_length(passwdPolicy))
    iam_security.append(security_1_9_password_policy_reuse(passwdPolicy))
    iam_security.append(security_1_10_enable_mfa_on_iam_console_password(credential_report))
    iam_security.append(security_1_11_no_iam_access_key_passwd_setup(credential_report))
    iam_security.append(security_1_12_credentials_unused(credential_report))
    iam_security.append(security_1_13_no_2_active_access_keys_iam_user())
    iam_security.append(security_1_14_access_keys_rotated(credential_report))
    iam_security.append(security_1_15_only_group_policies_on_iam_users())
    iam_security.append(security_1_16_no_admin_priv_policies())
    iam_security.append(security_1_17_ensure_support_roles())
    iam_security.append(security_1_19_expired_SSL_TLS_certificates())
    iam_security.append(security_1_20_Bucket_PublicAccess_check())
    iam_security.append(security_1_21_Access_Analyzer())

    print("IAM Done")

    storage = []
    
    storage.append(security_2_1_1_s3_EncryptionCheck())
    storage.append(security_2_1_1_SslPolicyCheck()) 
    storage.append(security_2_2_EBSVolumeEncryptCheck(region_list))

    print("Storage Done")

    logging= []

    logging.append(security_3_1_cloud_trail_all_regions(cloudtrails))
    logging.append(security_3_2_cloudtrail_validation(cloudtrails))
    logging.append(security_3_3_cloudtrail_public_bucket(cloudtrails))
    logging.append(security_3_4_integrate_cloudtrail_cloudwatch_logs(cloudtrails))
    logging.append(security_3_5_ensure_config_all_regions(region_list))
    logging.append(security_3_6_cloudtrail_bucket_access_log(cloudtrails))
    logging.append(security_3_7_cloudtrail_log_kms_encryption(cloudtrails))
    logging.append(security_3_8_kms_cmk_rotation(region_list))
    logging.append(security_3_9_vpc_flow_logs_enabled(region_list))
    logging.append(security_3_10_write_events_cloudtrail(cloudtrails))
    logging.append(security_3_11_read_events_cloudtrail(cloudtrails))

    print("Logging Done")

    
    monitoring = []

    monitoring.append(security_4_1_unauthorized_api_calls_metric_filter(cloudtrails))
    monitoring.append(security_4_2_console_signin_no_mfa_metric_filter(cloudtrails))
    monitoring.append(security_4_3_root_account_usage_metric_filter(cloudtrails))
    monitoring.append(security_4_4_iam_policy_change_metric_filter(cloudtrails))
    monitoring.append(security_4_5_cloudtrail_configuration_changes_metric_filter(cloudtrails))
    monitoring.append(security_4_6_console_auth_failures_metric_filter(cloudtrails))
    monitoring.append(security_4_7_disabling_or_scheduled_deletion_of_customers_cmk_metric_filter(cloudtrails))
    monitoring.append(security_4_8_s3_bucket_policy_changes_metric_filter(cloudtrails))
    monitoring.append(security_4_9_aws_config_configuration_changes_metric_filter(cloudtrails))
    monitoring.append(security_4_10_security_group_changes_metric_filter(cloudtrails))
    monitoring.append(security_4_11_nacl_metric_filter(cloudtrails))
    monitoring.append(security_4_12_changes_to_network_gateways_metric_filter(cloudtrails))
    monitoring.append(security_4_13_changes_to_route_tables_metric_filter(cloudtrails))
    monitoring.append(security_4_14_changes_to_vpc_metric_filter(cloudtrails))
    monitoring.append(security_4_15_aws_org_changes_metric_filter(cloudtrails))

    print("Monitoring Done")

    
    networking = []
    networking.append(security_5_1_ssh_not_public(region_list))
    networking.append(security_5_2_rdp_not_public(region_list))
    networking.append(security_5_3_flow_logs_enabled_on_all_vpc(region_list))
    networking.append(security_5_4_default_security_groups_restricts_traffic(region_list))

    print("Networking Done")

    
    # Join results
    cis_control = []
    cis_control.append(iam_security)
    cis_control.append(storage)
    cis_control.append(logging)
    cis_control.append(monitoring)
    cis_control.append(networking)

    TotalPolicyCount = str(len(cis_control[0])+ len(cis_control[1]) + len(cis_control[2]) + len(cis_control[3])+len(cis_control[4]))
    
    # Generating HTML Report

    gen_html(cis_control, account, FailPolicyCount, PassPolicyCount, TotalPolicyCount)

    printTable(iam_security,iam_sec)
    printTable(storage,store)
    printTable(logging,log)
    printTable(monitoring, monitor)
    printTable(networking, network)
    
    printFooter()

    htmlReport=table
    # print(htmlReport)
    reportName = "AWS_CIS_Report_"+account_number+"_CIS.html"
    tmp_file_path = "/tmp/"+reportName
    Html_file= open(tmp_file_path,"w")
    for item in htmlReport:
        Html_file.write(item)
        Html_file.flush()
    Html_file.close()
    try:
        record = get_record(event['requestId'])
        name = record['data'].get('firstName') + ' ' + record['data'].get('lastName')
        emails = [record['data'].get('email')]
        subject = "AWS Scan Report"
        body = """The AWS scan report is attached here \n"""
        # Send scan report email
        send_notification(name, subject, body, emails, tmp_file_path)
        update_record(event['requestId'])
        print("record updated....")
    except Exception as e:
        print(str(e))

    boto3_session = ""
    if os.path.exists(tmp_file_path):
        os.remove(tmp_file_path)
        print("Removed the file : ", tmp_file_path)     
    else:
        print("Sorry, file %s does not exist." % tmp_file_path)

    #update the scan status in dynamodb

# if __name__ == '__main__':
    
#     event=""
#     event['requestId'] = "randomid"
#     event['access_type'] = "credentils"
#     event['access_input'] =  {'access_key':'<value>','access_secret':'<value>'}
#     event['email']="example@email.com"
    
#     AWS_CIS(event,"example")
