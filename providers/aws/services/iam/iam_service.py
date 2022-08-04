import csv
from dataclasses import dataclass

from lib.logger import logger
from providers.aws.aws_provider import current_audit_info


################## IAM
class IAM:
    def __init__(self, audit_info):
        self.service = "iam"
        self.session = audit_info.audit_session
        self.account = audit_info.audited_account
        self.client = self.session.client(self.service)
        self.region = audit_info.profile_region
        self.users = self.__get_users__()
        self.roles = self.__get_roles__()
        self.account_summary = self.__get_account_summary__()
        self.virtual_mfa_devices = self.__list_virtual_mfa_devices__()
        self.customer_managed_policies = self.__get_customer_managed_policies__()
        self.__get_customer_managed_policies_version__(self.customer_managed_policies)
        self.credential_report = self.__get_credential_report__()
        self.groups = self.__get_groups__()
        self.__get_group_users__()
        self.__list_attached_group_policies__()
        self.__list_mfa_devices__()

    def __get_client__(self):
        return self.client

    def __get_session__(self):
        return self.session

    def __get_roles__(self):
        try:
            get_roles_paginator = self.client.get_paginator("list_roles")
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            roles = []
            for page in get_roles_paginator.paginate():
                for role in page["Roles"]:
                    roles.append(role)

            return roles

    def __get_credential_report__(self):
        report_is_completed = False
        while not report_is_completed:
            try:
                report_status = self.client.generate_credential_report()
            except Exception as error:
                logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
            else:
                if report_status["State"] == "COMPLETE":
                    report_is_completed = True

        # Convert credential report to list of dictionaries
        credential = self.client.get_credential_report()["Content"].decode("utf-8")
        credential_lines = credential.split("\n")
        csv_reader = csv.DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)
        return credential_list

    def __get_groups__(self):
        try:
            get_groups_paginator = self.client.get_paginator("list_groups")
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            groups = []
            for page in get_groups_paginator.paginate():
                for group in page["Groups"]:
                    groups.append(Group(group["GroupName"], group["Arn"]))

            return groups

    def __get_customer_managed_policies__(self):
        try:
            get_customer_managed_policies_paginator = self.client.get_paginator(
                "list_policies"
            )
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            customer_managed_policies = []
            # Use --scope Local to list only Customer Managed Policies
            for page in get_customer_managed_policies_paginator.paginate(Scope="Local"):
                for customer_managed_policy in page["Policies"]:
                    customer_managed_policies.append(customer_managed_policy)

            return customer_managed_policies

    def __get_customer_managed_policies_version__(self, customer_managed_policies):
        try:
            for policy in customer_managed_policies:
                response = self.client.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )
                policy["PolicyDocument"] = response["PolicyVersion"]["Document"]
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")

    def __get_account_summary__(self):
        try:
            account_summary = self.client.get_account_summary()
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:

            return account_summary

    def __get_users__(self):
        try:
            get_users_paginator = self.client.get_paginator("list_users")
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            users = []
            for page in get_users_paginator.paginate():
                for user in page["Users"]:
                    if "PasswordLastUsed" not in user:
                        users.append(User(user["UserName"], user["Arn"], None))
                    else:
                        users.append(
                            User(
                                user["UserName"], user["Arn"], user["PasswordLastUsed"]
                            )
                        )

            return users

    def __list_virtual_mfa_devices__(self):
        try:
            list_virtual_mfa_devices_paginator = self.client.get_paginator(
                "list_virtual_mfa_devices"
            )
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")
        else:
            mfa_devices = []
            for page in list_virtual_mfa_devices_paginator.paginate():
                for mfa_device in page["VirtualMFADevices"]:
                    mfa_devices.append(mfa_device)

            return mfa_devices

    def __list_attached_group_policies__(self):
        try:
            for group in self.groups:
                list_attached_group_policies_paginator = self.client.get_paginator(
                    "list_attached_group_policies"
                )
                attached_group_policies = []
                for page in list_attached_group_policies_paginator.paginate(
                    GroupName=group.name
                ):
                    for attached_group_policy in page["AttachedPolicies"]:
                        attached_group_policies.append(attached_group_policy)

                group.attached_policies = attached_group_policies
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")

    def __get_group_users__(self):
        try:
            for group in self.groups:
                get_group_paginator = self.client.get_paginator("get_group")
                group_users = []
                for page in get_group_paginator.paginate(GroupName=group.name):
                    for user in page["Users"]:
                        if "PasswordLastUsed" not in user:
                            group_users.append(
                                User(user["UserName"], user["Arn"], None)
                            )
                        else:
                            group_users.append(
                                User(
                                    user["UserName"],
                                    user["Arn"],
                                    user["PasswordLastUsed"],
                                )
                            )
                group.users = group_users
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")

    def __list_mfa_devices__(self):
        try:
            for user in self.users:
                list_mfa_devices_paginator = self.client.get_paginator(
                    "list_mfa_devices"
                )
                mfa_devices = []
                for page in list_mfa_devices_paginator.paginate(UserName=user.name):
                    for mfa_device in page["MFADevices"]:
                        mfa_serial_number = mfa_device["SerialNumber"]
                        mfa_type = (
                            mfa_device["SerialNumber"].split(":")[5].split("/")[0]
                        )
                        mfa_devices.append(MFADevice(mfa_serial_number, mfa_type))
                user.mfa_devices = mfa_devices
        except Exception as error:
            logger.error(f"{self.region} -- {error.__class__.__name__}: {error}")


@dataclass
class MFADevice:
    serial_number: str
    type: str

    def __init__(self, serial_number, type):
        self.serial_number = serial_number
        self.type = type


@dataclass
class User:
    name: str
    arn: str
    mfa_devices: list[MFADevice]
    password_last_used: str

    def __init__(self, name, arn, password_last_used):
        self.name = name
        self.arn = arn
        self.password_last_used = password_last_used
        self.mfa_devices = []


@dataclass
class Group:
    name: str
    arn: str
    attached_policies: list[dict]
    users: list[User]

    def __init__(self, name, arn):
        self.name = name
        self.arn = arn
        self.attached_policies = []
        self.users = []


iam_client = IAM(current_audit_info)