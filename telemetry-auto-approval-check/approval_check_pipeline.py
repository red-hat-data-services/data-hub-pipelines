from kfp import dsl
# from kfp_tekton.tekton import CEL_ConditionOp
from kfp import components
from kubernetes.client import V1Volume, V1VolumeMount, V1ConfigMapVolumeSource

BASE_IMAGE = "quay.io/gmfrasca/dh-telemetry-approval-check:latest"
NOTIFY_IMAGE = "quay.io/gmfrasca/dh-telemetry-approval-check:latest"  # TODO: change to image that can use sendmail
CONFIG_PATH = "/opt/app-root/src/config/config.yaml"


def check_management_chain(username):
    CONFIG_PATH = "/opt/app-root/src/config/config.yaml"

    import argparse
    import logging
    import ldap
    import json
    import yaml
    import os


    DEFAULT_LDAP_SERVER = 'ldap://ldap.corp.redhat.com'
    DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), 'config.yaml')
    METADATA_FIELDS = ['memberOf', 'manager', 'rhatProduct', 'rhatSubproduct', 'rhatProject', 'rhatRnDComponent']


    class LdapInterface(object):
        '''Abstraction to handle interfacing with LDAP'''

        def __init__(self, uri):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.uri = uri
            self.conn = self.connect()

        def connect(self):
            '''Connect to LDAP server and initialize the interface'''
            conn = ldap.initialize(self.uri)
            return conn

        def get_user(self, user):
            '''Search LDAP server for a specific user and record their metadata'''
            res = self.conn.search_s('dc=redhat,dc=com',
                                     ldap.SCOPE_SUBTREE,
                                     f"uid={user}",
                                     METADATA_FIELDS)
            if len(res) > 1:
                self.logger.warning("More than 1 user with uid found. using first result")
            uid, metadata = res[0]
            metadata = self._decode_metadata(metadata)
            return LdapUserEntry(user, metadata)

        def _decode_metadata(self, metadata):
            '''Recursively decode any bytestrings contained within various datastructs'''
            if isinstance(metadata, str):
                return metadata
            if isinstance(metadata, bytes):
                return metadata.decode('utf-8')
            if isinstance(metadata, list):
                return [(self._decode_metadata(m)) for m in metadata]
            if isinstance(metadata, dict):
                decoded = {}
                for k, v in metadata.items():
                    k = self._decode_metadata(k)
                    v = self._decode_metadata(v)
                    decoded[k] = v
                return decoded

        def get_management_chain(self, uid):
            '''Recursively get list of all LDAP uids in user's management heirachy'''
            user = self.get_user(uid)
            self.logger.debug(f"Checking for manager of {uid}")
            manager_uid = user.get_manager_uid()
            self.logger.debug(f"Manager UID: {manager_uid}")
            if manager_uid is not None and manager_uid != uid:
                mgmt_chain = self.get_management_chain(manager_uid)
                mgmt_chain.append(manager_uid)
                return mgmt_chain
            else:
                return []


    class LdapUserEntry(object):
        '''Represents LDAP metadata for a single user'''

        def __init__(self, uid, user_info):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.uid = uid
            self.user_info = user_info

        def __repr__(self):
            return str(json.dumps(self.user_info))

        def _parse_from_ldap_str(self, item, data):
            '''Extract a specific item from a domain name string (ex: cn=foo,dc=bar)'''
            split = data.split(",")
            for s in split:
                if s.startswith(item):
                    return s.split("=")[1]

        def get_manager_uid(self):
            '''Get the LDAP UID of this user's manager'''
            manager = self.user_info.get('manager', [])
            if len(manager) == 0:
                return None
            return self._parse_from_ldap_str("uid", manager[0])

        def get_groups(self):
            '''Aggregate a list of LDAP groups this user is a member of'''
            groups = self.user_info.get('memberOf', [])
            return [self._parse_from_ldap_str("cn", x) for x in groups]

        def get_projects(self):
            '''Aggregate a list of products, subproducts, projects and componets this user works on'''
            prod_list = self.user_info.get('rhatProduct', [])
            subproducts = self.user_info.get('rhatSubproduct', [])
            projects = self.user_info.get('rhatProject', [])
            components = self.user_info.get('rhatRnDComponent', [])
            prod_list.extend(subproducts)
            prod_list.extend(projects)
            prod_list.extend(components)
            return prod_list


    class TelemeterApprovalChecker(object):
        '''Interface to check if an ldap user is autoapproved to access telemetery data/dashboards'''

        def __init__(self, config):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.cfg = self._get_config(config)
            self.conn = LdapInterface(self.cfg.get('ldap_server', DEFAULT_LDAP_SERVER))
            self.preapprovals = self.cfg.get('preapprovals', {})
            self.preapproved_managers = self.preapprovals.get("managers", [])
            self.preapproved_groups = self.preapprovals.get("groups", [])
            self.preapproved_projects = self.preapprovals.get("projects", [])

        def _get_config(self, config_file):
            '''Load preapproval and ldap settings from config yaml'''
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)

        def check_approval(self, uid):
            '''Check if user is automatically approved for access to telemetry'''
            in_mgmt_chain = self.check_management_chain(uid, self.preapproved_managers)
            in_ldap_group = self.check_groups(uid, self.preapproved_groups)
            in_approved_project = self.check_project(uid, self.preapproved_projects)

            approved = any([in_mgmt_chain, in_ldap_group, in_approved_project])

            if in_ldap_group:
                self.logger.info(f"User '{uid}' already has access to telemetery!")
            elif approved:
                self.logger.info(f"User '{uid}' is auto-approved for, but hasn't yet been granted, telemetry access")
            else:
                self.logger.info(f"User '{uid}' is not automatically approved for telemetry access")
                self.logger.info("Please check Data Hub Onboarding documentation if further verification is required")
            return approved

        def check_management_chain(self, uid, approved_managers=[]):
            '''Check if user works (directly or indirectly) for a preapproved manager'''
            mgmt_chain = self.conn.get_management_chain(uid)
            for mgr in mgmt_chain:
                if mgr in approved_managers:
                    self.logger.debug(f"User '{uid}' is preapproved as they are a direct or indirect report of '{mgr}'")
                    return True
            self.logger.debug(f"The management heirarcy for user '{uid}' does not auto-approve them.")
            return False

        def check_groups(self, uid, approved_groups=[]):
            '''Check if user is a member on a preapproved group'''
            groups = self.conn.get_user(uid).get_groups()
            for g in groups:
                if g in approved_groups:
                    self.logger.debug(f"User '{uid}' belongs to a preapproved LDAP group: {g}")
                    return True
            self.logger.debug(f"User '{uid}' does not belong to any preapproved LDAP groups")
            return False

        def check_project(self, uid, approved_projects=[]):
            '''Check if user works on a preapproved project'''
            projects = self.conn.get_user(uid).get_projects()
            for p in projects:
                if p in approved_projects:
                    self.logger.debug(f"User '{uid}' works on a preapproved project: {p}")
                    return True
            self.logger.debug(f"User '{uid}' does not work on any preapproved projects")
            return False

    tac = TelemeterApprovalChecker(CONFIG_PATH)
    approved = tac.check_management_chain(username, tac.preapproved_managers)
    if approved:
        print("User has a pre-approved manager in their management chain")
        print("APPROVED")
    else:
        print("User does not have a pre-approved manager in their management chain")
        print("DEFER APPROVAL")
    return approved


def check_projects(username):
    CONFIG_PATH = "/opt/app-root/src/config/config.yaml"

    import argparse
    import logging
    import ldap
    import json
    import yaml
    import os


    DEFAULT_LDAP_SERVER = 'ldap://ldap.corp.redhat.com'
    DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), 'config.yaml')
    METADATA_FIELDS = ['memberOf', 'manager', 'rhatProduct', 'rhatSubproduct', 'rhatProject', 'rhatRnDComponent']


    class LdapInterface(object):
        '''Abstraction to handle interfacing with LDAP'''

        def __init__(self, uri):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.uri = uri
            self.conn = self.connect()

        def connect(self):
            '''Connect to LDAP server and initialize the interface'''
            conn = ldap.initialize(self.uri)
            return conn

        def get_user(self, user):
            '''Search LDAP server for a specific user and record their metadata'''
            res = self.conn.search_s('dc=redhat,dc=com',
                                     ldap.SCOPE_SUBTREE,
                                     f"uid={user}",
                                     METADATA_FIELDS)
            if len(res) > 1:
                self.logger.warning("More than 1 user with uid found. using first result")
            uid, metadata = res[0]
            metadata = self._decode_metadata(metadata)
            return LdapUserEntry(user, metadata)

        def _decode_metadata(self, metadata):
            '''Recursively decode any bytestrings contained within various datastructs'''
            if isinstance(metadata, str):
                return metadata
            if isinstance(metadata, bytes):
                return metadata.decode('utf-8')
            if isinstance(metadata, list):
                return [(self._decode_metadata(m)) for m in metadata]
            if isinstance(metadata, dict):
                decoded = {}
                for k, v in metadata.items():
                    k = self._decode_metadata(k)
                    v = self._decode_metadata(v)
                    decoded[k] = v
                return decoded

        def get_management_chain(self, uid):
            '''Recursively get list of all LDAP uids in user's management heirachy'''
            user = self.get_user(uid)
            self.logger.debug(f"Checking for manager of {uid}")
            manager_uid = user.get_manager_uid()
            self.logger.debug(f"Manager UID: {manager_uid}")
            if manager_uid is not None and manager_uid != uid:
                mgmt_chain = self.get_management_chain(manager_uid)
                mgmt_chain.append(manager_uid)
                return mgmt_chain
            else:
                return []


    class LdapUserEntry(object):
        '''Represents LDAP metadata for a single user'''

        def __init__(self, uid, user_info):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.uid = uid
            self.user_info = user_info

        def __repr__(self):
            return str(json.dumps(self.user_info))

        def _parse_from_ldap_str(self, item, data):
            '''Extract a specific item from a domain name string (ex: cn=foo,dc=bar)'''
            split = data.split(",")
            for s in split:
                if s.startswith(item):
                    return s.split("=")[1]

        def get_manager_uid(self):
            '''Get the LDAP UID of this user's manager'''
            manager = self.user_info.get('manager', [])
            if len(manager) == 0:
                return None
            return self._parse_from_ldap_str("uid", manager[0])

        def get_groups(self):
            '''Aggregate a list of LDAP groups this user is a member of'''
            groups = self.user_info.get('memberOf', [])
            return [self._parse_from_ldap_str("cn", x) for x in groups]

        def get_projects(self):
            '''Aggregate a list of products, subproducts, projects and componets this user works on'''
            prod_list = self.user_info.get('rhatProduct', [])
            subproducts = self.user_info.get('rhatSubproduct', [])
            projects = self.user_info.get('rhatProject', [])
            components = self.user_info.get('rhatRnDComponent', [])
            prod_list.extend(subproducts)
            prod_list.extend(projects)
            prod_list.extend(components)
            return prod_list


    class TelemeterApprovalChecker(object):
        '''Interface to check if an ldap user is autoapproved to access telemetery data/dashboards'''

        def __init__(self, config):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.cfg = self._get_config(config)
            self.conn = LdapInterface(self.cfg.get('ldap_server', DEFAULT_LDAP_SERVER))
            self.preapprovals = self.cfg.get('preapprovals', {})
            self.preapproved_managers = self.preapprovals.get("managers", [])
            self.preapproved_groups = self.preapprovals.get("groups", [])
            self.preapproved_projects = self.preapprovals.get("projects", [])

        def _get_config(self, config_file):
            '''Load preapproval and ldap settings from config yaml'''
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)

        def check_approval(self, uid):
            '''Check if user is automatically approved for access to telemetry'''
            in_mgmt_chain = self.check_management_chain(uid, self.preapproved_managers)
            in_ldap_group = self.check_groups(uid, self.preapproved_groups)
            in_approved_project = self.check_project(uid, self.preapproved_projects)

            approved = any([in_mgmt_chain, in_ldap_group, in_approved_project])

            if in_ldap_group:
                self.logger.info(f"User '{uid}' already has access to telemetery!")
            elif approved:
                self.logger.info(f"User '{uid}' is auto-approved for, but hasn't yet been granted, telemetry access")
            else:
                self.logger.info(f"User '{uid}' is not automatically approved for telemetry access")
                self.logger.info("Please check Data Hub Onboarding documentation if further verification is required")
            return approved

        def check_management_chain(self, uid, approved_managers=[]):
            '''Check if user works (directly or indirectly) for a preapproved manager'''
            mgmt_chain = self.conn.get_management_chain(uid)
            for mgr in mgmt_chain:
                if mgr in approved_managers:
                    self.logger.debug(f"User '{uid}' is preapproved as they are a direct or indirect report of '{mgr}'")
                    return True
            self.logger.debug(f"The management heirarcy for user '{uid}' does not auto-approve them.")
            return False

        def check_groups(self, uid, approved_groups=[]):
            '''Check if user is a member on a preapproved group'''
            groups = self.conn.get_user(uid).get_groups()
            for g in groups:
                if g in approved_groups:
                    self.logger.debug(f"User '{uid}' belongs to a preapproved LDAP group: {g}")
                    return True
            self.logger.debug(f"User '{uid}' does not belong to any preapproved LDAP groups")
            return False

        def check_project(self, uid, approved_projects=[]):
            '''Check if user works on a preapproved project'''
            projects = self.conn.get_user(uid).get_projects()
            for p in projects:
                if p in approved_projects:
                    self.logger.debug(f"User '{uid}' works on a preapproved project: {p}")
                    return True
            self.logger.debug(f"User '{uid}' does not work on any preapproved projects")
            return False

    tac = TelemeterApprovalChecker(CONFIG_PATH)
    approved =  tac.check_project(username, tac.preapproved_projects)
    if approved:
        print("User works on a pre-approved project")
        print("APPROVED")
    else:
        print("User does not work on a pre-approved project")
        print("DEFER APPROVAL")
    return approved


def check_groups(username):
    CONFIG_PATH = "/opt/app-root/src/config/config.yaml"

    import argparse
    import logging
    import ldap
    import json
    import yaml
    import os


    DEFAULT_LDAP_SERVER = 'ldap://ldap.corp.redhat.com'
    DEFAULT_CONFIG = os.path.join(os.path.dirname(__file__), 'config.yaml')
    METADATA_FIELDS = ['memberOf', 'manager', 'rhatProduct', 'rhatSubproduct', 'rhatProject', 'rhatRnDComponent']


    class LdapInterface(object):
        '''Abstraction to handle interfacing with LDAP'''

        def __init__(self, uri):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.uri = uri
            self.conn = self.connect()

        def connect(self):
            '''Connect to LDAP server and initialize the interface'''
            conn = ldap.initialize(self.uri)
            return conn

        def get_user(self, user):
            '''Search LDAP server for a specific user and record their metadata'''
            res = self.conn.search_s('dc=redhat,dc=com',
                                     ldap.SCOPE_SUBTREE,
                                     f"uid={user}",
                                     METADATA_FIELDS)
            if len(res) > 1:
                self.logger.warning("More than 1 user with uid found. using first result")
            uid, metadata = res[0]
            metadata = self._decode_metadata(metadata)
            return LdapUserEntry(user, metadata)

        def _decode_metadata(self, metadata):
            '''Recursively decode any bytestrings contained within various datastructs'''
            if isinstance(metadata, str):
                return metadata
            if isinstance(metadata, bytes):
                return metadata.decode('utf-8')
            if isinstance(metadata, list):
                return [(self._decode_metadata(m)) for m in metadata]
            if isinstance(metadata, dict):
                decoded = {}
                for k, v in metadata.items():
                    k = self._decode_metadata(k)
                    v = self._decode_metadata(v)
                    decoded[k] = v
                return decoded

        def get_management_chain(self, uid):
            '''Recursively get list of all LDAP uids in user's management heirachy'''
            user = self.get_user(uid)
            self.logger.debug(f"Checking for manager of {uid}")
            manager_uid = user.get_manager_uid()
            self.logger.debug(f"Manager UID: {manager_uid}")
            if manager_uid is not None and manager_uid != uid:
                mgmt_chain = self.get_management_chain(manager_uid)
                mgmt_chain.append(manager_uid)
                return mgmt_chain
            else:
                return []


    class LdapUserEntry(object):
        '''Represents LDAP metadata for a single user'''

        def __init__(self, uid, user_info):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.uid = uid
            self.user_info = user_info

        def __repr__(self):
            return str(json.dumps(self.user_info))

        def _parse_from_ldap_str(self, item, data):
            '''Extract a specific item from a domain name string (ex: cn=foo,dc=bar)'''
            split = data.split(",")
            for s in split:
                if s.startswith(item):
                    return s.split("=")[1]

        def get_manager_uid(self):
            '''Get the LDAP UID of this user's manager'''
            manager = self.user_info.get('manager', [])
            if len(manager) == 0:
                return None
            return self._parse_from_ldap_str("uid", manager[0])

        def get_groups(self):
            '''Aggregate a list of LDAP groups this user is a member of'''
            groups = self.user_info.get('memberOf', [])
            return [self._parse_from_ldap_str("cn", x) for x in groups]

        def get_projects(self):
            '''Aggregate a list of products, subproducts, projects and componets this user works on'''
            prod_list = self.user_info.get('rhatProduct', [])
            subproducts = self.user_info.get('rhatSubproduct', [])
            projects = self.user_info.get('rhatProject', [])
            components = self.user_info.get('rhatRnDComponent', [])
            prod_list.extend(subproducts)
            prod_list.extend(projects)
            prod_list.extend(components)
            return prod_list


    class TelemeterApprovalChecker(object):
        '''Interface to check if an ldap user is autoapproved to access telemetery data/dashboards'''

        def __init__(self, config):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.cfg = self._get_config(config)
            self.conn = LdapInterface(self.cfg.get('ldap_server', DEFAULT_LDAP_SERVER))
            self.preapprovals = self.cfg.get('preapprovals', {})
            self.preapproved_managers = self.preapprovals.get("managers", [])
            self.preapproved_groups = self.preapprovals.get("groups", [])
            self.preapproved_projects = self.preapprovals.get("projects", [])

        def _get_config(self, config_file):
            '''Load preapproval and ldap settings from config yaml'''
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)

        def check_approval(self, uid):
            '''Check if user is automatically approved for access to telemetry'''
            in_mgmt_chain = self.check_management_chain(uid, self.preapproved_managers)
            in_ldap_group = self.check_groups(uid, self.preapproved_groups)
            in_approved_project = self.check_project(uid, self.preapproved_projects)

            approved = any([in_mgmt_chain, in_ldap_group, in_approved_project])

            if in_ldap_group:
                self.logger.info(f"User '{uid}' already has access to telemetery!")
            elif approved:
                self.logger.info(f"User '{uid}' is auto-approved for, but hasn't yet been granted, telemetry access")
            else:
                self.logger.info(f"User '{uid}' is not automatically approved for telemetry access")
                self.logger.info("Please check Data Hub Onboarding documentation if further verification is required")
            return approved

        def check_management_chain(self, uid, approved_managers=[]):
            '''Check if user works (directly or indirectly) for a preapproved manager'''
            mgmt_chain = self.conn.get_management_chain(uid)
            for mgr in mgmt_chain:
                if mgr in approved_managers:
                    self.logger.debug(f"User '{uid}' is preapproved as they are a direct or indirect report of '{mgr}'")
                    return True
            self.logger.debug(f"The management heirarcy for user '{uid}' does not auto-approve them.")
            return False

        def check_groups(self, uid, approved_groups=[]):
            '''Check if user is a member on a preapproved group'''
            groups = self.conn.get_user(uid).get_groups()
            for g in groups:
                if g in approved_groups:
                    self.logger.debug(f"User '{uid}' belongs to a preapproved LDAP group: {g}")
                    return True
            self.logger.debug(f"User '{uid}' does not belong to any preapproved LDAP groups")
            return False

        def check_project(self, uid, approved_projects=[]):
            '''Check if user works on a preapproved project'''
            projects = self.conn.get_user(uid).get_projects()
            for p in projects:
                if p in approved_projects:
                    self.logger.debug(f"User '{uid}' works on a preapproved project: {p}")
                    return True
            self.logger.debug(f"User '{uid}' does not work on any preapproved projects")
            return False

    tac = TelemeterApprovalChecker(CONFIG_PATH)
    approved = tac.check_groups(username, tac.preapproved_groups)
    if approved:
        print("User already belongs to a pre-approved LDAP group")
        print("APPROVED")
    else:
        print("User does not already belong to a pre-approved LDAP group")
        print("DEFER APPROVAL")
    return approved


def handle_result(result):
    print(result)  # TODO: send an email or something instead, i dunno


mgmt_check_op = components.create_component_from_func(
    check_management_chain, base_image=BASE_IMAGE)
proj_check_op = components.create_component_from_func(
    check_projects, base_image=BASE_IMAGE)
group_check_op = components.create_component_from_func(
    check_groups, base_image=BASE_IMAGE)
result_op = components.create_component_from_func(
    handle_result, base_image=NOTIFY_IMAGE)


@dsl.pipeline(
    name='data-hub-telemetry-pre-approval-check-pipeline',
    description='Checks if a user is pre-approved to access telemetry dashboards and data hosted by Data Hub'
)
def custom_task_pipeline():
    username = "gfrasca"  # TODO: figure out how to dynamically get this as a param
    mgmt_check = mgmt_check_op(username)
    proj_check = proj_check_op(username)
    group_check = group_check_op(username)

    config_vol = V1Volume(name="telemetry-access-config",
                          config_map=V1ConfigMapVolumeSource(name="telemetry-access-config"))
    config_mnt = V1VolumeMount(mount_path='/opt/app-root/src/config',
                               name='telemetry-access-config')

    for step in [mgmt_check, proj_check, group_check]:
        step.add_volume(config_vol)
        step.container.add_volume_mount(config_mnt)

    if any([mgmt_check.output, proj_check.output, group_check.output]):
        result_op(f"User {username} is Approved!")
    else:
        result_op(f"User {username} is Not Approved!")

    # with dsl.Condition(any([mgmt_check.output, proj_check.output, group_check.output]) == True):
    #     result_op(f"User {username} is Approved!")
    #
    # with dsl.Condition(any([mgmt_check.output, proj_check.output, group_check.output]) is False):
    #     result_op(f"User {username} is Not Approved!")


if __name__ == '__main__':
    from kfp_tekton.compiler import TektonCompiler
    TektonCompiler().compile(custom_task_pipeline, __file__.replace('.py', '.yaml'))
