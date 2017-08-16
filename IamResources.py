#!/usr/bin/env python

class IamResources:

  def __init__(self):
        self.groups = {}
        self.roles = {}
        self.profiles = {}
        self.users = {}
        self.managed_policies = {}
        self.data = {}

  def add_group(self, name):
    self.groups[str(name)] = {'policies': {}, 'users': set(), 'managed_policies': set()}

  def add_user_to_group(self, group_name, user_name):
    self.groups[group_name]['users'].add(user_name)

  def add_role(self, name):
    self.roles[str(name)] = {'policies': {}, 'trust': "", 'managed_policies': set()}

  def add_role_trust_policy(self, role_name, policy_document):
    self.roles[role_name]['trust'] = str(policy_document).rstrip()

  def add_profile(self, name):
    self.profiles[str(name)] = {'policies': {}, 'trust': "", 'managed_policies': set()}

  def add_profile_trust_policy(self, profile_name, policy_document):
    self.profiles[profile_name]['trust'] = str(policy_document).rstrip()

  def add_user(self, name):
    self.users[name] = {'policies': {}, 'managed_policies': set()}

  def add_managed_policy(self, name, policy_document, arn, read_only):
    self.managed_policies[str(name)] = {'policy': str(policy_document).rstrip(), 'arn': str(arn), 'read_only': bool(read_only)}

  def add_managed_policy_to_entity(self, entity, entity_name, policy_name):
    entities = {"groups": self.groups,
                "roles": self.roles,
                "profiles": self.profiles,
                "users": self.users
                }

    entities[entity][entity_name]['managed_policies'].add(str(policy_name))

  def add_policy_to_entity(self, entity, entity_name, policy_name, policy_document):
    entities = {"groups": self.groups,
                "roles": self.roles,
                "profiles": self.profiles,
                "users": self.users
                }

    entities[entity][entity_name]['policies'].update({str(policy_name): str(policy_document).rstrip()})

  def add_entity(self, entity, entity_name):
    entities = {"groups": self.add_group,
                "roles": self.add_role,
                "profiles": self.add_profile,
                "users": self.add_user
                }

    entities[entity](entity_name)
