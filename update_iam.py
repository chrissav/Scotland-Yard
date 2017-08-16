#!/usr/bin/env python

"""

This has 3 major functions:

1) Import/Export Resources from file system and AWS IAM
2) Compare the found resources
3) Update the resources in AWS IAM with the file system as
   the source of truth

I use these words a lot:

entity: this is the type of item found in AWS IAM
        ex. Group, Role, User, Policy
resource: this is the actual item name of the entity
        ex. Example-Group, Example-Role, Alice, Bob, etc.


# Written by @chrissav or http://github.com/chrissav

"""

import argparse
import os
import uritools
import boto
import time
import shutil
from IamResources import IamResources
from blessings import Terminal

t = Terminal()
iam = boto.connect_iam()


"""

Import Functions


"""

def _paginate(func, attr, *args):
  """Paginates a boto response if it's truncated"""
  finished, marker = False, None
  while not finished:
      res = func(*args, marker=marker)
      for item in getattr(res, attr):
          yield item

      finished = res.is_truncated == 'false'
      if not finished:
          marker = res.marker


def list_all_groups_in_iam():
  """Return a list of all groups found in IAM"""
  return [item['group_name'] for item in
    _paginate(iam.get_all_groups, 'groups')]


def list_all_roles_in_iam():
  """Returns a list of all roles and it's trust policy found in IAM."""
  return [[item['role_name'], item['assume_role_policy_document']]
    for item in _paginate(iam.list_roles, 'roles')]


def list_all_instance_profiles_in_iam():
  """Returns a list of all instance profiles found in IAM"""
  return [item['instance_profile_name'] for item in
    _paginate(iam.list_instance_profiles, 'instance_profiles')]


def list_all_users_in_iam():
  """Returns a list of all users found in IAM"""
  return [item['user_name'] for item in _paginate(iam.get_all_users, 'users')]


def list_all_managed_policies_in_iam():
  """Returns a list of all managed policies found in IAM"""
  return [item for item in _paginate(iam.list_policies, 'policies')]

def list_policy_versions(arn):
  """Returns a list of all versions of a managed policy in IAM"""
  return [item['version_id'] for item in
    _paginate(iam.list_policy_versions, 'versions', arn)]


def read_and_strip_file(path):
  string = ""
  with open(path) as f:
    for line in f:
      string += line.strip()
  return "".join(string.split())


def read_and_add_policies_from_file(path, entity, file_data):
  """Imports policies into IamResource object."""
  name = path.split('/')[-1]
  file_data.add_entity(entity, name)

  root, dirs, files = os.walk(path).next()
  for file in files:
    if file.endswith('.json'):
      file_data.add_policy_to_entity(entity, name,
        file.rsplit('.', 1)[0], open(os.path.join(root, file)).read())
    if os.path.exists(os.path.join(path, 'managed_policies.txt')):
      with open(os.path.join(path, 'managed_policies.txt')) as f:
        for policy in f:
          file_data.add_managed_policy_to_entity(
              entity, name, policy.rstrip())


def import_groups_from_file(path, file_data):
  """Finds all groups to import from file."""
  read_and_add_policies_from_file(path, 'groups', file_data)

  group_name = path.split('/')[-1]
  if os.path.exists(os.path.join(path, 'users.txt')):
    with open(os.path.join(path, 'users.txt')) as user_file:
      for user in user_file:
        file_data.add_user_to_group(group_name, user.rstrip())


def import_roles_from_file(path, file_data):
  """Finds all roles to import from file."""
  read_and_add_policies_from_file(path, 'roles', file_data)

  role_name = path.split('/')[-1]
  try:
    file_data.add_role_trust_policy(
        role_name, read_and_strip_file("%s/trust/trust.json" % path))
  except:
    print t.red("No trust policy found for %s" % role_name)


def import_profiles_from_file(path, file_data):
  """Finds all profiles to import from file."""
  read_and_add_policies_from_file(path, 'profiles', file_data)

  profile_name = path.split('/')[-1]
  try:
    file_data.add_profile_trust_policy(
        profile_name, read_and_strip_file("%s/trust/trust.json" % path))
  except:
    print t.red("No trust policy found for %s" % profile_name)


def import_managed_policies_from_file(path, file_data):
  """Imports managed policy from file to IamResource object."""
  name = path.split('/')[-1]
  arn = open("%s/attributes.txt" % path).readline().rstrip().split('=')[-1]
  if name != arn.split('/')[-1]:
    print (t.yellow(
        'Warning: Incorrect arn found in attributes.txt for %s' % name))
  read_only = [False, True]['arn:aws:iam::aws:policy' in arn]
  file_data.add_managed_policy(name.rsplit('.', 1)[0],
                               open("%s/policy.json" % path).read(),
                               arn,
                               read_only
                               )

def import_users_from_file(path, file_data):
  """Imports users from file to IamResources object."""
  read_and_add_policies_from_file(path, 'users', file_data)


def import_from_files(root='./resources'):
  """Imports resources from file and returns an IamResource object."""
  print "\nGetting IAM data from files..."
  file_data = IamResources()

  function = {"groups": import_groups_from_file,
              "roles": import_roles_from_file,
              "profiles": import_profiles_from_file,
              "managed_policies": import_managed_policies_from_file,
              "users": import_users_from_file
              }

  for item in os.listdir(root):
    for resource in os.listdir(os.path.join(root, item)):
      if "_%s" % item in resource:
        for inner_resource in os.listdir(os.path.join(root, item, resource)):
          function[item](os.path.join(
              root, item, resource, inner_resource), file_data)
      else:
        function[item](os.path.join(root, item, resource), file_data)

  print "Finished getting data from files!"
  return file_data


def import_from_iam():
  """Imports resources from AWS IAM and returns an IamResource object."""
  print "\nGetting IAM data from AWS..."
  iam_data = IamResources()

  # import group data
  for group in list_all_groups_in_iam():
    iam_data.add_group(group)
    policies = (iam.get_all_group_policies(group)
               ['list_group_policies_response']
               ['list_group_policies_result']
               ['policy_names'])
    for policy in policies:
      iam_data.add_policy_to_entity('groups',
          group, policy, uritools.uridecode
          (iam.get_group_policy(group, policy)
          ['get_group_policy_response']
          ['get_group_policy_result']
          ['policy_document']))
    users = (iam.get_group(group)
            ['get_group_response']
            ['get_group_result']
            ['users'])
    for user in users:
      iam_data.add_user_to_group(group, user['user_name'])

  # import roles and profiles data
  profiles = list_all_instance_profiles_in_iam()
  for role, trust in list_all_roles_in_iam():
    policies = (iam.list_role_policies(role)
               ['list_role_policies_response']
               ['list_role_policies_result']
               ['policy_names'])
    if role in profiles:
      iam_data.add_profile(role)
      iam_data.add_profile_trust_policy(role, uritools.uridecode(trust))
      for policy in policies:
        iam_data.add_policy_to_entity('profiles',
            role, policy, uritools.uridecode
            (iam.get_role_policy(role, policy)
            ['get_role_policy_response']
            ['get_role_policy_result']
            ['policy_document']))
    else:
      iam_data.add_role(role)
      iam_data.add_role_trust_policy(role, uritools.uridecode(trust))
      for policy in policies:
        iam_data.add_policy_to_entity('roles',
            role, policy, uritools.uridecode
            (iam.get_role_policy(role, policy)
            ['get_role_policy_response']
            ['get_role_policy_result']
            ['policy_document']))

  # import user data
  for user in list_all_users_in_iam():
    iam_data.add_user(user)
    policies = (iam.get_all_user_policies(user)
               ['list_user_policies_response']
               ['list_user_policies_result']
               ['policy_names'])
    for policy in policies:
      iam_data.add_policy_to_entity('users',
          user, policy, uritools.uridecode
          (iam.get_user_policy(user, policy)
          ['get_user_policy_response']
          ['get_user_policy_result']
          ['policy_document']))

  # import managed policies
  for managed_policy in list_all_managed_policies_in_iam():
    policy_document = (uritools.uridecode
        (iam.get_policy_version(
            managed_policy['arn'],
            managed_policy['default_version_id'])
            ['get_policy_version_response']
            ['get_policy_version_result']
            ['policy_version']
            ['document']))
    read_only = [False, True]['arn:aws:iam::aws:policy' in managed_policy['arn']]

    iam_data.add_managed_policy(managed_policy['policy_name'],
                                policy_document,
                                managed_policy['arn'],
                                read_only)
    if managed_policy['attachment_count'] != '0':
      entities = (retry(iam.list_entities_for_policy, managed_policy['arn'])
                     ['list_entities_for_policy_response']
                     ['list_entities_for_policy_result'])
      for resource in ['groups', 'roles', 'users']:
        items = getattr(entities, "policy_%s" % resource)
        if items:
          for names in items:
            name = getattr(names, "%s_name" % resource[:-1])
            if resource == 'roles':
              r = ['roles', 'profiles'][name in profiles]
            else:
              r = resource
            iam_data.add_managed_policy_to_entity(
                r, name, managed_policy['policy_name'])

  print "Finished getting data from AWS!"
  return iam_data

"""

Export Functions


"""

def export_to_file(iam_data):
  """Exports IamResources object to file system. Run with --export"""
  rootdir = "iam-policies-%s" % time.strftime("%m-%d-%Y")
  print "\nExporting IAM data from AWS to '%s'..." % rootdir

  if os.path.exists(rootdir):
    shutil.rmtree(rootdir)
  os.makedirs(rootdir)

  # export groups
  for group in iam_data.groups.keys():
    directory = "%s/groups/%s" % (rootdir, group)
    os.makedirs(directory)

    for policy in iam_data.groups[group]['managed_policies']:
      with open("%s/managed_policies.txt" % (directory), 'a+') as file:
        file.write(policy + '\n')

    policies = iam_data.groups[group]['policies']
    for policy in policies:
      file = open("%s/%s.json" % (directory, policy), 'w+')
      file.write(policies.get(policy))
      file.close()

    user_file = open("%s/users.txt" % directory, 'w+')
    for user in iam_data.groups[group]['users']:
      user_file.write("%s\n" % user)
    user_file.close()

  # export profiles
  for profile in iam_data.profiles.keys():
    directory = "%s/profiles/%s" % (rootdir, profile)
    os.makedirs(directory)
    os.makedirs("%s/trust" % directory)

    with open("%s/trust/trust.json" % directory, 'w+') as file:
      file.write(iam_data.profiles[profile]['trust'])

    for policy in iam_data.profiles[profile]['managed_policies']:
      with open("%s/managed_policies.txt" % (directory), 'a+') as file:
        file.write(policy + '\n')

    policies = iam_data.profiles[profile]['policies']
    for policy in policies:
      file = open("%s/%s.json" % (directory, policy), 'w+')
      file.write(policies.get(policy))
      file.close()

  # export roles
  for role in iam_data.roles.keys():
    if 'kms' in role.lower():
      directory = "%s/roles/KMS_roles/%s" % (rootdir, role)
    else:
      directory = "%s/roles/%s" % (rootdir, role)
    os.makedirs(directory)

    os.makedirs("%s/trust" % directory)
    with open("%s/trust/trust.json" % directory, 'w+') as file:
      file.write(iam_data.roles[role]['trust'])

    for policy in iam_data.roles[role]['managed_policies']:
      with open("%s/managed_policies.txt" % (directory), 'a+') as file:
        file.write(policy + '\n')

    policies = iam_data.roles[role]['policies']
    for policy in policies:
      file = open("%s/%s.json" % (directory, policy), 'w+')
      file.write(policies.get(policy))
      file.close()

  # export users
  for user in iam_data.users.keys():
    directory = "%s/users/%s" % (rootdir, user)
    os.makedirs(directory)

    for policy in iam_data.users[user]['managed_policies']:
      with open("%s/managed_policies.txt" % (directory), 'a+') as file:
        file.write(policy + '\n')

    policies = iam_data.users[user]['policies']
    if policies:
      for policy in policies:
        with open("%s/%s.json" % (directory, policy), 'w+') as file:
          file.write(policies.get(policy))
    else:
      # create a file, git will not commit an empty directory
      open("%s/.gitkeep" % directory, 'a').close()

  # export managed policies
  for managed_policy in iam_data.managed_policies.keys():
    directory = "%s/managed_policies/%s" % (rootdir, managed_policy)
    os.makedirs(directory)
    with open("%s/policy.json" % directory, 'w+') as file:
      file.write(iam_data.managed_policies[managed_policy]['policy'])
    with open("%s/attributes.txt" % directory, 'w+') as file:
      file.write("arn=%s\n" % iam_data.managed_policies[managed_policy]['arn'])
      file.write("read_only=%s" % iam_data.managed_policies[managed_policy]['read_only'])

  print "Finished writing data to file!"


"""

Update Functions


"""

def create_resource(entity, resource_name, *args):
  """Calls iam.create_* function for whichever item is passed."""
  create = {"groups": iam.create_group,
            "roles": iam.create_role,
            "profiles": create_instance_profile,
            "managed_policies": create_managed_policy,
            "users": skip_function
            }
  try:
    create[entity](resource_name, *args)
    if entity != 'users':
      print t.green("Success: Created %s: %s" % (entity, resource_name))
  except Exception, e:
    if e.status == 409:
      pass
    else:
      print t.red("Failure: Creating %s:%s" % (resource_name, e.message))


def delete_resource(entity, resource_name):
  """Calls iam.delete_* function for whichever item is passed."""
  delete = {"groups": iam.delete_group,
            "roles": iam.delete_role,
            "profiles": iam.delete_role,
            "users": skip_function,
            "managed_policies": delete_managed_policy
            }
  try:
    delete[entity](resource_name)
    if entity != 'users':
      print t.yellow("Warning: Deleted %s: %s" % (entity, resource_name))
  except Exception, e:
    if e.status == 409:
      pass
    else:
      print t.red("Failure: Deleting %s:%s" % (resource_name, e.message))


def add_policy(entity, resource_name, policy_name, policy_document):
  """Adds policies to a group or role."""
  add = {"groups": iam.put_group_policy,
         "roles": iam.put_role_policy,
         "users": iam.put_user_policy,
         "profiles": iam.put_role_policy
         }

  try:
    add[entity](resource_name, policy_name, policy_document)
    print t.green("Success: Added %s to %s" % (policy_name, resource_name))
  except Exception, e:
    print t.red("Failure: Adding %s policy to %s:%s" % (policy_name, resource_name, e.message))


def remove_policy(entity, resource_name, policy_name):
  """Removes policies from a group or role."""
  remove = {"groups": iam.delete_group_policy,
            "roles": iam.delete_role_policy,
            "users": iam.delete_user_policy,
            "profiles": iam.delete_role_policy
            }
  try:
    remove[entity](resource_name, policy_name)
    print t.yellow("Warning: Removed %s from %s"
      % (policy_name, resource_name))
  except Exception, e:
    print t.red("Failure: Removing %s policy from %s:%s" % (policy_name, resource_name, e.message))


def attach_policy(entity, resource_name, policy_name):
  """Attaches managed policies to a group or role."""
  attach = {"groups": iam.attach_group_policy,
            "roles": iam.attach_role_policy,
            "users": iam.attach_user_policy,
            "profiles": iam.attach_role_policy
            }

  for policy in list_all_managed_policies_in_iam():
    if policy['policy_name'] == policy_name:
      arn = policy['arn']

  try:
    attach[entity](arn, resource_name)
    print t.green("Success: Attached %s to %s" % (arn, resource_name))
  except Exception, e:
    print t.red("Failure: Attaching %s policy to %s:%s" % (policy_name, resource_name, e.message))


def detach_policy(entity, resource_name, policy_name):
  """Detaches a managed policy from a resource."""
  detach = {"groups": iam.detach_group_policy,
            "roles": iam.detach_role_policy,
            "users": iam.detach_user_policy,
            "profiles": iam.detach_role_policy
            }

  for policy in list_all_managed_policies_in_iam():
    if policy['policy_name'] == policy_name:
      arn = policy['arn']

  try:
    detach[entity](arn, resource_name)
    print t.yellow("Warning: Detached %s from %s" % (arn, resource_name))
  except Exception, e:
    print t.red("Failure: Detaching %s policy from %s:%s" % (policy_name, resource_name, e.message))


def delete_policy_version(policy_arn, version):
  """Deletes a given managed policy version."""
  try:
    iam.delete_policy_version(policy_arn, version)
    print t.yellow("Warning: Deleted %s %s" % (policy_arn, version))
  except Exception, e:
    print t.red("Failure: Deleting %s:%s" % (policy_arn, e.message))


def delete_managed_policy(policy_name):
  """Deletes a given managed policy."""
  for policy in list_all_managed_policies_in_iam():
    if policy['policy_name'] == policy_name:
      arn = policy['arn']

  for version in list_policy_versions(arn):
    if (iam.get_policy_version(arn, version)
        ['get_policy_version_response']
        ['get_policy_version_result']
        ['policy_version']
        ['is_default_version'] == 'false'):
          delete_policy_version(arn, version)

  try:
    iam.delete_policy(arn)
    print t.yellow("Warning: Deleted %s" % arn)
  except Exception, e:
    print t.red("Failure: Deleting managed policy %s:%s" % (arn, e.message))


def create_managed_policy(policy_name, policy_document):
  """Creates a given managed policy."""
  try:
    iam.create_policy(policy_name, policy_document)
    print t.green("Success: Created %s" % policy_name)
  except Exception, e:
    print t.red("Failure: Creating managed policy %s:%s" % (policy_name, e.message))


def update_managed_policy(policy_arn, policy_document):
  """Updates a given managed policy."""
  try:
    iam.create_policy_version(policy_arn, policy_document, set_as_default=True)
    print t.green("Success: Updated %s" % policy_arn)
  except Exception, e:
    print t.red("Failure: Updating %s:%s" % (policy_arn, e.message))


def add_user_to_group(group, user):
  """Adds user to group."""
  try:
    iam.add_user_to_group(group, user.rstrip())
    t.green("Success: Added %s to %s" % (user, group))
  except Exception, e:
    print t.red("Failure: Adding %s to %s:%s" % (user, group, e.message))


def remove_user_from_group(group, user):
  """Removes user from group."""
  try:
    iam.remove_user_from_group(group, user.rstrip())
    t.yellow("Warning: Removed %s from %s" % (user, group))
  except Exception, e:
    print t.red("Failure: Removing %s from %s:%s" % (user, group, e.message))


def update_trust_policy(role, trust_policy):
  """Updates the trust policy for a group or role."""
  try:
    iam.update_assume_role_policy(role, trust_policy)
    print t.green("Success: Updated trust policy for %s" % role)
  except Exception, e:
    print t.red("Failure: Updating %s:trust policy - %s" % (role, e.message))


def create_instance_profile(profile):
  """Creates and attaches an instance profile to a role."""
  try:
    iam.create_role(profile)
    iam.create_instance_profile(profile)
    iam.add_role_to_instance_profile(profile, profile)
    print t.green("Success: Created and attached Instance Profile: %s"
                  % profile)
  except Exception, e:
    if e.status == 409:
      pass
    else:
      print t.red("Failure: Creating instance profile %s:%s" % (profile, e.message))


def delete_instance_profile(profile):
  """Deletes an instance profile."""
  try:
    iam.remove_role_from_instance_profile(profile, profile)
    iam.delete_instance_profile(profile)
    print t.yellow("Warning: Deleted Instance Profile: %s"
                  % profile)
  except Exception, e:
    if e.status == 409:
      pass
    else:
      print t.red("Failure: Deleting instance profile %s:%s" % (profile, e.message))


def purge_resource(entity, resource_name, iam_data):
  """Removes all items associated with a resource."""
  if entity != 'managed_policies':
    for policy in iam_data.__dict__.get(entity)[resource_name]['policies']:
      remove_policy(entity, resource_name, policy)
    for managed_policy in iam_data.__dict__.get(entity)[resource_name]['managed_policies']:
      detach_policy(entity, resource_name, managed_policy)

  if entity == 'groups':
    for user in iam_data.__dict__.get(entity)[resource_name]['users']:
      remove_user_from_group(resource_name, user)

  if entity == 'profiles':
    delete_instance_profile(resource_name)


def skip_function(*args):
  print t.yellow("Skipping: %s. You must do this manually." % " ".join(args))


def update(results):
  for result in results:
    if dryrun:
      print t.green("Dryrun: %s") % result
    else:
      # the first item in result is the func name
      # pass the rest of result list items to the func
      globals()[result[0]](*result[1:])

"""

Compare Functions


"""

def find_complement(a, b):
  return list(set(a) - set(b))


def compare(iam_data, file_data):
  """Compares two IamResource objects and updates IAM based on changes."""
  print "\nComparing IAM data..."

  results = []

  compare = {"groups": compare_group,
             "roles": compare_role,
             "profiles": compare_profile,
             "users": compare_user,
             "managed_policies": compare_managed_policy
             }

  # check if entire entity is the same
  for entity in file_data.__dict__.keys():
    if (file_data.__dict__.get(entity) !=
            iam_data.__dict__.get(entity)):

      # will add/remove entire group/role/user
      add_differences = find_complement(file_data.__dict__.get(entity).keys(),
                                        iam_data.__dict__.get(entity).keys())
      for found in add_differences:
        print "%s: %s" % (entity, found)
        if entity == 'managed_policies':
          policy_document = file_data.managed_policies[found]['policy']
          results.append(['create_resource', entity, found, policy_document])
        else:
          results.append(['create_resource', entity, found])
          results = compare[entity](found, iam_data, file_data, results)

      remove_differences = find_complement(
          iam_data.__dict__.get(entity).keys(),
          file_data.__dict__.get(entity).keys())
      for found in remove_differences:
        results.append(['purge_resource', entity, found, iam_data])
        results.append(['delete_resource', entity, found])

      # search through remaining resources
      for resource in file_data.__dict__.get(entity).keys():
        if (resource not in add_differences and
          (file_data.__dict__.get(entity)[resource] !=
          iam_data.__dict__.get(entity)[resource])):
          results = compare[entity](resource, iam_data, file_data, results)

  print "\nFinished finding changes!"
  return results


def compare_policies(iam_data, file_data, entity, resource_name, results):
  """Compares policies from two IamResource objects and updates IAM."""

  # find policies to remove
  if resource_name in iam_data.__dict__.get(entity).keys():
    for policy in (find_complement
        (iam_data.__dict__.get(entity)[resource_name]['policies'],
         file_data.__dict__.get(entity)[resource_name]['policies'])):
      results.append(['remove_policy', entity, resource_name, policy])

    # compare remaining policies
    for policy in file_data.__dict__.get(entity)[resource_name]['policies']:
      # check if it's not in iam data to prevent dict key error
      if policy not in iam_data.__dict__.get(entity)[resource_name]['policies']:
        results.append(['add_policy', entity, resource_name, policy,
                file_data.__dict__.get(entity)[resource_name]['policies'][policy]])
      elif (file_data.__dict__.get(entity)[resource_name]['policies'][policy] !=
        iam_data.__dict__.get(entity)[resource_name]['policies'][policy]):
          results.append(['add_policy', entity, resource_name, policy,
                  file_data.__dict__.get(entity)[resource_name]['policies'][policy]])

  else:
    for policy in file_data.__dict__.get(entity)[resource_name]['policies']:
      results.append(['add_policy', entity, resource_name, policy,
                  file_data.__dict__.get(entity)[resource_name]['policies'][policy]])

  return results


def compare_entity_managed_policy_list(entity, resource_name, iam_data, file_data, results):
  """Compares managed policies and attaches or detaches from resource."""
  if resource_name in iam_data.__dict__.get(entity).keys():
    for policy in find_complement(file_data.__dict__.get(entity)
                                  [resource_name]['managed_policies'],
                                  iam_data.__dict__.get(entity)
                                  [resource_name]['managed_policies']):
        results.append(['attach_policy', entity, resource_name, policy])

    for policy in find_complement(iam_data.__dict__.get(entity)
                                  [resource_name]['managed_policies'],
                                  file_data.__dict__.get(entity)
                                  [resource_name]['managed_policies']):
        results.append(['detach_policy', entity, resource_name, policy])
  else:
    for policy in (file_data.__dict__.get(entity)
      [resource_name]['managed_policies']):
        results.append(['attach_policy', entity, resource_name, policy])

  return results


def compare_trust_policy(iam_data, file_data, entity, resource_name, results):
  """Compares trust policy and updates if needed."""
  if resource_name in iam_data.__dict__.get(entity).keys():
    a = file_data.__dict__.get(entity)[resource_name]['trust']
    b = iam_data.__dict__.get(entity)[resource_name]['trust']
    sorted_a = sorted(a)
    sorted_b = sorted(b)
    if (sorted_a != sorted_b):
      results.append(['update_trust_policy', resource_name, file_data.__dict__.get(entity)[resource_name]['trust']])
  else:
    results.append(['update_trust_policy', resource_name, file_data.__dict__.get(entity)[resource_name]['trust']])
  return results


def compare_managed_policy(managed_policy, iam_data, file_data, results):
  """Compares managed policies and updates if needed."""
  if managed_policy in iam_data.managed_policies.keys():
    if (file_data.managed_policies[managed_policy]['policy'] !=
      iam_data.managed_policies[managed_policy]['policy']):
        if file_data.managed_policies[managed_policy]['read_only']:
          print t.yellow("Warning: You cannot update the readonly policy %s" % managed_policy)
        else:
          results.append(['update_managed_policy',
                         file_data.managed_policies[managed_policy]['arn'],
                         file_data.managed_policies[managed_policy]['policy']])
  else:
    results.append(['update_managed_policy',
                   file_data.managed_policies[managed_policy]['arn'],
                   file_data.managed_policies[managed_policy]['policy']])
  return results


def compare_group(group, iam_data, file_data, results):
  """Compares a group and adds/removes users and updates policies."""
  results = compare_policies(iam_data, file_data, 'groups', group, results)

  if group in iam_data.groups.keys():
    for user in find_complement(file_data.groups[group]['users'],
                                iam_data.groups[group]['users']):
        results.append(['add_user_to_group', group, user])
    for user in find_complement(iam_data.groups[group]['users'],
                                file_data.groups[group]['users']):
        results.append(['remove_user_from_group', group, user])
  else:
    for user in file_data.groups[group]['users']:
      results.append(['add_user_to_group', group, user])

  results = compare_entity_managed_policy_list('groups', group, iam_data, file_data, results)

  return results


def compare_role(role, iam_data, file_data, results):
  """Compares a role and updates policies."""
  results = compare_policies(iam_data, file_data, 'roles', role, results)
  results = compare_trust_policy(iam_data, file_data, 'roles', role, results)
  results = compare_entity_managed_policy_list('roles', role, iam_data, file_data, results)

  return results


def compare_profile(profile, iam_data, file_data, results):
  """Compares a profile and updated policies."""
  results = compare_policies(iam_data, file_data, 'profiles', profile, results)
  results = compare_trust_policy(iam_data, file_data, 'profiles', profile, results)
  results = compare_entity_managed_policy_list('profiles', profile, iam_data, file_data, results)

  return results


def compare_user(user, iam_data, file_data, results):
  """Compares a user and updates policies."""
  results = compare_policies(iam_data, file_data, 'users', user, results)
  results = compare_entity_managed_policy_list('users', user, iam_data, file_data, results)

  return results

def retry(aws_function, *args):
    tries = 0
    while tries < 5:
        sleep_time = 10
        try:
            return aws_function(*args)
        except boto.exception.BotoServerError as error:
            print("Getting error %s \n" % error)
            print("Getting throttled. Sleeping for %s secs." % sleep_time)
            time.sleep(10)
            sleep_time = sleep_time*2
            tries += 1

def main():
  parser = argparse.ArgumentParser(description='Updates IAM resources')
  parser.add_argument('--dryrun',
    help="Pass this flag to see what would be updated.",
    action='store_true')
  parser.add_argument('--export',
    help="Pass this flag to export all IAM data from AWS.",
    action='store_true')

  args = parser.parse_args()
  global dryrun
  dryrun = args.dryrun

  if args.export:
    export_to_file(import_from_iam())
  else:
    file_data = import_from_files()
    iam_data = import_from_iam()
    results = compare(iam_data, file_data)
    update(results)


if __name__ == "__main__":
    main()
