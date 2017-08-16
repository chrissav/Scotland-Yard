# Scotland-Yard
Manage IAM resources

This will manage all resources in AWS IAM.  It'll add/delete/update anything so that everything defined here is present in IAM.

Setup
-----

#### You must have the requirements installed ####

```sh
$ pip install -r requirements.txt
```

Adding a New Resource (Group, Role, Profile, User)
------------------

All resources are in the resources/ dir.  Add a new subdirectory within there to create that resource.  The name of the directory will be the name of the resource.

You cannot create/delete users this way.  That needs to be a manual process.

Roles and profiles must have a trust policy, by name of trust.json added in resources/[role/profile_name]/trust/trust.json.

Groups may have a users.txt in their directory with a list of users, but is not required.

Managed Policies are slightly different from other resources.  Each policy is its own directory and the policy itself is a file called exactly policy.json.  There is also an attributes.txt file with the arn and read_only param.  This is because AWS adds and updates their own managed policies, they're usually named like AmazonServiceNameAccessType.  These policies can't be updated by us, but can be attached to a resource.


Adding a New Policy to a Resource
------------------------------

Create a new JSON file in `resources/[resource_name]/` directory using the
name of the policy.
For example:
```
S3.json
```

Attaching/Detaching Managed Policies to a Resource
------------------------------
In the subdirectory of the resource create a managed_policies.txt file if it doesn't already exist.  List the managed policies by name (without the .json extension), one per line.  To detach, just remove the policy from the list.

Adding Users to a Group
------------------------------
In `resources/groups/[group-name]/`, you can add a users.txt file with a list of user names, one user per line.


The difference between Profiles and Roles
------------------------------
Profiles are roles.  In the IAM console both will be under Roles.  The only difference is Profiles are a role that have an instance profile attached.  Instance profiles are used by EC2 instances to assume the role.  A lot of roles are used by users, so no EC2 instance is needed, and no need to create an instance profile in AWS.

Updating Changes
-----------------------------

To run update manually:

```sh
$ python update_iam.py
```

There is a dryrun parameter: `python update_iam.py --dryrun`

To export resources from AWS IAM Console to the resources file directory:
```sh
$ python update_iam.py --export
```
This will export to a folder named `iam-policies-[todays-date]`.
Rename the folder to resources/ when ready to merge.  This can be used if you make changes in the Console to test, and are ready to add the changes to the repo.
