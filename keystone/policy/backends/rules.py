# Copyright (c) 2011 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Policy engine for keystone."""
import sys
from oslo_log import log
from oslo_policy import policy as common_policy

import keystone.conf
from keystone import exception
from keystone.policy.backends import base
import policy_enforcer as JiwanPolicy
import json
import traceback
import time
CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


_ENFORCER = None


def reset():
    global _ENFORCER
    _ENFORCER = None
    

def init():
    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = common_policy.Enforcer(CONF)

def enforce(credentials, action, target, do_raise=True):
    """Verify that the action is valid on the target in this context.

    :param credentials: user credentials
    :param action: string representing the action to be checked, which should
                   be colon separated for clarity.
    :param target: dictionary representing the object of the action for object
                   creation this should be a dictionary representing the
                   location of the object e.g. {'project_id':
                   object.project_id}
    :raises keystone.exception.Forbidden: If verification fails.

    Actions should be colon separated for clarity. For example:

    * identity:list_users

    """
    init()

    # Add the exception arguments if asked to do a raise
    extra = {}
    if do_raise:
        extra.update(exc=exception.ForbiddenAction, action=action,
                     do_raise=do_raise)
    return _ENFORCER.enforce(action, target, credentials, **extra)


def authorize_aura(credentials, target):
                print "***********************"
                print "POLICY ENFORCE"
                print "***** TARGET:"
                print target
                print "***** Credentials:"
                print credentials
                print "***********************"

                admin_unit = ['target.admin_unit']
                admin_admin_unit = credentials.get('admin_unit')
                admin_location = credentials.get('location')
                print admin_location
                admin_admin_roles = credentials.get('admin_roles')
                user_admin_unit = target.get('target.admin_unit')
                user_location = target.get('target.location')
                print user_location
                user_user_clearance = target.get('target.user_clearance')
                target_role = target.get('target.role.name')

                with open('/opt/stack/keystone/keystone/policy/backends/attribute_policy.json') as policy:
                    policy = json.load(policy)
                for i in range(len(policy)):
                    print "ADMIN ROLES"
                    print policy[i]["role"]
		    #for j in (policy[i]["role"]):
		    if True == (target_role in policy[i]["role"]):
			print "target role is present!" 
		        print target_role			
		    #for j in (policy[i]["role"]):
                        #if j == target_role:
                        if (str(policy[i]["admin"]["admin_unit"])) == admin_admin_unit and (str(policy[i]["user"]["admin_unit"])) == user_admin_unit:
                            print "ADMIN UNIT IS PRESENT!"
                            print admin_admin_unit
                            print user_admin_unit
                            if (str(policy[i]["admin"]["location"])) == admin_location and (str(policy[i]["user"]["location"])) == user_location:
                                print "LOCATION IS PRESENT"
                                print admin_location
                                print user_location
                                print policy[i]["admin"]["admin_roles"]
                                print admin_admin_roles
                                for k in (policy[i]["admin"]["admin_roles"]):
                                    print "INSIDE ADMIN ROLES" 
                                    if k == admin_admin_roles:
                                        print "ADMIN ROLES MATCH.." 
                                        print policy[i]["admin"]["admin_roles"] 
                                        print admin_admin_roles 
                                        print "**********************************"  
                                        print policy[i]["user"]["clearance"] 
                                        print user_user_clearance  
                                        if (str(policy[i]["user"]["clearance"])) == user_user_clearance:
                                            print "USER CLEARANCE MATCH"
                                            print(time.time()) 
                                            print("**********")
                                            print ("Authorized granted!")
                                            print("**********")
                                            return True

                raise exception.Forbidden("Unathorised user role assignment attempt!!") 

class Policy(base.PolicyDriverBase):
    def enforce(self, credentials, action, target):
        msg = 'enforce %(action)s: %(credentials)s'
	LOG.debug(msg, {
            'action': action,
            'credentials': credentials}) 
        start_time = time.time()
	enforce(credentials, action, target) 	 
        # Now call the AURA authorization
        #traceback.print_stack()
	print "---------- ACTION ---------------"
	print action
        print "---------------------------------"
        if action == 'identity:create_grant' or action == 'identity:revoke_grant': 
            try:
                authorize_aura(credentials, target)
            except:          
                end_time = time.time()
                delta = end_time - start_time
                print("---------------print time diff ----------------")
                print delta
                raise exception.Forbidden("Unathorised user role assignment attempt!!") 
        end_time = time.time()
        delta = end_time - start_time
        print("---------------print time diff ----------------")
        print delta
                     
    def create_policy(self, policy_id, policy):
        raise exception.NotImplemented()

    def list_policies(self):
        raise exception.NotImplemented()

    def get_policy(self, policy_id):
        raise exception.NotImplemented()

    def update_policy(self, policy_id, policy):
        raise exception.NotImplemented()

    def delete_policy(self, policy_id):
        raise exception.NotImplemented()

