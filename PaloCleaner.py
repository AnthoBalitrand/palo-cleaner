import pan.xapi
import panos.objects
from panos.panorama import Panorama, DeviceGroup, PanoramaDeviceGroupHierarchy
from panos.objects import AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, PreRulebase, PostRulebase, Rulebase
from panos.predefined import Predefined
import re

class PaloCleaner:
    def __init__(self, panorama_url, panorama_user, panorama_password, dg_filter, apply_cleaning):
        self._panorama_url = panorama_url
        self._panorama_credentials = (panorama_user, panorama_password)
        self._dg_filter = dg_filter
        self._apply_cleaning = apply_cleaning
        self._panorama = self.panorama_connector(self._panorama_url, *self._panorama_credentials)
        self._objects = dict()
        self._used_objects_sets = dict()
        self._rulebases = dict()
        self._stored_pano_hierarchy = None
        self._removable_objects = list()
        self._tag_referenced = set()

    def panorama_connector(self, url, user, password):
        """
        Creates the Panorama object (connection)
        :param url: (string) FQDN / IP of the Panorama to connect
        :param user: (string) API user to be used
        :param password: (string) API user password
        :return: (Panorama) Connection to Panorama
        """

        print(f"Connecting to {url} with user {user}... ")
        return Panorama(url, user, password)

    def get_devicegroups(self):
        """
        Gets list of DeviceGroups from Panorama
        :return: (list) List of DeviceGroup objects
        """

        dg_list = DeviceGroup.refreshall(self._panorama)
        return dg_list

    def get_pano_dg_hierarchy(self):
        """
        Get DeviceGroupHierarchy from Panorama
        Returns cached value if already called
        :return: (dict)
        """

        if not self._stored_pano_hierarchy:
            self._stored_pano_hierarchy = PanoramaDeviceGroupHierarchy(self._panorama).fetch()
        return self._stored_pano_hierarchy

    def reverse_dg_hierarchy(self, pano_hierarchy, print_result=False):
        """
        Reverses the PanoramaDeviceGroupHierarchy dict
        (permits to have list of childs for each parent, instead of parent for each child)
        TODO : add colors to device-groups not concerned by the cleaning

        :param pano_hierarchy: (dict) PanoramaDeviceGroupHierarchy fetch result
        :param print_result: (bool) To print or not the reversed hierarchy on stdout
        :return: (dict) Each key is a device-group name, the associated value is the list of child device-groups
        """

        reversed_tree = dict()

        for k, v in pano_hierarchy.items():
            reversed_tree[v] = reversed_tree[v] + [k] if v in reversed_tree.keys() else [k]
            if k not in reversed_tree.keys():
                reversed_tree[k] = list()

        # If print_result attribute is True, print the result on screen
        if print_result:
            def print_tree_branch(tree, start = None, indent = 1):
                for k, v in reversed_tree.items():
                    if k == start:
                        for d in v:
                            print("   " * indent + "|--- " + d)
                            print_tree_branch(tree, d, indent + 1)

            print("\nObjects inheritance tree is : ")
            print("\nshared")
            print_tree_branch(reversed_tree)

        return reversed_tree

    def fetch_objects(self, context, location_name):
        """
        Gets the list of objects (AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup) for the provided location
        Stores it in the global _objects dict (per location name as a key)

        :param context: (Panorama or DeviceGroup) the panos object to use for polling
        :param location_name: (string) the name of the location
        :return:
        """

        # create _objects[location] if not yet existing
        if location_name not in self._objects.keys():
            self._objects[location_name] = dict()

        if location_name == 'predefined':
            # if location_name is "predefined", only download Predefined objects type (normally only services)
            predef = Predefined()
            self._panorama.add(predef)
            predef.refreshall()
            self._objects[location_name]['service'] = [v for k, v in predef.service_objects.items()]
            # context object is stored on the dict for further usage
            self._objects[location_name]['context'] = context
            self._objects[location_name]['address_obj'] = list()
            self._objects[location_name]['address_group'] = list()
            self._objects[location_name]['tag'] = list()
            self._objects[location_name]['service_group'] = list()
        else:
            # else download all objects types
            self._objects[location_name]['context'] = context
            self._objects[location_name]['address_obj'] = AddressObject.refreshall(context)
            self._objects[location_name]['address_group'] = AddressGroup.refreshall(context)
            self._objects[location_name]['tag'] = Tag.refreshall(context)
            self._objects[location_name]['service'] = ServiceObject.refreshall(context)
            self._objects[location_name]['service_group'] = ServiceGroup.refreshall(context)
        print("OK")

    def fetch_rulebase(self, context, location_name):
        """
        Downloads rulebase for the requested context
        TODO : fetch all rulebases (security, NAT, authentication...)

        :param context: (Panorama or DeviceGroup) instance to be used for fetch operation
        :param location_name: (string) Name of the location (Panorama or DeviceGroup name)
        :return:
        """

        # create _rulebases[location] if not yet existing
        if location_name not in self._rulebases.keys():
            self._rulebases[location_name] = dict()

        # context object given as parameter is stored for further usage
        self._rulebases[location_name]['context'] = context
        pre_security = PreRulebase()
        context.add(pre_security)
        self._rulebases[location_name]['pre_security'] = SecurityRule.refreshall(pre_security, add=True)
        post_security = PostRulebase()
        context.add(post_security)
        self._rulebases[location_name]['post_security'] = SecurityRule.refreshall(post_security, add=True)
        security = Rulebase()
        context.add(security)
        self._rulebases[location_name]['security'] = SecurityRule.refreshall(security, add=True)
        print("OK")

    def get_relative_object_location(self, obj_name, reference_location, type="address"):
        """
        Find referenced object by location (permits to get the referenced object on current location if
        existing at this level, or on upper levels of the device-groups hierarchy)
        TODO : find a way to block recursive call if already on the "shared" context

        :param obj_name: (string) Name of the object to find
        :param reference_location: (string) Where to start to find the object (device-group name or 'shared')
        :param type: (string) Type of object to look for (default = AddressGroup or AddressObject)
        :return: (AddressObject, string) Found object (or group), and its location name
        """

        print(f"Get relative object location for {obj_name} on {reference_location}")

        # Initialize return variables
        found_location = None
        found_object = None
        # For each object at the reference_location level, find any object having the searched name
        if type=="address":
            for obj in self._objects[reference_location]['address_obj'] + self._objects[reference_location]['address_group']:
                if obj.about()['name'] == obj_name:
                    found_location = reference_location
                    found_object = obj
        elif type=="tag":
            for obj in self._objects[reference_location]['tag']:
                if obj.name == obj_name:
                    found_location = reference_location
                    found_object = obj
        # if no object is found at current reference_location, find the upward device-group on the hierarchy
        # and call the current function recursively with this upward level as reference_location
        if not found_location and reference_location != 'shared':
            upward_dg = self.get_pano_dg_hierarchy()[reference_location]
            if not upward_dg:
                upward_dg = 'shared'
            found_object, found_location = self.get_relative_object_location(obj_name, upward_dg, type)
        # finally return the tuple of the found object and its location
        return (found_object, found_location)

    def get_relative_object_location_by_tag(self, executable_condition, reference_location):
        """
        Find objects referenced by a dynamic group (based on their tags)
        Knowing that dynamic groups can reference any object up to the level at which they are used
        And not only up to the level where they are defined
        TODO : what happen if upward object has the same name / tags than a matched local object ?

        :param executable_condition: (string) Executable python statement to match tags as configured on DAG
        :param reference_location: (string) Location where to start to find referenced objects (where the group is used)
        :return:
        """

        found_objects = list()
        # For each object at the reference_location level
        for obj in self._objects[reference_location]['address_obj'] + self._objects[reference_location]['address_group']:
            # check if current object has tags
            if obj.tag:
                #print(f"Object {obj} has tags !!!!!! ({obj.tag})")
                #print(f"Condition is : {executable_condition!r}")
                # initialize dict which will contain the results of the executable_condition execution
                expr_result = dict()
                obj_tags = obj.tag
                # Execute the executable_condition with the locals() context
                exec(executable_condition, locals(), expr_result)
                cond_expr_result = expr_result['cond_expr_result']
                # If the current object tags matches the executable_condition, add it to found_objects
                if cond_expr_result:
                    #print(f"AND THOSE TAGS HAVE BEEN MATCHED")
                    found_objects.append((obj, reference_location))
        # if we are not yet at the 'shared' level
        if reference_location != 'shared':
            # find the upward device-group
            upward_dg = self.get_pano_dg_hierarchy()[reference_location]
            if not upward_dg:
                upward_dg = 'shared'
            # call the current function recursively with the upward group level
            found_objects += self.get_relative_object_location_by_tag(executable_condition, upward_dg)
        # return list of tuples containing all found objects and their respective location
        return found_objects

    def fetch_address_obj_set(self, location_name):
        """
        For a given location_name, will parse the rulebase, and will build a set of all objects used
        (either directly referenced, or member of a static or dynamic group)
        Each member of the set will be a tuple of (object, location)
        where the location of the used object can be anything at the same location of the parsed rulebase
        (location_name), or upper in the DeviceGroups hierarchy
        Knowing that :
        - a static-group can only reference objects at same level or upward
        - a dynamic-group can reference anything (upward or downward) as soon as objects are tagged with a matching value

        :param location_name: (string) Name of fetched location ('shared' or any device-group name)
        :return:
        """

        # it is possible to create an object group using the name of an upward address object
        # but the object group cannot be deleted to be replaced by a reference to the upward address object
        # WARNING : unexpected behaviors if groups and address objects have the same names

        def flatten_group(group, members_location_base, group_location):
            """
            Submethod used to iterate over members of groups (including nested groups) to find all used objects
            :param group: (AddressGroup) for which to get all members
            :param members_location_base: (string) base location where we can find group members for this kind of groups
            :param group_location: (string) where the group has been found
            :return: (set) of tuples (obj, location) of all member objects of the parsed group
            """
            print(f"Call to flatten_group : {group, members_location_base, group_location}")

            group_obj_set = list()
            # if this is a static group, only check for same-level or upward members
            if group.static_value :
                for a in group.static_value:
                    # Get object referenced relatively to AddressGroup location
                    referenced_object, referenced_object_location = self.get_relative_object_location(a, members_location_base)
                    # if referenced object is another group, flatten this one recursively
                    if type(referenced_object) == panos.objects.AddressGroup:
                        group_obj_set += flatten_group(referenced_object, referenced_object_location, referenced_object_location)
                    # add object (address or nested group) to object set
                    group_obj_set.append((referenced_object, referenced_object_location))
                    # for each tag used on a referenced object, add it to the used objects set
                    if referenced_object.tag:
                        for tag in referenced_object.tag:
                            referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_object_location, type="tag")
                            group_obj_set.append((referenced_tag, referenced_tag_location))
            # if this is a dynamic group, check for upward or downward members (down to location_name of the referencing rule)
            elif group.dynamic_value:
                print(f"[{group_location}] Found DAG : {group.name}")
                # Transform the dynamic group condition to an executable python statement
                # Example : ('TAG1' and 'TAG2') or 'TAG3'
                # will become "cond_expr_result = ('TAG1' and 'TAG2') in obj_tags or 'TAG3' in obj_tags"
                executable_condition = gen_condition_expression(group.dynamic_value, "obj_tags")
                # for each object, location found using the tags condition
                for referenced_object, referenced_object_location in self.get_relative_object_location_by_tag(executable_condition, members_location_base):
                    print(f"[{members_location_base}] Group {group.name} is referencing object ({referenced_object}, {referenced_object_location})")
                    # if object is another group, flatten it
                    if type(referenced_object) == panos.objects.AddressGroup:
                        group_obj_set += flatten_group(referenced_object, members_location_base, referenced_object_location)
                    # else just add each found object to the set
                    else:
                        # TODO : do not add object to the referenced list if an object with the same name has already been added
                        group_obj_set.append((referenced_object, referenced_object_location))
                        # add object to the list of objects which are referenced by their tag for further treatment
                        self._tag_referenced.add((referenced_object, referenced_object_location))
                    # for each tag used on a referenced object, add it to the used objects set
                    if referenced_object.tag:
                        for tag in referenced_object.tag:
                            referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_object_location, type="tag")
                            group_obj_set.append((referenced_tag, referenced_tag_location))

            # finally add the group itself to the objects set
            group_obj_set.append((group, group_location))
            print(group_obj_set)
            return group_obj_set

        def gen_condition_expression(condition_string, field_name):
            """
            Transforms a DAG objects match condition in an executable python statement
            :param condition_string: (string) Condition got from the DAG object
            :param field_name: (string) List on which the objects will be put for match at statement execution
            :return: (string) Python executable condition
            """

            condition1 = re.sub('and(?![^(]*\))', f"in {field_name} and", condition_string)
            condition2 = re.sub('or(?![^(]*\))', f"in {field_name} or", condition1)
            condition2 += f" in {field_name}"
            condition = "cond_expr_result = " + condition2
            return condition

        obj_ref_set = list()
        # iterates on all rulebases for the concerned location
        for k, v in self._rulebases[location_name].items():
            if k == "context":
                # if the current key is 'context', pass (as it contains the DeviceGroup object instance)
                continue
            # for each rule in the current rulebase
            for r in v:
                # for all objects, used either as source or destination
                for obj in r.source + r.destination:
                    # if the value is not 'any'
                    if obj != 'any':
                        # get the referenced object and its location (can be at same level or upward)
                        referenced_object, referenced_object_location = self.get_relative_object_location(obj, location_name)
                        if referenced_object and referenced_object_location:
                            # if the referenced object is an AddressGroup, call the flatten method to get all members
                            if type(referenced_object) == panos.objects.AddressGroup:
                                if referenced_object.static_value:
                                    # if object is a static group, it can only use local or upward objects (base on the group location = referenced_object_location)
                                    obj_ref_set += flatten_group(referenced_object, referenced_object_location, referenced_object_location)
                                elif referenced_object.dynamic_value:
                                    # if object is a dynamic group, it can reference all objects (upward or downward) starting by the location where the object is used (location_name)
                                    obj_ref_set += flatten_group(referenced_object, location_name, referenced_object_location)
                                obj_ref_set.append((referenced_object, referenced_object_location))
                            # if the referenced object is not an AddressGroup, just add it to the obj_ref_set as a tuple (with its location)
                            else:
                                obj_ref_set.append((referenced_object, referenced_object_location))
                                # for each tag used on the referenced object
                                if referenced_object.tag:
                                    for tag in referenced_object.tag:
                                        # get the referenced object's referenced tag and its location (can be same level or upward)
                                        referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_object_location, type="tag")
                                        obj_ref_set.append((referenced_tag, referenced_tag_location))
                # for all objects used as tag directly on the rule
                if r.tag:
                    for tag in r.tag:
                        # get the referenced tag object and its location (can be at same level or upward)
                        referenced_tag, referenced_tag_location = self.get_relative_object_location(obj, location_name, type="tag")
                        obj_ref_set.append((referenced_tag, referenced_tag_location))

        # add the fetched objects set to the _used_objects_set dict
        self._used_objects_sets[location_name] = set(obj_ref_set)
        print(set(obj_ref_set))
        print("OK")

    def find_upward_obj_by_addr(self, base_location_name, obj_addr):
        """
        Find AddressObject having the same IP given as obj_addr at upper levels, starting at base_location_name level
        :param base_location_name: (string) Base location where to find objects upward
        :param obj_addr: (string) IP address of the objects for which we want to find duplicates at upper levels
        :return: (list) of tuples (AddressObject, location) of objects found on upper levels
        """

        def hostify_address(address):
            """
            Submethod used to remove /32 at the end of an IP address
            :param address: (string) IP address to be modified
            :return: (string) Host IP address (instead of network /32)
            """

            # removing /32 mask for hosts
            if address[-3:] == '/32':
                return address[:-3:]
            return address

        # call to hostify_address submethod to remove /32 at the end
        obj_addr = hostify_address(obj_addr)
        # initialize the list which will contains found objects
        found_upward_objects = list()
        # find name of the parent device-group (related to base_location_name)
        upward_devicegroup = self.get_pano_dg_hierarchy().get(base_location_name)
        # if there's no parent, then parent is 'shared' level
        if not upward_devicegroup:
            upward_devicegroup = 'shared'
        # for each object existing at found upper evel
        for obj in self._objects[upward_devicegroup]['address_obj']:
            # if current object has the same IP address than the searched one
            if hostify_address(obj.value) == obj_addr:
                # add tuple for the found object to the found_upward_objects list
                found_upward_objects.append((obj, upward_devicegroup))
        # if we are not yet at the 'shared' level
        if upward_devicegroup != 'shared':
            # call the current function recursively to find upward objects
            found_upward_objects += self.find_upward_obj_by_addr(upward_devicegroup, obj_addr)
        # returns list of tuple containing all found objects
        return found_upward_objects

    def find_best_replacement_addr_obj(self, obj_list):
        """
        Get a list of tuples (object, location) and returns the best to be used based on location and naming criterias
        TODO : WARNING, can have unpredictable results with nested device-groups

        :param obj_list: list((AddressObject, string)) List of tuples of AddressObject and location names
        :return:
        """

        # create a list of shared objects from the obj_list
        shared_obj = [x for x in obj_list if x[1] == 'shared']
        # create a list of objects having name with multiple "." and ending with "corp" or "com" (probably FQDN)
        fqdn_obj = [x for x in obj_list if len(x[0].about()['name'].split('.')) > 1 and x[0].about()['name'].split('.')[-1] in ['corp', 'com']]
        # find objects being both shared and with FQDN-like naming
        shared_fqdn_obj = list(set(shared_obj) & set(fqdn_obj))

        # if shared and well-named objects are found, return the first one
        if shared_fqdn_obj:
            return shared_fqdn_obj[0]
        # else return the first found shared object
        if shared_obj:
            return shared_obj[0]

    def optimize_address_objects(self, location_name):
        """
        Start object optimization processing for device-group given as argument

        :param location_name: (string) Location where to start objects optimization
        :return:
        """

        # for each object and location found on the _used_objects_set for the current location
        for obj, location in self._used_objects_sets[location_name]:
            # if the current object type is AddressObject and exists at the current location level
            if type(obj) == panos.objects.AddressObject and location == location_name:
                # find similar objects (same IP address) on upper level device-groups (including 'shared')
                upward_objects = self.find_upward_obj_by_addr(location_name, obj.value)
                # if upward duplicate objects are found
                if upward_objects:
                    # find which one is the best to use
                    replacement_obj, replacement_obj_location = self.find_best_replacement_addr_obj(upward_objects)
                    #print(f"Object {obj.about()['name']} ({obj.value}) can be replaced by {replacement_obj[0].about()['name']} ({replacement_obj[0].value}) on {replacement_obj[1]}")
                    print(f"[{location_name}] Replacing ({obj}, {location}) --by--> ({replacement_obj.about()['name']}, {replacement_obj_location})")
                    # call replace_object method with current object and the one with which to replace it
                    self.replace_object(location_name, (obj, location), (replacement_obj, replacement_obj_location))

    def replace_object(self, location_name, ref_obj, replacement_obj):
        """
        Method in charge of replacing on object wherever it is used on rulebases and groups at a defined location
        TODO : handle deletion of tags when replaced by shared ones

        :param location_name: (string) Name of the location where the object has been seen used
        :param ref_obj: ((AddressObject, string)) To-be-replaced object instance and its location name
        :param replacement_obj: ((AddressObject, string)) Replacement object instance and its location name
        :return:
        """

        # Get all useful values from replaced and replacement objects
        ref_obj_instance, ref_obj_location = ref_obj
        ref_obj_name = ref_obj_instance.about()['name']
        replacement_obj_instance, replacement_obj_location = replacement_obj
        replacement_obj_name = replacement_obj_instance.about()['name']

        # If the initial object is referenced on DAGs, make sure to replicate tags on replacement object
        if ref_obj in self._tag_referenced:
            ref_obj_instance, ref_obj_location = ref_obj
            for t in ref_obj_instance.tag:
                # for each tag in the tag-referenced object, check if this tag exists as a shared object
                if not any((x for x in self._objects['shared']['tag'] if x.name == t)):
                    tag_instance, tag_location = self.get_relative_object_location(t, location_name, type="tag")
                    print(
                        f'[shared] Create tag {t} (copy from {tag_location}) to be used on ({replacement_obj_name}, {replacement_obj_location})')
                    try:
                        if self._apply_cleaning:
                            self._panorama.add(tag_instance).create()
                        self._objects['shared']['tag'].append(tag_instance)
                        self._used_objects_sets['shared'].add((tag_instance, 'shared'))
                    except Exception as e:
                        print(f"Exception while creating tag {t} as shared : {e}")
                print(f"[{replacement_obj_location}] Adding tag {t} to ({replacement_obj_name}, {replacement_obj_location})")
                replacement_obj_instance.tag.append(t)
                if self._apply_cleaning:
                    replacement_obj_instance.apply()

        # If the initial and the replacement objects have different names
        if ref_obj_name != replacement_obj_name:
            # fetch all items of the _rulebases cached data for the concerned location
            for l, rb in self._rulebases[location_name].items():
                if l == 'context':
                    continue
                # for each rule of the current rulebase
                for r in rb:
                    replace_in_source = False
                    replace_in_destination = False
                    # check if initial object needs to be replaced in rule source or destination
                    if ref_obj_name in r.source:
                        replace_in_source = True
                    if ref_obj_name in r.destination:
                        replace_in_destination = True
                    # if object reference needs to be replaced on current rule source, remove initial reference and add new one
                    if replace_in_source:
                        r.source.remove(ref_obj_name)
                        r.source.append(replacement_obj_name)
                        print(f"    -- Replaced as source on rule {r.name}")
                        #print(f"{ref_obj_name} (inherited from {ref_obj_location}) has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on rule {r.name} as source")
                    # if object reference needs to be replacent on current rule destination, remove initial reference and add new one
                    if replace_in_destination:
                        r.destination.remove(ref_obj_name)
                        r.destination.append(replacement_obj_name)
                        print(f"    -- Replaced as destination on rule {r.name}")
                        #print(f"{ref_obj_name} (inherited from {ref_obj_location}) has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on rule {r.name} as destination")
                    # apply change if anything has been changed
                    if replace_in_source or replace_in_destination:
                        if self._apply_cleaning:
                            r.apply()
            # fetch all AddressGroup objects for the concerned location
            for g in self._objects[location_name]['address_group']:
                replace = False
                # if reference to the initial object is found on the group members
                if ref_obj_name in g.static_value:
                    replace = True
                # replace the found reference by the new object name
                if replace:
                    g.static_value.remove(ref_obj_name)
                    g.static_value.append(replacement_obj_name)
                    print(f"    -- Replaced on static group {g.name}")
                    #print(f"{ref_obj_name} (inherited from {ref_obj_location} has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on group {g.name}")
                    # apply change if anything ha been changed
                    if self._apply_cleaning:
                        g.apply()
        # if initial object and replacement objects have the same name, deleting the initial object will make the reference
        # directly pointing to the replacement object
        else:
            print(f"    -- Can be deleted as chosen replacement object has the same name")
            #print(f"{ref_obj_name} (inherited from {ref_obj_location}) can be deleted and will be directly replaced by same-name object {replacement_obj_name} (inherited from {replacement_obj_location})")
        # add objects to the deletion list
        self._removable_objects.append(ref_obj)

    def remove_objects(self):
        """
        Delete objects which have been added to the _removable_objects dict

        :return:
        """
        delete_count = dict()
        for loc in self._objects.keys():
            if not loc in delete_count.keys():
                delete_count[loc] = 0

        # for each tuple (Object, location_name) in _removable_objects
        for obj_instance, obj_location in self._removable_objects:

            print(f"[{obj_location}] Deleting object {obj_instance.about().get('name')}")

            # remove from the _objects cached information for the object location
            self._objects[obj_location]['address_obj'].remove(obj_instance)
            # TODO : test behavior is object on parent (intermediate) DG is removed from 1 child DG and remains used on another one

            # remove object from all _used_objects_set sub-dict (each location) where it has been found as used
            for loc in self._used_objects_sets.keys():
                try:
                    self._used_objects_sets[loc].remove((obj_instance, obj_location))
                    print(f"Object {obj_instance.about().get('name')} well DELETED from location {loc}")
                except KeyError:
                    pass
                except Exception as e:
                    print(f"[{loc}] ERROR - Object {obj_instance.about().get('name')} not found ! {e}")

            # delete the object itself (if apply-cleaning parameter is given in start command)
            if self._apply_cleaning:
                obj_instance.delete()
            delete_count[obj_location] += 1
            print(f"[{obj_location}] Deleting object {obj_instance.about().get('name')} as it has been replaced")

        # remove unused objects (including groups), which are not member of any used_objects_set sub-dict
        # cleaning order has to be fixed to avoid dependencies errors (deleting unused group before deleting members of this group)
        cleaning_order = ['service_group', 'service', 'address_group', 'address_obj', 'tag']

        global_used_objects_set = set()
        for k, v in self._used_objects_sets.items():
            for obj_tuple in v:
                global_used_objects_set.add(obj_tuple)

        depthed_tree = dict({0: ['shared']})

        def gen_tree_depth(input_tree, start=None, depth=1):
            """
            Submethod used to create a dict with the "depth" value for each device-group, depth for 'shared' being 0

            :param input_tree: (dict) Reversed PanoramaDeviceGroupHierarchy tree
            :param start: (string) Where to start for depth calculation (function being called recursively)
            :param depth: (int) Actual depth of analysis
            :return: (dict) Dict with keys being the depth of the devicegroups and value being list of device-group names
            """

            for loc in input_tree[start]:
                if depth not in depthed_tree.keys():
                    depthed_tree[depth] = list()
                depthed_tree[depth].append(loc)
                gen_tree_depth(input_tree, loc, depth+1)

        # get reversed PanoramaDeviceGroupHierarchy dict
        dg_reversed_tree = self.reverse_dg_hierarchy(self.get_pano_dg_hierarchy())
        # use it on gen_tree_depth to update depthed_tree
        gen_tree_depth(dg_reversed_tree)

        # Create a list for which the order will be the more "depth" device-groups first, then going up to 'shared'
        dg_clean_order = list()
        for key in sorted(depthed_tree.keys(), reverse=True):
            dg_clean_order += depthed_tree[key]
        print(f"Cleaning DG in the following order : {dg_clean_order} ")

        # for each device-group in the dg_clean_order list (starting with the more depthed)
        for k in dg_clean_order:
            print(f"Starting cleaning unused {k}")
            v = self._objects[k]
            # for each type of objects, in the cleaning_order order
            for type in cleaning_order:
                for obj in v[type]:
                    # If the current object is not used anywhere
                    if (obj, k) not in global_used_objects_set:
                        try:
                            print(f"[{k}] Deleting unused object {obj.about().get('name')}")
                            # Let's delete it
                            if self._apply_cleaning:
                                obj.delete()
                        except pan.xapi.PanXapiError as e:
                            print(f"[{k}] ERROR when deleting unused object {obj.about().get('name')}. TRY MANUALLY")
                        finally:
                            delete_count[k] += 1
        print("\n\n\n")
        print("Deleted objects per location : ")
        for k, v in delete_count.items():
            print(f"{k} --> {v}")

        print(self._used_objects_sets)