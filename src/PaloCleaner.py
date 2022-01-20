import pan.xapi
import sys
sys.path.append("/Users/to148757/PycharmProjects/panos-python/pan-os-python")

from rich.console import Console
from rich.prompt import Prompt
from rich.tree import Tree
from rich.spinner import Spinner
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
import panos.objects
from panos.panorama import Panorama, DeviceGroup, PanoramaDeviceGroupHierarchy
from panos.objects import AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, PreRulebase, PostRulebase, Rulebase, NatRule, AuthenticationRule
from panos.predefined import Predefined
from panos.errors import PanXapiError
import re
import time

class PaloCleaner:
    def __init__(self, panorama_url, panorama_user, panorama_password, dg_filter, apply_cleaning, superverbose=False):
        self._panorama_url = panorama_url
        self._panorama_user = panorama_user
        self._panorama_password = panorama_password
        self._dg_filter = dg_filter
        self._depthed_tree = dict({0: ['shared']})
        self._apply_cleaning = apply_cleaning
        self._panorama = None
        self._objects = dict()
        self._addr_namesearch = dict()
        self._tag_namesearch = dict()
        self._addr_ipsearch = dict()
        self._service_namesearch = dict()
        self._used_objects_sets = dict()
        self._rulebases = dict()
        self._stored_pano_hierarchy = None
        self._removable_objects = list()
        self._tag_referenced = set()
        self._resolved_cache = dict()
        self._superverbose = superverbose
        self._console = Console()

    def start(self):
        header_text = Text("""

  ___      _        ___ _                       
 | _ \__ _| |___   / __| |___ __ _ _ _  ___ _ _ 
 |  _/ _` | / _ \ | (__| / -_) _` | ' \/ -_) '_|
 |_| \__,_|_\___/  \___|_\___\__,_|_||_\___|_|  
                                                
        by Anthony BALITRAND v1.0                                           

""")
        self._console.print(header_text, style="green", justify="left")
        while self._panorama_password == "":
            self._panorama_password = Prompt.ask(f"Please provide the password for API user {self._panorama_user!r} ", password=True)
        with self._console.status("Connecting to Panorama...", spinner="dots12") as status:
            try:
                self._panorama = Panorama(self._panorama_url, self._panorama_user, self._panorama_password)
                self.get_pano_dg_hierarchy()
                time.sleep(1)
                self._console.log("Panorama connection established")
            except PanXapiError as e:
                self._console.log(f"Error while connecting to Panorama : {e.message}", style="red")
                return 0
            except Exception as e:
                self._console.log("Unknown error occured while connecting to Panorama", style="red")
                return 0

            status.update("Parsing device groups list")
            hierarchy_tree = self.generate_hierarchy_tree()
            time.sleep(2)
            self._console.log("Discovered hierarchy tree is the following :")
            self._console.log("( + are directly included / * are indirectly included / - are not included )")
            self._console.log(Panel(hierarchy_tree))
            time.sleep(2)

            status.update("Downloading Panorama shared objects")
            self.fetch_objects(self._panorama, 'shared')
            self.fetch_objects(self._panorama, 'predefined')
            self._console.log(f"Panorama objects downloaded ({self.count_objects('shared')} found)")

            status.update("Downloading Panorama rulebases")
            self.fetch_rulebase(self._panorama, 'shared')
            self._console.log(f"Panorama rulebases downloaded ({self.count_rules('shared')} rules found)")

            for dg in self.get_devicegroups():
                context_name = dg.about()['name']
                if context_name in self._analysis_perimeter['direct'] + self._analysis_perimeter['indirect']:
                    status.update(f"Downloading {context_name} objects")
                    self.fetch_objects(dg, context_name)
                    self._console.log(f"{context_name} objects downloaded ({self.count_objects(context_name)} found)")
                    status.update(f"Downloading {context_name} rulebases")
                    self.fetch_rulebase(dg, context_name)
                    self._console.log(f"{context_name} rulebases downloaded ({self.count_rules(context_name)} rules found)")
            """
            status.update("Parsing used address objects set for shared")
            self.fetch_address_obj_set("shared")
            self._console.log("shared used objects set processed")

            for dg in self.get_devicegroups():
                if dg.about()['name'] in self._analysis_perimeter['direct'] + self._analysis_perimeter['indirect']:
                    status.update(f"Parsing used address objects set for {dg}")
                    self.fetch_address_obj_set(dg.about()['name'])
                    self._console.log(f"{dg.about()['name']} used objects set processed")
            """

        with Progress(
                SpinnerColumn(spinner_name= "dots12"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                TimeElapsedColumn(),
                console= self._console,
                transient= True
                ) as progress:

            shared_task = progress.add_task("Shared - Processing used objects location", total=self.count_rules('shared'))
            self.fetch_address_obj_set("shared", progress, shared_task)
            self._console.log("shared used objects set processed")
            progress.remove_task(shared_task)

            for dg in self.get_devicegroups():
                if dg.about()['name'] in self._analysis_perimeter['direct'] + self._analysis_perimeter['indirect']:
                    dg_task = progress.add_task(f"{dg.about()['name']} - Processing used objects location", total=self.count_rules(dg.about()['name']))
                    self.fetch_address_obj_set(dg.about()['name'], progress, dg_task)
                    self._console.log(f"{dg.about()['name']} used objects set processed")
                    progress.remove_task(dg_task)
        #self.reverse_dg_hierarchy(self.get_pano_dg_hierarchy(), print_result=True)

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
            self._reversed_tree = dict()
            self._stored_pano_hierarchy = PanoramaDeviceGroupHierarchy(self._panorama).fetch()
            for k, v in self._stored_pano_hierarchy.items():
                if v is None:
                    v = 'shared'
                self._reversed_tree[v] = self._reversed_tree[v] + [k] if v in self._reversed_tree.keys() else [k]
                if k not in self._reversed_tree.keys():
                    self._reversed_tree[k] = list()

            # Initializes _depthred_tree dict which is an "ordered list" of device-groups, from higher in hierarchy to
            # lowest ones. Then calls gen_tree_depth method to populate.
            self._depthed_tree = dict({0: ['shared']})
            self.gen_tree_depth(self._reversed_tree)

    def generate_hierarchy_tree(self):
        """
        Reverses the PanoramaDeviceGroupHierarchy dict
        (permits to have list of childs for each parent, instead of parent for each child)
        TODO : add colors to device-groups not concerned by the cleaning

        :param pano_hierarchy: (dict) PanoramaDeviceGroupHierarchy fetch result
        :param print_result: (bool) To print or not the reversed hierarchy on stdout
        :return: (dict) Each key is a device-group name, the associated value is the list of child device-groups
        """
        self._analysis_perimeter = self.get_perimeter(self._reversed_tree)
        if 'shared' in self._analysis_perimeter['direct']:
            hierarchy_tree = Tree("+ shared", style="red")
        elif 'shared' in self._analysis_perimeter['indirect']:
            hierarchy_tree = Tree("* shared", style="yellow")

        # If print_result attribute is True, print the result on screen
        def add_leafs(tree, tree_branch, start='shared'):
            for k, v in self._reversed_tree.items():
                if k == start:
                    for d in v:
                        if d in self._analysis_perimeter['direct']:
                            leaf = tree_branch.add("+ " + d, style="red")
                        elif d in self._analysis_perimeter['indirect']:
                            leaf = tree_branch.add("* " + d, style="yellow")
                        else :
                            leaf = tree_branch.add("- " + d, style="green")
                        add_leafs(tree, leaf, d)

        add_leafs(self._reversed_tree, hierarchy_tree)
        return hierarchy_tree

    def get_perimeter(self, reversed_tree):
        """
        Returns the list of directly, indirectly, and fully included device groups in the cleaning perimeter.
        Direct included DG are the ones specified in the CLI argument at startup
        Indirect included are all upwards DG above the directly included ones.
        Fully included are parents DG having all their child included.

        :param reversed_tree: (dict) Dict where keys are parent device groups and value is the list of childs
        :return: (dict) Representation of directly, indirectly, and fulled included device-groups
        """

        indirectly_included = list()
        directly_included = list()
        fully_included = list()
        for depth in sorted(self._depthed_tree, reverse=True):
            for dg in self._depthed_tree[depth]:
                if self._dg_filter:
                    if dg in self._dg_filter:
                        directly_included.append(dg)
                    else:
                        found_child = False
                        nb_found_child = 0
                        for child in reversed_tree.get(dg, list()):
                            if child in directly_included + indirectly_included:
                                found_child = True
                                nb_found_child += 1
                        if found_child:
                            indirectly_included.append(dg)
                            if nb_found_child == len(reversed_tree.get(dg)):
                                fully_included.append(dg)
                else:
                    directly_included.append(dg)
                    fully_included.append(dg)
        return {'direct': directly_included, 'indirect': indirectly_included, 'full': fully_included}

    def count_objects(self, location_name):
        counter = 0
        try:
            for t, l in self._objects.get(location_name, dict()).items():
                counter += len(l) if type(l) is list else 0
        finally:
            return counter

    def count_rules(self, location_name):
        counter = 0
        try:
            for b, l in self._rulebases.get(location_name, dict()).items():
                counter += len(l) if type(l) is list else 0
        finally:
            return counter

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
            self._service_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['service']}
        else:
            # else download all objects types
            self._objects[location_name]['context'] = context
            self._objects[location_name]['address_obj'] = AddressObject.refreshall(context)
            self._objects[location_name]['address_group'] = AddressGroup.refreshall(context)
            if self._superverbose:
                self._console.log(f"{location_name} objects namesearch structures initialized")
            self._addr_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['address_group'] + self._objects[location_name]['address_obj']}
            if self._superverbose:
                self._console.log(f"{location_name} objects ipsearch structures initialized")
            self._addr_ipsearch[location_name] = dict()
            for obj in self._objects[location_name]['address_obj']:
                addr = self.hostify_address(obj.value)
                if addr not in self._addr_ipsearch[location_name].keys():
                    self._addr_ipsearch[location_name][addr] = list()
                self._addr_ipsearch[location_name][addr].append(obj)
            self._objects[location_name]['tag'] = Tag.refreshall(context)
            self._tag_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['tag']}
            self._objects[location_name]['service'] = ServiceObject.refreshall(context)
            self._objects[location_name]['service_group'] = ServiceGroup.refreshall(context)
            if self._superverbose:
                self._console.log(f"{location_name} services namesearch structures initialized")
            self._service_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['service'] + self._objects[location_name]['service_group']}

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
        pre_rulebase = PreRulebase()
        context.add(pre_rulebase)
        self._rulebases[location_name]['pre_security'] = SecurityRule.refreshall(pre_rulebase, add=True)
        self._rulebases[location_name]['pre_nat'] = NatRule.refreshall(pre_rulebase, add=True)
        self._rulebases[location_name]['pre_auth'] = AuthenticationRule.refreshall(pre_rulebase, add=True)
        post_rulebase = PostRulebase()
        context.add(post_rulebase)
        self._rulebases[location_name]['post_security'] = SecurityRule.refreshall(post_rulebase, add=True)
        self._rulebases[location_name]['post_nat'] = NatRule.refreshall(post_rulebase, add=True)
        self._rulebases[location_name]['pre-auth'] = AuthenticationRule.refreshall(post_rulebase, add=True)
        default_rulebase = Rulebase()
        context.add(default_rulebase)
        self._rulebases[location_name]['default_security'] = SecurityRule.refreshall(default_rulebase, add=True)

    def get_relative_object_location(self, obj_name, reference_location, obj_type="address"):
        """
        Find referenced object by location (permits to get the referenced object on current location if
        existing at this level, or on upper levels of the device-groups hierarchy)
        TODO : find a way to block recursive call if already on the "shared" context

        :param obj_name: (string) Name of the object to find
        :param reference_location: (string) Where to start to find the object (device-group name or 'shared')
        :param obj_type: (string) Type of object to look for (default = AddressGroup or AddressObject)
        :return: (AddressObject, string) Found object (or group), and its location name
        """

        #self._console.log(f"Call to get_relative_object_location for {obj_name} (type {obj_type}) on {reference_location}")

        # Initialize return variables
        found_object = None
        found_location = None
        # For each object at the reference_location level, find any object having the searched name
        if obj_type == "address":
            """
            for obj in self._objects[reference_location]['address_obj'] + self._objects[reference_location]['address_group']:
                if obj.about()['name'] == obj_name:
                    found_location = reference_location
                    found_object = obj
            """
            found_object = self._addr_namesearch[reference_location].get(obj_name, None)
            found_location = reference_location
        elif obj_type == "tag":
            """
            for obj in self._objects[reference_location]['tag']:
                if obj.name == obj_name:
                    found_location = reference_location
                    found_object = obj
            """
            found_object = self._tag_namesearch[reference_location].get(obj_name, None)
            found_location = reference_location
        elif obj_type == "service":
            found_object = self._service_namesearch[reference_location].get(obj_name, None)
            found_location = reference_location

        # if no object is found at current reference_location, find the upward device-group on the hierarchy
        # and call the current function recursively with this upward level as reference_location
        if not found_object and reference_location not in ['shared', 'predefined']:
            upward_dg = self._stored_pano_hierarchy[reference_location]
            if not upward_dg:
                upward_dg = 'shared'
            found_object, found_location = self.get_relative_object_location(obj_name, upward_dg, obj_type)
        elif not found_object and (obj_type == "service" and reference_location == 'shared'):
            upward_dg = "predefined"
            found_object, found_location = self.get_relative_object_location(obj_name, upward_dg, obj_type)
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
            upward_dg = self._stored_pano_hierarchy[reference_location]
            if not upward_dg:
                upward_dg = 'shared'
            # call the current function recursively with the upward group level
            found_objects += self.get_relative_object_location_by_tag(executable_condition, upward_dg)
        # return list of tuples containing all found objects and their respective location
        return found_objects

    def fetch_address_obj_set(self, location_name, progress, task):
        """
        For a given location_name, will parse the rulebase, and will build a set of all objects used
        (either directly referenced, or member of a static or dynamic group)
        Each member of the set will be a tuple of (object, location)
        where the location of the used object can be anything at the same location of the parsed rulebase
        (location_name), or upper in the DeviceGroups hierarchy
        Knowing that :
        - a static-group can only reference objects at same level or upward
        - a dynamic-group can reference anything (upward or downward) as soon as objects are tagged with a matching value

        TODO : avoid adding / flattening two times the same group object

        :param location_name: (string) Name of fetched location ('shared' or any device-group name)
        :return:
        """

        # it is possible to create an object group using the name of an upward address object
        # but the object group cannot be deleted to be replaced by a reference to the upward address object
        # WARNING : unexpected behaviors if groups and address objects have the same names
        def flatten_group(group, members_location_base, group_location, obj_type='address'):
            """
            Submethod used to iterate over members of groups (including nested groups) to find all used objects
            :param group: (AddressGroup) for which to get all members
            :param members_location_base: (string) base location where we can find group members for this kind of groups
            :param group_location: (string) where the group has been found
            :return: (set) of tuples (obj, location) of all member objects of the parsed group
            """

            group_obj_set = list()
            # if this is a static group, only check for same-level or upward members
            if obj_type == "address":
                if group.static_value :
                    for a in group.static_value:
                        if a not in self._resolved_cache[members_location_base]['addresses']:
                            if self._superverbose:
                                self._console.log(f"Found member of group {group.name} : {a}")
                            # Get object referenced relatively to AddressGroup location
                            referenced_object, referenced_object_location = self.get_relative_object_location(a, members_location_base)
                            # if referenced object is another group, flatten this one recursively
                            if type(referenced_object) == panos.objects.AddressGroup:
                                if self._superverbose:
                                    self._console.log(f"{a} is a group. Expanding members...")
                                group_obj_set += flatten_group(referenced_object, members_location_base, referenced_object_location)
                            # add object (address or nested group) to object set
                            group_obj_set.append((referenced_object, referenced_object_location))
                            # for each tag used on a referenced object, add it to the used objects set
                            if referenced_object.tag:
                                for tag in referenced_object.tag:
                                    if self._superverbose:
                                        self._console.log(f"Object {a} uses tag {tag}. Trying to resolve it")
                                    if not tag in self._resolved_cache[members_location_base]['tags']:
                                        # TODO : check if a tag can be overriden on downward group (replacing referenced_object_location by members_location_base ?)
                                        referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_object_location, obj_type="tag")
                                        group_obj_set.append((referenced_tag, referenced_tag_location))
                                    elif self._superverbose:
                                        self._console.log(
                                            f"Tag {tag} already resolved on current context ({referenced_object_location})",
                                            style="green")
                        elif self._superverbose:
                            self._console.log(f"Object {a} member of group {group.name} already resolved in context {group_location}", style="green")
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
                        # TODO : do not add object to the referenced list if an object with the same name has already been added
                        group_obj_set.append((referenced_object, referenced_object_location))
                        # add object to the list of objects which are referenced by their tag for further treatment
                        self._tag_referenced.add((referenced_object, referenced_object_location))
                        # for each tag used on a referenced object, add it to the used objects set
                        if referenced_object.tag:
                            for tag in referenced_object.tag:
                                referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_object_location, obj_type="tag")
                                group_obj_set.append((referenced_tag, referenced_tag_location))
            elif obj_type == "service":
                if group.value:
                    for s in group.value:
                        if s not in self._resolved_cache[members_location_base]['services']:
                            referenced_object, referenced_object_location = self.get_relative_object_location(s, members_location_base)
                            if type(referenced_object) == panos.objects.ServiceGroup:
                                group_obj_set += flatten_group(referenced_object, members_location_base, referenced_object_location, obj_type)
                            group_obj_set.append((referenced_object, referenced_object_location))
                            if referenced_object.tag:
                                for tag in referenced_object.tag:
                                    if not tag in self._resolved_cache[members_location_base]['tags']:
                                        referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_object_location, obj_type="tag")
                                        group_obj_set.append((referenced_tag, referenced_tag_location))

            # finally add the group itself to the objects set
            group_obj_set.append((group, group_location))
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
        self._resolved_cache[location_name] = dict({'addresses': list(), 'services': list(), 'tags': list()})
        # iterates on all rulebases for the concerned location
        for k, v in self._rulebases[location_name].items():
            if k == "context":
                # if the current key is 'context', pass (as it contains the DeviceGroup object instance)
                continue
            # for each rule in the current rulebase
            for r in v:
                if self._superverbose:
                    self._console.log(f"Processing used objects on rule {r.name}")
                try:
                    # for all objects, used either as source or destination
                    rule_objects = r.source + r.destination
                except AttributeError:
                    try:
                        rule_objects = r.source_addresses + r.destination_addresses
                    except AttributeError:
                        pass
                if 'nat' in k:
                    if r.source_translation_translated_addresses:
                        rule_objects += r.source_translation_translated_addresses
                    if r.destination_translated_address:
                        rule_objects.append(r.destination_translated_address)
                for obj in rule_objects:
                    # if the value is not 'any'
                    if obj != 'any' and obj not in self._resolved_cache[location_name]['addresses']:
                        if self._superverbose:
                            self._console.log(f"Looking for object {obj} used from location {location_name}")
                        # get the referenced object and its location (can be at same level or upward)
                        referenced_object, referenced_object_location = self.get_relative_object_location(obj, location_name)
                        if referenced_object and referenced_object_location:
                            self._console.log(f"Object {obj} used from location {location_name} found at {referenced_object_location}", style="green")
                            # if the referenced object is an AddressGroup, call the flatten method to get all members
                            if type(referenced_object) == panos.objects.AddressGroup:
                                if referenced_object.static_value:
                                    if self._superverbose:
                                        self._console.log(f"Object {obj} is a static group. Expanding members...", style="yellow")
                                    # if object is a static group, it can only use local or upward objects (base on the group location = referenced_object_location)
                                    #obj_ref_set += flatten_group(referenced_object, referenced_object_location, referenced_object_location)

                                    # TEST FOR SUPPORT OF MEMBERS OVERRIDING ON CHILD DEVICE-GROUPS
                                    # if one of the returned flattened_members is below the referenced_object_location
                                    # then it is overriding an existing member of the group, thus upward cannot be deleted
                                    # TODO : local one can be deleted if this is a copy of the upward one !!!
                                    flattened_members = flatten_group(referenced_object, location_name, referenced_object_location)
                                    for m, loc in flattened_members:
                                        # TODO : check if member is BELOW referenced_object_location
                                        if loc not in [referenced_object_location, 'shared']:
                                            self._console.log(f"Member {m.name} of group {referenced_object} is overriden below the group location. Protecting upward group members for deletion", style="red")
                                            # COMMENT 20012022
                                            # Find non-removable elements relatively to the group (so starting at the group level)
                                            # instead of finding it above the group usage location
                                            """
                                            upward_dg = self._stored_pano_hierarchy[location_name]
                                            if upward_dg is None:
                                                upward_dg = 'shared'
                                            if type(m) is AddressGroup:
                                                # call again flatten_group but with upper location to protect source group against deletion
                                                flattened_members += flatten_group(referenced_object, upward_dg, referenced_object_location)
                                            elif type(m) is AddressObject:
                                                obj_ref_set.append(self.get_relative_object_location(m.name, upward_dg))
                                            """
                                            if type(m) is AddressGroup:
                                                flattened_members += flatten_group(referenced_object, referenced_object_location, referenced_object_location)
                                            elif type(m) is AddressObject:
                                                obj_ref_set.append(self.get_relative_object_location(m.name, referenced_object_location))

                                    obj_ref_set += flattened_members
                                elif referenced_object.dynamic_value:
                                    if self._superverbose:
                                        self._console.log(f"Object {obj} is a dynamic group. Expanding members...", style="yellow")
                                    # if object is a dynamic group, it can reference all objects (upward or downward) starting by the location where the object is used (location_name)
                                    flattened_members = flatten_group(referenced_object, location_name, referenced_object_location)
                                    obj_ref_set += flattened_members

                                # Adding flattened group members to resolved cache
                                self._resolved_cache[location_name]['addresses'] += [x[0].name for x in flattened_members]

                            # Below is matched for both AddressGroups and AddressObjects
                            obj_ref_set.append((referenced_object, referenced_object_location))
                            self._resolved_cache[location_name]['addresses'].append(obj)
                            # for each tag used on the referenced object
                            if referenced_object.tag:
                                for tag in referenced_object.tag:
                                    if self._superverbose:
                                        self._console.log(f"Object {obj} uses tag {tag}. Trying to resolve it")
                                    if tag not in self._resolved_cache[location_name]['tags']:
                                        # get the referenced object's referenced tag and its location (can be same level or upward)
                                        referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_object_location, obj_type="tag")
                                        obj_ref_set.append((referenced_tag, referenced_tag_location))
                                    elif self._superverbose:
                                        self._console.log(f"Tag {tag} already resolved on current context ({location_name})", style="green")
                    elif obj != 'any' and obj in self._resolved_cache[location_name]['addresses'] and self._superverbose:
                        self._console.log(f"Object {obj} already resolved on current context ({location_name})", style="green")
                # for all objects used as tag directly on the rule
                if r.tag:
                    for tag in r.tag:
                        if tag not in self._resolved_cache[location_name]['tags']:
                            # get the referenced tag object and its location (can be at same level or upward)
                            referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, location_name, obj_type="tag")
                            obj_ref_set.append((referenced_tag, referenced_tag_location))
                            self._resolved_cache[location_name]['tags'].append(tag)
                        elif self._superverbose:
                            self._console.log(f"Tag {tag} already resolved on current context ({location_name})", style="green")
                if r.service:
                    # NAT rules will not sent a list as service, so need to be converted to list is not already
                    for service in [r.service] if isinstance(r.service, str) else r.service:
                        if service not in self._resolved_cache[location_name]['tags'] + ['application-default', 'any']:
                            if self._superverbose:
                                self._console.log(f"Looking for service {service} location")
                            referenced_service, referenced_service_location = self.get_relative_object_location(service, location_name, obj_type="service")
                            if type(referenced_service) == panos.objects.ServiceGroup:
                                if referenced_service.value:
                                    flattened_members = flatten_group(referenced_service, location_name, referenced_service_location, "service")
                                    for m, loc in flattened_members:
                                        if loc not in [referenced_service_location, 'shared']:
                                            upward_dg = self._stored_pano_hierarchy[location_name]
                                            if upward_dg is None:
                                                upward_dg = 'shared'
                                            if type(m) is ServiceGroup:
                                                flattened_members += flatten_group(referenced_service, upward_dg, referenced_service_location)
                                            elif type(m) is ServiceObject:
                                                obj_ref_set.append(self.get_relative_object_location(m.name, upward_dg))
                                    obj_ref_set += flattened_members
                            obj_ref_set.append((referenced_service, referenced_service_location))
                            self._resolved_cache[location_name]['services'].append(service)
                            if referenced_service.tag:
                                for tag in referenced_service.tag:
                                    if tag not in self._resolved_cache[location_name]['tags']:
                                        # get the referenced object's referenced tag and its location (can be same level or upward)
                                        referenced_tag, referenced_tag_location = self.get_relative_object_location(tag, referenced_service_location, obj_type="tag")
                                        obj_ref_set.append((referenced_tag, referenced_tag_location))
                                    else:
                                        print(f"############### Tag {tag} has already been resolved on the current context ({location_name})")
                        elif service != 'any' and service != 'application-default' and service in self._resolved_cache[location_name]['tags']:
                            print(f"############### Service {service} has already been resolved on the current context ({location_name})")
                progress.update(task, advance=1)
                time.sleep(2)
        # add the fetched objects set to the _used_objects_set dict
        self._used_objects_sets[location_name] = set(obj_ref_set)

    def hostify_address(self, address):
        """
        Submethod used to remove /32 at the end of an IP address
        :param address: (string) IP address to be modified
        :return: (string) Host IP address (instead of network /32)
        """

        # removing /32 mask for hosts
        if address[-3:] == '/32':
            return address[:-3:]
        return address

    def find_upward_obj_by_addr(self, base_location_name, obj_addr):
        """
        Find AddressObject having the same IP given as obj_addr at upper levels, starting at base_location_name level
        :param base_location_name: (string) Base location where to find objects upward
        :param obj_addr: (string) IP address of the objects for which we want to find duplicates at upper levels
        :return: (list) of tuples (AddressObject, location) of objects found on upper levels
        """

        # call to hostify_address submethod to remove /32 at the end
        obj_addr = self.hostify_address(obj_addr)
        # initialize the list which will contains found objects
        found_upward_objects = list()
        # find name of the parent device-group (related to base_location_name)
        upward_devicegroup = self._stored_pano_hierarchy.get(base_location_name)
        # if there's no parent, then parent is 'shared' level
        if not upward_devicegroup:
            upward_devicegroup = 'shared'
        # for each object existing at found upper evel
        for obj in self._addr_ipsearch[upward_devicegroup].get(obj_addr, list()):
            found_upward_objects.append((obj, upward_devicegroup))
        """
        for obj in self._objects[upward_devicegroup]['address_obj']:
            # if current object has the same IP address than the searched one
            if self.hostify_address(obj.value) == obj_addr:
                # add tuple for the found object to the found_upward_objects list
                found_upward_objects.append((obj, upward_devicegroup))
        """
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
        Will return the intermediate group replacement object if any

        :param obj_list: list((AddressObject, string)) List of tuples of AddressObject and location names
        :return:
        """
        if len (obj_list) == 1:
            return obj_list[0]
        # create a list of shared objects from the obj_list
        shared_obj = [x for x in obj_list if x[1] == 'shared']
        # create a list of intermediate DG objects from the obj_list
        interm_obj = [x for x in obj_list if x[1] != 'shared']
        # create a list of objects having name with multiple "." and ending with "corp" or "com" (probably FQDN)
        fqdn_obj = [x for x in obj_list if len(x[0].about()['name'].split('.')) > 1 and x[0].about()['name'].split('.')[-1] in ['corp', 'com']]
        # find objects being both shared and with FQDN-like naming
        shared_fqdn_obj = list(set(shared_obj) & set(fqdn_obj))
        interm_fqdn_obj = list(set(interm_obj) & set(fqdn_obj))

        # if shared and well-named objects are found, return the first one
        if shared_fqdn_obj:
            for o in shared_fqdn_obj:
                if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_fqdn_obj]:
                    return o
        if interm_fqdn_obj:
            return interm_fqdn_obj[0]
        # else return the first found shared object
        if shared_obj:
            for o in shared_obj:
                if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_obj]:
                    return o
        if interm_obj:
            return interm_obj[0]
        print(f"ERROR !!!!!! UNABLE TO CHOSE OBJECT IN LIST {obj_list}")

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
                    tag_instance, tag_location = self.get_relative_object_location(t, location_name, obj_type="tag")
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
                    replace_in_source_translation_translated_addresses = False
                    replace_in_destination_translated_address = False
                    # check if initial object needs to be replaced in rule source or destination
                    if ref_obj_name in r.source:
                        replace_in_source = True
                    if ref_obj_name in r.destination:
                        replace_in_destination = True
                    if 'nat' in l:
                        if r.source_translation_translated_addresses:
                            if ref_obj_name in r.source_translation_translated_addresses:
                                replace_in_source_translation_translated_addresses = True
                        if r.destination_translated_address:
                            if ref_obj_name == r.destination_translated_address:
                                replace_in_destination_translated_address = True
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
                    if replace_in_source_translation_translated_addresses:
                        r.source_translation_translated_addresses.remove(ref_obj_name)
                        r.destination.append(replacement_obj_name)
                    if replace_in_destination_translated_address:
                        r.destination_translated_address = replacement_obj_name
                    # apply change if anything has been changed
                    if replace_in_source or replace_in_destination or replace_in_source_translation_translated_addresses or replace_in_destination_translated_address:
                        if self._apply_cleaning:
                            r.apply()
            # fetch all AddressGroup objects for the concerned location
            # after checking that there are existing AddressGroups on this location
            if self._objects[location_name]['address_group']:
                for g in self._objects[location_name]['address_group']:
                    replace = False
                    # if reference to the initial object is found on the group members
                    if g.static_value:
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

    def gen_tree_depth(self, input_tree, start='shared', depth=1):
        """
        Submethod used to create a dict with the "depth" value for each device-group, depth for 'shared' being 0

        :param input_tree: (dict) Reversed PanoramaDeviceGroupHierarchy tree
        :param start: (string) Where to start for depth calculation (function being called recursively)
        :param depth: (int) Actual depth of analysis
        :return: (dict) Dict with keys being the depth of the devicegroups and value being list of device-group names
        """
        for loc in input_tree[start]:
            if depth not in self._depthed_tree.keys():
                self._depthed_tree[depth] = list()
            self._depthed_tree[depth].append(loc)
            self.gen_tree_depth(input_tree, loc, depth + 1)

    def remove_objects(self, analyzis_perimeter, delete_upward_objects):
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

        # Create a list for which the order will be the more "depth" device-groups first, then going up to 'shared'
        dg_clean_order = list()
        for key in sorted(self._depthed_tree.keys(), reverse=True):
            for dg in self._depthed_tree[key]:
                if dg in analyzis_perimeter['direct']:
                    dg_clean_order.append(dg)
                elif delete_upward_objects:
                    if dg in analyzis_perimeter['direct'] + analyzis_perimeter['indirect'] and dg in analyzis_perimeter['full']:
                        dg_clean_order.append(dg)
        print(f"Cleaning DG in the following order : {dg_clean_order} ")

        # for each device-group in the dg_clean_order list (starting with the more depthed)
        for k in dg_clean_order:
            print(f"Starting cleaning unused {k}")
            v = self._objects[k]
            # for each type of objects, in the cleaning_order order
            for obj_type in cleaning_order:
                for obj in v[obj_type]:
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

        #print(self._used_objects_sets)