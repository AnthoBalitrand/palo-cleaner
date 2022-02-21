import pan.xapi
from rich.console import Console
from rich.prompt import Prompt
from rich.tree import Tree
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
import panos.objects
from panos.panorama import Panorama, DeviceGroup, PanoramaDeviceGroupHierarchy
from panos.objects import AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, PreRulebase, PostRulebase, Rulebase, NatRule, AuthenticationRule, RulebaseHitCount
from panos.predefined import Predefined
from panos.errors import PanXapiError
from panos.firewall import Firewall
from panos.device import SystemSettings
import re
import time

repl_map = {
    SecurityRule: {
        "Address": [["source"], ["destination"]],
        "Service": [["service"]],
        "Tag": [["tag"]],
    },
    NatRule: {
        "Address": [["source"], ["destination"], ["source_translation_translated_addresses"], "destination_translated_address"],
        "Service": ["service"],
        "Tag": [["tag"]],
    },
    AuthenticationRule: {
        "Address": [["source_addresses"], ["destination_addresses"]],
        "Service": [["service"]],
        "Tag": [["tag"]],
    }
}


class PaloCleaner:
    def __init__(self, report_folder, **kwargs):
        self._panorama_url = kwargs['panorama_url']
        self._panorama_user = kwargs['api_user']
        self._panorama_password = kwargs['api_password']
        self._dg_filter = kwargs['device_groups']
        self._depthed_tree = dict({0: ['shared']})
        self._apply_cleaning = kwargs['apply_cleaning']
        self._tiebreak_tag = kwargs['tiebreak_tag']
        self._apply_tiebreak_tag = kwargs['apply_tiebreak_tag']
        self._no_report = kwargs['no_report']
        self._report_folder = report_folder
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
        self._superverbose = kwargs['superverbose']
        self._max_change_timestamp = int(time.time()) - int(kwargs['max_days_since_change']) * 86400 if kwargs['max_days_since_change'] else None
        self._max_hit_timestamp = int(time.time()) - int(kwargs['max_days_since_hit']) * 86400 if kwargs['max_days_since_hit'] else None
        self._need_opstate = self._max_change_timestamp or self._max_hit_timestamp
        self._console = Console(record=True if not self._no_report else False)
        self._replacements = dict()
        self._panorama_devices = dict()
        self._hitcounts = dict()

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
            self._panorama_password = Prompt.ask(f"Please provide the password for API user {self._panorama_user!r} ",
                                                 password=True)
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
                self._console.log("Unknown error occurred while connecting to Panorama", style="red")
                return 0

            status.update("Parsing device groups list")
            hierarchy_tree = self.generate_hierarchy_tree()
            time.sleep(1)
            self._console.log("Discovered hierarchy tree is the following :")
            self._console.log(
                "( [red] + are directly included [/red] / [yellow] * are indirectly included [/yellow] / [green] - are not included [/green] )")
            self._console.log(
                " F (Fully included = cleaned) / P (Partially included = not cleaned) "
            )
            self._console.log(Panel(hierarchy_tree))
            time.sleep(1)

        perimeter = [(dg.about()['name'], dg) for dg in self.get_devicegroups() if
                     dg.about()['name'] in self._analysis_perimeter['direct'] + self._analysis_perimeter['indirect']]

        with Progress(
                SpinnerColumn(spinner_name="dots12"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                TimeElapsedColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self._console,
                transient=True
        ) as progress:

            download_task = progress.add_task("", total=len(perimeter) + 1)

            progress.update(download_task, description="Downloading Panorama shared objects")
            self.fetch_objects(self._panorama, 'shared')
            self.fetch_objects(self._panorama, 'predefined')
            self._console.log(f"Panorama objects downloaded ({self.count_objects('shared')} found)")

            # calling a function which will make sure that the tiebreak-tag exists (if requested as argument)
            # and will create it if it does not
            self.validate_tiebreak_tag()

            progress.update(download_task, description="Downloading Panorama rulebases")
            self.fetch_rulebase(self._panorama, 'shared')
            self._console.log(f"Panorama rulebases downloaded ({self.count_rules('shared')} rules found)")

            progress.update(download_task, description="Downloading Panorama managed devices information")
            self.get_panorama_managed_devices()
            self._console.log(f"Panorama managed devices information downloaded (found {len(self._panorama_devices)} devices)")

            progress.update(download_task, advance=1)

            for (context_name, dg) in perimeter:
                progress.update(download_task, description=f"Downloading {context_name} objects")
                self.fetch_objects(dg, context_name)
                self._console.log(f"{context_name} objects downloaded ({self.count_objects(context_name)} found)")
                progress.update(download_task, description=f"Downloading {context_name} rulebases")
                self.fetch_rulebase(dg, context_name)
                self._console.log(f"{context_name} rulebases downloaded ({self.count_rules(context_name)} rules found)")
                # downloading hitcounts for leafs
                if self._need_opstate and not self._reversed_tree.get(context_name):
                    progress.update(download_task, description=f"Downloading {context_name} hitcounts (connecting to devices)")
                    self.fetch_hitcounts(dg, context_name)
                    self._console.log(f"{context_name} hit counts downloaded for all rulebases")

                progress.update(download_task, advance=1)

            progress.remove_task(download_task)

            shared_fetch_task = progress.add_task("Shared - Processing used objects location",
                                                  total=self.count_rules('shared'))
            self.fetch_address_obj_set("shared", progress, shared_fetch_task)
            self._console.log("shared used objects set processed")
            progress.remove_task(shared_fetch_task)

            for (context_name, dg) in perimeter:
                dg_fetch_task = progress.add_task(f"{dg.about()['name']} - Processing used objects location",
                                                  total=self.count_rules(dg.about()['name']))
                self.fetch_address_obj_set(dg.about()['name'], progress, dg_fetch_task)
                self._console.log(f"{dg.about()['name']} used objects set processed")
                progress.remove_task(dg_fetch_task)

            """
            # 26012022 - cleaning only leafs device groups (DG without childs)
            dg_to_clean = [context_name for context_name, dg in perimeter if not self._reversed_tree.get(context_name)]
            for context_name in dg_to_clean:
                dg_optimize_task = progress.add_task(f"{context_name} - Optimizing objects", total=len(self._used_objects_sets[context_name]))
                self.optimize_address_objects(context_name, progress, dg_optimize_task)
                self._console.log(f"{context_name} objects optimization done")
                self.replace_object_in_groups(context_name, progress, dg_optimize_task)
                self._console.log(f"{context_name} objects replaced in groups")
                self.replace_object_in_rulebase(context_name, progress, dg_optimize_task)
                self._console.log(f"{context_name} objects replaced in rulebases")
                self.clean_local_object_set(context_name, progress, dg_optimize_task)
                self._console.log(f"{context_name} used objects set cleaned")
                progress.remove_task(dg_optimize_task)
            """

            for depth in self._depthed_tree:
                for context_name in self._depthed_tree.get(depth):
                    if context_name in self._analysis_perimeter['direct'] + self._analysis_perimeter['indirect']:
                        # OBJECTS OPTIMIZATION
                        dg_optimize_task = progress.add_task(f"{context_name} - Optimizing objects", total=len(self._used_objects_sets[context_name]))
                        self.optimize_address_objects(context_name, progress, dg_optimize_task)
                        self._console.log(f"{context_name} objects optimization done")

                        # OBJECTS REPLACEMENT IN GROUPS
                        self.replace_object_in_groups(context_name, progress, dg_optimize_task)
                        self._console.log(f"{context_name} objects replaced in groups")

                        # OBJECTS REPLACEMENT IN RULEBASES
                        self.replace_object_in_rulebase(context_name, progress, dg_optimize_task)
                        self._console.log(f"{context_name} objects replaced in rulebases")

                        progress.remove_task(dg_optimize_task)

            #self.clean_local_object_set("shared", progress, None)
        # self.reverse_dg_hierarchy(self.get_pano_dg_hierarchy(), print_result=True)
        if not self._no_report:
            self._console.save_html(self._report_folder+'/report.html')

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

    def get_panorama_managed_devices(self):
        devices = self._panorama.refresh_devices(expand_vsys=False, include_device_groups=False)
        for fw in devices:
            if fw.state.connected:
                self._panorama_devices[getattr(fw, "serial")] = fw

    def generate_hierarchy_tree(self):
        """
        Reverses the PanoramaDeviceGroupHierarchy dict
        (permits to have list of childs for each parent, instead of parent for each child)

        :param pano_hierarchy: (dict) PanoramaDeviceGroupHierarchy fetch result
        :param print_result: (bool) To print or not the reversed hierarchy on stdout
        :return: (dict) Each key is a device-group name, the associated value is the list of child device-groups
        """
        self._analysis_perimeter = self.get_perimeter(self._reversed_tree)
        if 'shared' in self._analysis_perimeter['direct']:
            line_value = "+ "
            line_value += "F " if "shared" in self._analysis_perimeter['full'] else "P "
            line_value += "shared"
            hierarchy_tree = Tree(line_value, style="red")
        elif 'shared' in self._analysis_perimeter['indirect']:
            line_value = "* "
            line_value += "F " if "shared" in self._analysis_perimeter['full'] else "P "
            line_value += "shared"
            hierarchy_tree = Tree(line_value, style="yellow")

        # If print_result attribute is True, print the result on screen
        def add_leafs(tree, tree_branch, start='shared'):
            for k, v in self._reversed_tree.items():
                if k == start:
                    for d in v:
                        if d in self._analysis_perimeter['direct']:
                            line_value = "+ "
                            line_value += "F " if d in self._analysis_perimeter['full'] else "P "
                            line_value += d
                            leaf = tree_branch.add(line_value, style="red")
                        elif d in self._analysis_perimeter['indirect']:
                            line_value = "* "
                            line_value += "F " if d in self._analysis_perimeter['full'] else "P "
                            line_value += d
                            leaf = tree_branch.add(line_value, style="yellow")
                        else:
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
                        fully_included.append(dg)
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
            self._objects[location_name]['Service'] = [v for k, v in predef.service_objects.items()]
            # context object is stored on the dict for further usage
            self._objects[location_name]['context'] = context
            for obj_type in ['Address', 'Tag']:
                self._objects[location_name][obj_type] = list()
            self._service_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['Service']}
        else:
            # else download all objects types
            self._objects[location_name]['context'] = context
            self._objects[location_name]['Address'] = AddressObject.refreshall(context) + AddressGroup.refreshall(context)
            self._addr_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['Address']}
            if self._superverbose:
                self._console.log(f"  {location_name} objects namesearch structures initialized")
            self._addr_ipsearch[location_name] = dict()
            for obj in self._objects[location_name]['Address']:
                if type(obj) is panos.objects.AddressObject:
                    addr = self.hostify_address(obj.value)
                    if addr not in self._addr_ipsearch[location_name].keys():
                        self._addr_ipsearch[location_name][addr] = list()
                    self._addr_ipsearch[location_name][addr].append(obj)
            if self._superverbose:
                self._console.log(f"  {location_name} objects ipsearch structures initialized")
            self._objects[location_name]['Tag'] = Tag.refreshall(context)
            self._tag_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['Tag']}
            self._objects[location_name]['Service'] = ServiceObject.refreshall(context) + ServiceGroup.refreshall(context)
            self._service_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['Service']}
            if self._superverbose:
                self._console.log(f"  {location_name} services namesearch structures initialized")

    def fetch_rulebase(self, context, location_name):
        """
        Downloads rulebase for the requested context

        :param context: (Panorama or DeviceGroup) instance to be used for fetch operation
        :param location_name: (string) Name of the location (Panorama or DeviceGroup name)
        :return:
        """

        # create _rulebases[location] if not yet existing
        if location_name not in self._rulebases.keys():
            self._rulebases[location_name] = dict()

        self._rulebases[location_name]['context'] = context
        for ruletype in repl_map:

            rulebases = [PreRulebase(), PostRulebase()]
            if ruletype is SecurityRule:
                rulebases += [Rulebase()]

            for rb in rulebases:
                context.add(rb)
                self._rulebases[location_name][rb.__class__.__name__+"_"+ruletype.__name__] = \
                    ruletype.refreshall(rb, add=True)
                context.remove(rb)

    def fetch_hitcounts(self, context, location_name):
        dg_firewalls = Firewall.refreshall(context)
        rulebases = [x.__name__ for x in repl_map]
        interest_counters = ["last_hit_timestamp", "rule_modification_timestamp"]
        self._hitcounts[location_name] = ({x: dict() for x in rulebases})

        for fw in dg_firewalls:
            device = self._panorama_devices.get(getattr(fw, "serial"))
            if device:
                system_settings = device.find("", SystemSettings)
                fw_ip = system_settings.ip_address
                fw_vsys = getattr(fw, "vsys")
                fw_conn = Firewall(fw_ip, self._panorama_user, self._panorama_password, vsys=fw_vsys)
                print(f"Connecting to device {fw_ip} on vsys {fw_vsys} ({location_name})")
                rb = Rulebase()
                fw_conn.add(rb)
                for rulebase in rulebases:
                    ans = rb.opstate.hit_count.refresh(rulebase, all_rules=True)
                    for rule, counters in ans.items():
                        if not (res := self._hitcounts[location_name][rulebase].get(rule)):
                            self._hitcounts[location_name][rulebase][rule] = ({x: getattr(counters, x) for x in interest_counters})
                        else:
                            for ic in interest_counters:
                                self._hitcounts[location_name][rulebase][rule][ic] = max(getattr(res, ic), getattr(counters, ic))

    def validate_tiebreak_tag(self):
        """
        This function will check that the tiebreak tag exists (on shared context) if it has been requested
        If it does not exists, it will be created and added to the (already fetched) objects set for shared context
        :return:
        """

        if self._tiebreak_tag:
            if not self._tiebreak_tag in self._tag_namesearch['shared']:
                self._console.log(f"Creating tiebreak tag {self._tiebreak_tag} on shared context")
                tiebreak_tag = Tag(name=self._tiebreak_tag)
                self._objects['shared']['Tag'].append(tiebreak_tag)
                self._tag_namesearch['shared'][self._tiebreak_tag] = tiebreak_tag
                if self._apply_cleaning:
                    self._panorama.add(tiebreak_tag).create()

    def get_relative_object_location(self, obj_name, reference_location, obj_type="Address"):
        """
        Find referenced object by location (permits to get the referenced object on current location if
        existing at this level, or on upper levels of the device-groups hierarchy)
        TODO : find a way to block recursive call if already on the "shared" context

        :param obj_name: (string) Name of the object to find
        :param reference_location: (string) Where to start to find the object (device-group name or 'shared')
        :param obj_type: (string) Type of object to look for (default = AddressGroup or AddressObject)
        :return: (AddressObject, string) Found object (or group), and its location name
        """

        # self._console.log(f"Call to get_relative_object_location for {obj_name} (type {obj_type}) on {reference_location}")

        # Initialize return variables
        found_object = None
        found_location = None
        # For each object at the reference_location level, find any object having the searched name
        if obj_type == "Address":
            found_object = self._addr_namesearch[reference_location].get(obj_name, None)
            found_location = reference_location
        elif obj_type == "Tag":
            found_object = self._tag_namesearch[reference_location].get(obj_name, None)
            found_location = reference_location
        elif obj_type == "Service":
            found_object = self._service_namesearch[reference_location].get(obj_name, None)
            found_location = reference_location

        # if no object is found at current reference_location, find the upward device-group on the hierarchy
        # and call the current function recursively with this upward level as reference_location
        if not found_object and reference_location not in ['shared', 'predefined']:
            upward_dg = self._stored_pano_hierarchy[reference_location]
            if not upward_dg:
                upward_dg = 'shared'
            found_object, found_location = self.get_relative_object_location(obj_name, upward_dg, obj_type)
        elif not found_object and (obj_type == "Service" and reference_location == 'shared'):
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
        for obj in self._objects[reference_location]['Address']:
            # check if current object has tags
            if obj.tag:
                # print(f"Object {obj} has tags !!!!!! ({obj.tag})")
                # print(f"Condition is : {executable_condition!r}")
                # initialize dict which will contain the results of the executable_condition execution
                expr_result = dict()
                obj_tags = obj.tag
                # Execute the executable_condition with the locals() context
                exec(executable_condition, locals(), expr_result)
                cond_expr_result = expr_result['cond_expr_result']
                # If the current object tags matches the executable_condition, add it to found_objects
                if cond_expr_result:
                    # print(f"AND THOSE TAGS HAVE BEEN MATCHED")
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

        def shorten_object_type(object_type):
            return object_type.replace('Group', '').replace('Object', '')

        def flatten_object(used_object: panos.objects, object_location: str, usage_base: str,
                           referencer_type: str = None, referencer_name: str = None, recursion_level: int = 1, ):
            """
            Recursively called function, charged of returning the obj_set (list of (panos.objects, location)) for a given rule
            (first call is from a loop iterating over the different rules of a rulebase at a given location)

            Calls itself recursively for AddressGroups (static or dynamic)

            :param used_object: (panos.object) The used object (found with get_relative_object_location)
            :param object_location: (string) The location where the used objects has been found by get_relative_object_location
            :param usage_base: (string) The location where the object has been found used
            :param referencer_type: (string) The type (class.__name__) of the object where the reference to used_object has been found
            :param referencer_name: (string) The name of the where the reference to used_object has been found
            """

            obj_set = list()

            # If used_object has been resolved at the time of calling the flatten_object function, mark it as resolved (in cache) for the "usage_base" location (adding its name)
            # and add the (object, location) tuple to the obj_set list
            if not isinstance(used_object, type(None)):
                if self._superverbose:
                    self._console.log(
                        f"  {'*' * recursion_level} Marking {used_object.name!r} ({used_object.__class__.__name__}) as resolved on cache for location {usage_base}",
                        style="green italic")
                resolved_cache[usage_base][shorten_object_type(used_object.__class__.__name__)].append(
                    used_object.name)

                obj_set.append((used_object, object_location))

            # if the resolved object is a "simple" object (not needing recursive search), just display a log indicating that search is over
            if type(used_object) in [panos.objects.AddressObject, panos.objects.ServiceObject, panos.objects.Tag]:
                if self._superverbose:
                    self._console.log(
                        f"  {'*' * recursion_level} Object {used_object.name!r} ({used_object.__class__.__name__}) used on {usage_base!r} (ref by {referencer_type} {referencer_name}) has been found on location {object_location}",
                        style="green italic")

            # if the resolved object needs recursive search for members (AddressGroup), let's go
            elif type(used_object) is panos.objects.AddressGroup:
                # in case of a static group, just call the flatten_object function recursively for each member (which can be only at the group level or below)
                if used_object.static_value:
                    if self._superverbose:
                        self._console.log(
                            f"  {'*' * recursion_level} Object {used_object.name!r} (static AddressGroup) used on {usage_base!r} (ref by {referencer_type} {referencer_name!r}) has been found on location {object_location}",
                            style="green italic")
                    for group_member in used_object.static_value:
                        if group_member not in resolved_cache[usage_base]['Address']:
                            if self._superverbose:
                                self._console.log(
                                    f"  {'*' * recursion_level} Found group member of AddressGroup {used_object.name!r} : {group_member!r}",
                                    style="green italic")

                            obj_set += flatten_object(*self.get_relative_object_location(group_member,
                                                                                         usage_base),
                                                      usage_base, used_object.__class__.__name__, used_object.name,
                                                      recursion_level + 1)

                    # TODO : find a way to protect upward group members for modification if they are overriden below
                    """
                    # the condition below permits to "protect" the group members (at group level) if they are overriden at a lower location
                    if object_location != usage_base:
                        if self._superverbose:
                            self._console.log(
                                f"  {'*' * recursion_level} AddressGroup {used_object.name!r} location is different than referencer location ({usage_base}). Protecting group at its location level",
                                style="red italic")
                        obj_set += flatten_object(used_object, object_location, object_location, referencer_type,
                                                  referencer_name, recursion_level)
                    """

                # in case of a dynamic group, the group condition is converted to an executable Python statement, for members to be found using their tags
                # for dynamic groups, members can be at any location, upward starting from the usage_base location
                elif used_object.dynamic_value:
                    if self._superverbose:
                        self._console.log(
                            f"  {'*' * recursion_level} Object {used_object.name!r} (dynamic AddressGroup) used on {usage_base!r} (ref by {referencer_type} {referencer_name!r}) has been found on location {object_location}",
                            style="green italic")
                    executable_condition = gen_condition_expression(used_object.dynamic_value, "obj_tags")
                    for referenced_object, referenced_object_location in self.get_relative_object_location_by_tag(
                            executable_condition, usage_base):
                        if self._superverbose:
                            self._console.log(
                                f"  {'*' * recursion_level} Found group member of dynamic AddressGroup {used_object.name!r} : {referenced_object.name!r}",
                                style="green italic")
                        if referenced_object.name not in resolved_cache[usage_base]['Address']:
                            obj_set += flatten_object(referenced_object, referenced_object_location, usage_base,
                                                      used_object.__class__.__name__, used_object.name,
                                                      recursion_level + 1)
                            self._tag_referenced.add((referenced_object, referenced_object_location))
                        else:
                            if self._superverbose:
                                self._console.log(
                                    f"  {'*' * recursion_level} Address Object {referenced_object.name!r} already resolved in context {usage_base}",
                                    style="yellow")

            # do the same with ServiceGroups than for static AddressGroups
            elif type(used_object) is panos.objects.ServiceGroup:
                if used_object.value:
                    if self._superverbose:
                        self._console.log(
                            f"  {'*' * recursion_level} Object {used_object.name!r} (ServiceGroup) used on {usage_base} has been found on location {object_location}")
                    for group_member in used_object.value:
                        if group_member not in resolved_cache[usage_base]['Service']:
                            if self._superverbose:
                                self._console.log(
                                    f"  {'*' * recursion_level} Found group member of ServiceGroup {used_object.name} : {group_member}")
                            obj_set += flatten_object(*self.get_relative_object_location(group_member, usage_base),
                                                      usage_base, used_object.__class__.__name__, used_object.name,
                                                      recursion_level + 1)

            # checking if the resolved objects has tags (which needs to be added to the used_object_set too)
            # checking is used_object is not None permits to avoid cases where unsupported objects are used on the rule
            # IE : EDL at the time of writing this comment

            if not isinstance(used_object, type(None)):
                if type(used_object) is not panos.objects.Tag:
                    if used_object.tag:
                        for tag in used_object.tag:
                            if self._superverbose:
                                self._console.log(
                                    f"  {'*' * recursion_level} Object {used_object.name} ({used_object.__class__.__name__}) uses tag {tag}",
                                    style="green italic")
                            if tag not in resolved_cache[usage_base]['Tag']:
                                obj_set += flatten_object(
                                    *self.get_relative_object_location(tag, object_location, obj_type="tag"),
                                    usage_base, used_object.__class__.__name__, used_object.name)

            return obj_set

        location_obj_set = list()
        resolved_cache = dict()
        resolved_cache[location_name] = dict({'Address': list(), 'Service': list(), 'Tag': list()})
        ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$')
        range_regex = re.compile(r'^((\d{1,3}\.){3}\d{1,3}-?){2}$')

        # iterates on all rulebases for the concerned location
        for k, v in self._rulebases[location_name].items():
            if k == "context":
                # if the current key is 'context', pass (as it contains the DeviceGroup object instance)
                continue
            # for each rule in the current rulebase
            for r in v:
                if self._superverbose:
                    self._console.log(f"[{location_name}] Processing used objects on rule {r.name!r}")

                rule_objects = {x: [] for x in repl_map.get(type(r))}

                for obj_type, obj_fields in repl_map.get(type(r)).items():
                    for field in obj_fields:
                        if type(field) is str:
                            if (to_add := getattr(r, field)):
                                rule_objects[obj_type].append(to_add)
                        else:
                            if (to_add := getattr(r, field[0])):
                                rule_objects[obj_type] += to_add

                    for obj in rule_objects[obj_type]:
                        if obj != 'any' and obj not in resolved_cache[location_name][obj_type]:
                            location_obj_set += (
                                flattened := flatten_object(*self.get_relative_object_location(obj, location_name, obj_type),
                                                            location_name, r.__class__.__name__, r.name)
                            )

                            # matched if the object used has not been found by the get_relative_object_location
                            # (flatten object will not return anything in such a case)
                            if not flattened:
                                # can be in case of an IP address / subnet directly used on a rule
                                if obj_type == "Address":
                                    if ip_regex.match(obj) or range_regex.match(obj):
                                        location_obj_set += [(AddressObject(name=obj, value=obj), location_name)]
                                        self._console.log(
                                            f"  * Created AddressObject for address {obj} used on rule {r.name!r}",
                                            style="yellow")

                                    # else for any type of un-supported object type
                                    else:
                                        self._console.log(
                                            f"  * Un-supported object type seems to be used on rule {r.name!r} ({obj})",
                                            style="red")
                                elif obj_type == "Service":
                                    if not obj == "application-default":
                                        self._console.log(
                                            f"  * Un-supported object type seems to be used on rule {r.name!r} ({obj})",
                                            style="red")
                                else:
                                    self._console.log(
                                        f"  * Un-supported object type seems to be used on rule {r.name!r} ({obj})",
                                        style="red")
                        elif obj != 'any':
                            if self._superverbose:
                                self._console.log(f" * {obj_type} Object {obj!r} already resolved in context {location_name}",
                                                  style="yellow")

                progress.update(task, advance=1)

        self._used_objects_sets[location_name] = set(location_obj_set)

    def hostify_address(self, address):
        """
        Used to remove /32 at the end of an IP address
        :param address: (string) IP address to be modified
        :return: (string) Host IP address (instead of network /32)
        """

        # removing /32 mask for hosts
        if address[-3:] == '/32':
            return address[:-3:]
        return address

    def find_upward_obj_by_addr(self, base_location_name, obj_addr):
        obj_addr = self.hostify_address(obj_addr)
        found_upward_objects = list()
        current_location_search = base_location_name
        reached_max = False
        while not reached_max:
            if current_location_search == "shared":
                reached_max = True
            for obj in self._addr_ipsearch[current_location_search].get(obj_addr, list()):
                found_upward_objects.append((obj, current_location_search))
            current_location_search = self._stored_pano_hierarchy.get(current_location_search)
            if not current_location_search:
                current_location_search = "shared"

        return found_upward_objects

    def find_upward_obj_by_addr2(self, base_location_name, obj_addr):
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
        # for each object existing at found upper level
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

    def find_upward_obj_static_group(self, base_location_name, obj_group):
        found_upward_objects = list()
        upward_devicegroup = self._stored_pano_hierarchy.get(base_location_name)
        if not upward_devicegroup:
            upward_devicegroup = 'shared'
        for obj in self._objects[upward_devicegroup]['Address']:
            if type(obj) is panos.objects.AddressGroup:
                if obj.static_value:
                    if sorted(obj.static_value) == sorted(obj_group.static_value):
                        found_upward_objects.append((obj, upward_devicegroup))

        if upward_devicegroup != 'shared':
            found_upward_objects += self.find_upward_obj_static_group(upward_devicegroup, obj_group)

        return found_upward_objects

    def find_upward_obj_group(self, base_location_name, obj_group):
        found_upward_objects = list()
        upward_devicegroup = self._stored_pano_hierarchy.get(base_location_name)
        if not upward_devicegroup:
            upward_devicegroup = 'shared'
        for obj in self._objects[upward_devicegroup]['Address']:
            if type(obj) is panos.objects.AddressGroup:
                if obj_group.static_value and obj.static_value:
                    if sorted(obj.static_value) == sorted(obj_group.static_value):
                        found_upward_objects.append((obj, upward_devicegroup))
                elif obj_group.dynamic_value and obj.dynamic_value:
                    if obj_group.dynamic_value == obj.dynamic_value:
                        found_upward_objects.append((obj, upward_devicegroup))

        if upward_devicegroup != 'shared':
            found_upward_objects += self.find_upward_obj_group(upward_devicegroup, obj_group)

        return found_upward_objects


    def find_best_replacement_addr_obj(self, obj_list, base_location):
        """
        Get a list of tuples (object, location) and returns the best to be used based on location and naming criterias
        TODO : WARNING, can have unpredictable results with nested device-groups
        Will return the intermediate group replacement object if any

        :param obj_list: list((AddressObject, string)) List of tuples of AddressObject and location names
        :return:
        """
        choosen_object = None
        choosen_by_tiebreak = False
        if len(obj_list) == 1:
            choosen_object = obj_list[0]
            if self._superverbose:
                self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as there's no other existing for value {choosen_object[0].value}")
        else:
            if self._tiebreak_tag:
                for o in obj_list:
                    if not choosen_object:
                        try:
                            if self._tiebreak_tag in o[0].tag:
                                choosen_object = o
                            if self._superverbose:
                                self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen by tiebreak")
                        except:
                            pass
            if not choosen_object:
                # create a list of shared objects from the obj_list
                shared_obj = [x for x in obj_list if x[1] == 'shared']
                # create a list of intermediate DG objects from the obj_list
                interm_obj = [x for x in obj_list if x[1] != 'shared' and x[1] != base_location]
                # create a list of objects having name with multiple "." and ending with "corp" or "com" (probably FQDN)
                fqdn_obj = [x for x in obj_list if
                            len(x[0].about()['name'].split('.')) > 1 and x[0].about()['name'].split('.')[-1] in ['corp', 'com']]
                # find objects being both shared and with FQDN-like naming
                shared_fqdn_obj = list(set(shared_obj) & set(fqdn_obj))
                interm_fqdn_obj = list(set(interm_obj) & set(fqdn_obj))

                # if shared and well-named objects are found, return the first one
                if shared_fqdn_obj and not choosen_object:
                    for o in shared_fqdn_obj:
                        if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_fqdn_obj]:
                            choosen_object = o
                            if self._superverbose:
                                self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object with FQDN naming")
                if interm_fqdn_obj and not choosen_object:
                    choosen_object = interm_fqdn_obj[0]
                    if self._superverbose:
                        self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object with FQDN naming")
                # else return the first found shared object
                if shared_obj and not choosen_object:
                    for o in shared_obj:
                        if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_obj]:
                            choosen_object = o
                            if self._superverbose:
                                self._console.log(f"Object {o[0].about()['name']} (context {o[1]}) choosen as it's a shared object")
                if interm_obj and not choosen_object:
                    choosen_object = interm_obj[0]
                    if self._superverbose:
                        self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object")
        if not choosen_object:
            print(f"ERROR !!!!!! UNABLE TO CHOSE OBJECT IN LIST {obj_list}")
        else:
            if self._apply_tiebreak_tag and not choosen_by_tiebreak:
                tag_changed = False
                if choosen_object[0].tag:
                    if not self._tiebreak_tag in choosen_object[0].tag:
                        choosen_object[0].tag.append(self._tiebreak_tag)
                        tag_changed = True
                else:
                    choosen_object[0].tag = [self._tiebreak_tag]
                    tag_changed = True
                if self._superverbose and tag_changed:
                    self._console.log(f"Adding tiebreak tag {self._tiebreak_tag} to {choosen_object[0].__class__.__name__} {choosen_object[0].about()['name']} on context {choosen_object[1]} ")
                if self._apply_cleaning and tag_changed:
                    choosen_object[0].apply()

        return choosen_object

    def optimize_address_objects(self, location_name, progress, task):
        """
        Start object optimization processing for device-group given as argument

        :param location_name: (string) Location where to start objects optimization
        :return:
        """

        # for each object and location found on the _used_objects_set for the current location
        self._replacements[location_name] = {'Address': dict(), 'Service': dict(), 'Tag': dict()}
        for obj_type in [panos.objects.AddressObject, panos.objects.AddressGroup]:
            # TODO : check performance of the following statement
            for (obj, location) in [(o, l) for (o, l) in self._used_objects_sets[location_name] if type(o) is obj_type]:
                # if the current object type is AddressObject and exists at the current location level
                # TODO : find objects at upward locations even if the used object is not local (can be at an intermediate level)
                # TODO 2 : processing for both types of objects can probably be merged
                if type(obj) == panos.objects.AddressObject and location == location_name:
                    # find similar objects (same IP address) on upper level device-groups (including 'shared')
                    upward_objects = self.find_upward_obj_by_addr(location_name, obj.value)
                    # if upward duplicate objects are found
                    if len(upward_objects) > 1:
                        # find which one is the best to use
                        replacement_obj, replacement_obj_location = self.find_best_replacement_addr_obj(upward_objects, location_name)
                        #if replacement_obj != obj and replacement_obj_location != location:
                        if replacement_obj != obj:
                            # print(f"Object {obj.about()['name']} ({obj.value}) can be replaced by {replacement_obj[0].about()['name']} ({replacement_obj[0].value}) on {replacement_obj[1]}")
                            #print(
                            #    f"[{location_name}] Replacing ({obj}, {location}) --by--> ({replacement_obj.about()['name']}, {replacement_obj_location})")
                            if self._superverbose:
                                self._console.log(f"   * Replacing {obj.about()['name']} ({obj.__class__.__name__}) at location {location_name} by {replacement_obj.about()['name']} at location {replacement_obj_location}", style="green italic")
                            # call replace_object method with current object and the one with which to replace it
                            #self.replace_object(location_name, (obj, location), (replacement_obj, replacement_obj_location))
                            #self.replace_object_in_groups(location_name, (obj, location), (replacement_obj, replacement_obj_location))
                            self._replacements[location_name]['Address'][obj.about()['name']] = {
                                'source': (obj, location),
                                'replacement': (replacement_obj, replacement_obj_location),
                                'blocked': False
                            }
                elif type(obj) == panos.objects.AddressGroup and location == location_name:
                    upward_objects = self.find_upward_obj_group(location_name, obj)
                    if upward_objects:
                        replacement_obj, replacement_obj_location = upward_objects[0]
                        self._console.log(
                            f"   Replacing {obj.about()['name']} ({obj.__class__.__name__}) at location {location_name} by {replacement_obj.about()['name']} at location {replacement_obj_location}")
                        self._replacements[location_name]['Address'][obj.about()['name']] = {
                            'source': (obj, location),
                            'replacement': (replacement_obj, replacement_obj_location),
                            'blocked': False
                        }
                progress.update(task, advance=1)

    def replace_object_in_groups(self, location_name, progress, task):
        replacements_done = dict()

        for replacement_name, replacement in self._replacements[location_name]['Address'].items():
            source_obj = replacement_name
            source_obj_instance, source_obj_location = replacement['source']
            replacement_obj_instance, replacement_obj_location = replacement['replacement']

            if source_obj in self._tag_referenced:
                for tag in source_obj_instance.tag:
                    if not [x for x in self._objects['shared']['Tag'] if x.name == tag]:
                        # tag used on referenced object does not exists as shared, so create it
                        tag_instance, tag_location = self.get_relative_object_location(tag, location_name, obj_type="tag")
                        self._console.log(f"   [shared] Creating tag {tag!r} (copy from {tag_location}), to be used on ({replacement_obj_instance.about()['name']} at location {replacement_obj_location})")
                        if self._apply_cleaning:
                            try:
                                self._panorama.add(tag_instance).create()
                            except Exception as e:
                                self._console.log(f"    [shared] Error while creating tag {tag!r} ! : {e.message}", style="red")
                        self._objects['shared']['Tag'].append(tag_instance)
                        self._used_objects_sets['shared'].add((tag_instance, 'shared'))
                    self._console.log(f"    [{replacement_obj_location}] Adding tag {tag} to object {replacement_obj_instance.about()['name']!r} ({replacement_obj_instance.__class__.__name__})", style="yellow italic")
                    replacement_obj_instance.tag.append(tag)
                    if self._apply_cleaning:
                        replacement_obj_instance.apply()

            # replacing object on current location static groups
            for checked_object in self._objects[location_name]['Address']:
                if type(checked_object) is panos.objects.AddressGroup and checked_object.static_value:
                    changed = False
                    matched = False
                    try:
                        if source_obj_instance.about()['name'] != replacement_obj_instance.about()['name']:
                            checked_object.static_value.remove(source_obj_instance.about()['name'])
                            checked_object.static_value.append(replacement_obj_instance.about()['name'])
                            changed = True
                            matched = True
                        elif source_obj_instance.about()['name'] in checked_object.static_value:
                            matched = True

                        if matched:
                            self._console.log(f"    [{location_name}] Replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r} on {checked_object.about()['name']!r} ({checked_object.__class__.__name__})", style="yellow italic")
                            if checked_object.name not in replacements_done:
                                replacements_done[checked_object.name] = list()
                            replacements_done[checked_object.name].append((source_obj_instance.about()['name'], replacement_obj_instance.about()['name']))
                    except ValueError:
                        continue
                    except Exception as e:
                        self._console.log(f"    [{location_name}] Unknown error while replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r} on {checked_object.about()['name']!r} ({checked_object.__class__.__name__}) : {e.message}", style="red")
                    if self._apply_cleaning and changed:
                        checked_object.apply()

        for changed_group_name in replacements_done:
            group_table = Table(style="dim", border_style="not dim", expand=False)
            group_table.add_column(changed_group_name)
            for replaced_item in replacements_done[changed_group_name]:
                if replaced_item[0] != replaced_item[1]:
                    group_table.add_row(f"[red]- {replaced_item[0]}[/red]")
                    group_table.add_row(f"[green]+ {replaced_item[1]}[/green]")
                else:
                    group_table.add_row(f"[yellow]! {replaced_item[0]}[/yellow]")
            self._console.log(group_table)

    def replace_object_in_rulebase(self, location_name, progress, task):
        ruletype_fields_map = {x: list() for x in repl_map}
        for ruletype in ruletype_fields_map:
            for obj_type, fields in repl_map.get(ruletype).items():
                for f in fields:
                    ruletype_fields_map[ruletype].append(f[0] if type(f) is list else f)

        tab_headers = dict()
        for rule_type in repl_map:
            tab_headers[rule_type.__name__] = ['Name']
            for field_type, field_names in repl_map[rule_type].items():
                for field in field_names:
                    tab_headers[rule_type.__name__].append(field[0] if type(field) is list else field)
            tab_headers[rule_type.__name__] += ["rule_modification_timestamp", "last_hit_timestamp", "changed"]

        def replace_in_rule(rule):
            replacements_done = dict()
            replacements_count = 0
            # this field counts the highest number of replacements on a given field, for the loop which will display
            # the replacements in a Table object
            max_replace = 0
            for obj_type in repl_map.get(type(rule)):
                replacements_done[obj_type] = dict()
                for field_name in [x[0] if type(x) is list else x for x in repl_map[type(rule)][obj_type]]:
                    replacements_done[obj_type][field_name] = list()
                    current_field_replacements_count = 0
                    # TODO : adapt check to field type (not list ??)
                    if (not_null_field := getattr(rule, field_name)):
                        for o in not_null_field:
                            if (replacement := self._replacements[location_name][obj_type].get(o)):
                                #source obj_instance, source_obj_location = replacement['source']
                                replacement_obj_instance, replacement_obj_location = replacement['replacement']
                                if o != (repl_name := replacement_obj_instance.about()['name']):
                                    # replacement type 2 = removed
                                    # replacement type 3 = added
                                    replacements_done[obj_type][field_name].append((o, 2))
                                    replacements_done[obj_type][field_name].append((repl_name, 3))
                                    current_field_replacements_count += 2
                                else:
                                    # replacement type 1 = same name different location
                                    replacements_done[obj_type][field_name].append((o, 1))
                                    current_field_replacements_count += 1
                                replacements_count += 1
                            else:
                                # replacement type 0 = no replacement
                                replacements_done[obj_type][field_name].append((o, 0))
                                current_field_replacements_count += 1
                    if current_field_replacements_count > max_replace:
                        max_replace = current_field_replacements_count
            return replacements_done, replacements_count, max_replace

        def format_for_table(repl_name, repl_type):
            type_map = {0: '', 1: 'yellow', 2: 'red', 3: 'green'}
            action_map = {0: ' ', 1: '!', 2: '-', 3: '+'}
            formatted_return = f"[{type_map[repl_type]}]" if repl_type > 0 else ""
            formatted_return += f"{action_map[repl_type]} {repl_name}"
            formatted_return += f"[/{type_map[repl_type]}]" if repl_type > 0 else ""
            return formatted_return

        for rulebase_name, rulebase in self._rulebases[location_name].items():
            if rulebase_name != "context" and len(rulebase) > 0:
                total_replacements = 0
                hitcount_rb_name = rulebase_name.split('_')[1]

                rulebase_table = Table(
                    title=f"{location_name} : {rulebase_name} (len : {len(rulebase)})",
                    style="dim",
                    border_style="not dim",
                    expand=True)

                for c_name in tab_headers[rulebase_name.split('_')[1]]:
                    rulebase_table.add_column(c_name)

                for r in rulebase:
                    in_timestamp_boundaries = False
                    replacements_in_rule, replacements_count, max_replace = replace_in_rule(r)
                    if replacements_count:
                        total_replacements += replacements_count

                        # if rule is disabled or if the job does not needs to rely on rule timestamps
                        # or if the hitcounts for a rule cannot be found (ie : new rule not yet pushed on device)
                        # then just consider that the rule can be modified (in_timestamp_boundaries = True)
                        if r.disabled or not self._need_opstate or not (rule_counters := self._hitcounts.get(location_name, dict()).get(hitcount_rb_name, dict()).get(r.name)):
                            in_timestamp_boundaries = True
                            rule_modification_timestamp = 0 if self._need_opstate else "N/A"
                            last_hit_timestamp = 0 if self._need_opstate else "N/A"
                        else:
                            rule_modification_timestamp = rule_counters.get('rule_modification_timestamp')
                            last_hit_timestamp = rule_counters.get('last_hit_timestamp')
                            # if the rule last modification and last hit timestamps are above the minimums requested,
                            # then consider that it can be updated (in_timestamp_boundaries = True)
                            if rule_modification_timestamp > self._max_change_timestamp and last_hit_timestamp > self._max_hit_timestamp:
                                in_timestamp_boundaries = True
                            # else, for each object used on the rule, protect them to make sure they'll not be deleted later by the job
                            else:
                                for obj_type, fields in repl_map[type(r)].items():
                                    for f in [x[0] if type(x) is list else x for x in fields]:
                                        for object_name in getattr(r, f):
                                            if object_name in self._replacements[location_name][obj_type]:
                                                self._replacements[location_name][obj_type][object_name]["blocked"] = True

                        for table_add_loop in range(max_replace):
                            row_values = list()
                            row_values.append(r.name if table_add_loop == 0 else ""),
                            for obj_type, fields in repl_map.get(type(r)).items():
                                for f in [x[0] if type(x) is list else x for x in fields]:
                                    row_values.append(format_for_table(*replacements_in_rule[obj_type][f][table_add_loop]) if table_add_loop < len(replacements_in_rule[obj_type][f]) else "")
                            row_values.append(str(rule_modification_timestamp) if table_add_loop == 0 else "")
                            row_values.append(str(last_hit_timestamp) if table_add_loop == 0 else "")
                            row_values.append("Y" if in_timestamp_boundaries else "N")
                            rulebase_table.add_row(*row_values, end_section=True if table_add_loop == max_replace - 1 else False)

                if total_replacements:
                    self._console.log(rulebase_table)

    def clean_local_object_set(self, location_name, progress, task):
        for type in self._replacements.get(location_name, list()):
            for name, infos in self._replacements[location_name][type].items():
                if not infos['blocked']:
                    try:
                        self._used_objects_sets[location_name].remove(infos['source'])
                        if self._superverbose:
                            self._console.log(f"[{location_name}] Removing object {name} (location {infos['source'][1]}) from used objects set")
                    except ValueError:
                        self._console.log(
                            f"ValueError when trying to remove {name} from used objects sets at location {location_name} : object not found on object set")
                    except:
                        self._console.log(
                            f"Unknown Error when trying to remove {name} from used objects sets at location {location_name}")
                else:
                    self._console.log(f"Not removing {name} as it is blocked by hitcounts at location {location_name}")

        for type in self._objects[location_name]:
            if type != "context":
                for o in self._objects[location_name][type]:
                    if not (o, location_name) in self._used_objects_sets[location_name]:
                        self._console.log(f"Object {o.name} ({o.__class__.__name__}) can be deleted at location {location_name}")


    def replace_object(self, location_name, ref_obj, replacement_obj):
        """
        Method in charge of replacing an object wherever it is used on rulebases and groups at a defined location
        TODO : handle deletion of tags when replaced by shared ones

        :param location_name: (string) Name of the location where the object has been seen used
        :param ref_obj: ((AddressObject, string)) To-be-replaced object instance and its location name
        :param replacement_obj: ((AddressObject, string)) Replacement object instance and its location name
        :return:
        """
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
                print(
                    f"[{replacement_obj_location}] Adding tag {t} to ({replacement_obj_name}, {replacement_obj_location})")
                replacement_obj_instance.tag.append(t)
                if self._apply_cleaning:
                    replacement_obj_instance.apply()
        """
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
                        # print(f"{ref_obj_name} (inherited from {ref_obj_location}) has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on rule {r.name} as source")
                    # if object reference needs to be replacent on current rule destination, remove initial reference and add new one
                    if replace_in_destination:
                        r.destination.remove(ref_obj_name)
                        r.destination.append(replacement_obj_name)
                        print(f"    -- Replaced as destination on rule {r.name}")
                        # print(f"{ref_obj_name} (inherited from {ref_obj_location}) has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on rule {r.name} as destination")
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
                            # print(f"{ref_obj_name} (inherited from {ref_obj_location} has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on group {g.name}")
                            # apply change if anything ha been changed
                            if self._apply_cleaning:
                                g.apply()
        # if initial object and replacement objects have the same name, deleting the initial object will make the reference
        # directly pointing to the replacement object
        else:
            print(f"    -- Can be deleted as chosen replacement object has the same name")
            # print(f"{ref_obj_name} (inherited from {ref_obj_location}) can be deleted and will be directly replaced by same-name object {replacement_obj_name} (inherited from {replacement_obj_location})")
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
                    if dg in analyzis_perimeter['direct'] + analyzis_perimeter['indirect'] and dg in analyzis_perimeter[
                        'full']:
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

        # print(self._used_objects_sets)
