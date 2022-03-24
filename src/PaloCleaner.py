import pan.xapi
import rich.progress
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

"""
Below is a representation of the different types of rules being processed, and for each of them, the name of each 
field (+ format : string "" or ["list"]) containing each type of object 
"""

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
        """
        PaloCleaner class initialization function

        :param report_folder: (string) The path to the folder where to store the operation report
        :param kwargs: (dict) Dict of arguments provided by argparse
        """

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
        self._service_valuesearch = dict()
        self._used_objects_sets = dict()
        self._rulebases = dict()
        self._stored_pano_hierarchy = None
        self._removable_objects = list()
        self._tag_referenced = set()
        self._superverbose = kwargs['superverbose']
        self._max_change_timestamp = int(time.time()) - int(kwargs['max_days_since_change']) * 86400 if kwargs['max_days_since_change'] else 0
        self._max_hit_timestamp = int(time.time()) - int(kwargs['max_days_since_hit']) * 86400 if kwargs['max_days_since_hit'] else 0
        self._need_opstate = self._max_change_timestamp or self._max_hit_timestamp
        self._console = Console(record=True if not self._no_report else False)
        self._replacements = dict()
        self._panorama_devices = dict()
        self._hitcounts = dict()
        self._cleaning_counts = dict()

    def start(self):
        """
        First function called after __init__, which starts the processing

        :return:
        """
        header_text = Text("""

  ___      _        ___ _                       
 | _ \__ _| |___   / __| |___ __ _ _ _  ___ _ _ 
 |  _/ _` | / _ \ | (__| / -_) _` | ' \/ -_) '_|
 |_| \__,_|_\___/  \___|_\___\__,_|_||_\___|_|  
                                                
        by Anthony BALITRAND v1.0                                           

""")
        self._console.print(header_text, style="green", justify="left")

        # if the API user password has not been provided within the CLI start command, prompt the user
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

            # get the full device-groups hierarchy and displays is in the console with color code to identity which
            # device-groups will be concerned by the cleaning process

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

        # "perimeter" is a list containing the name only of each device-group included in the cleaning process
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
                transient=True,
                disable=self._console.record
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

                # if opstate (hit counts) has to be cared, download on each device member of the device-group
                # if this device-group has no child device-group
                if self._need_opstate and not self._reversed_tree.get(context_name):
                    progress.update(
                        download_task,
                        description=f"Downloading {context_name} hitcounts (connecting to devices)"
                    )
                    self.fetch_hitcounts(dg, context_name)
                    self._console.log(f"{context_name} hit counts downloaded for all rulebases")

                progress.update(download_task, advance=1)

            progress.remove_task(download_task)

            # Processing used objects set at location "shared"
            shared_fetch_task = progress.add_task("Shared - Processing used objects location",
                                                  total=self.count_rules('shared'))
            self.fetch_used_obj_set("shared", progress, shared_fetch_task)
            self._console.log("shared used objects set processed")
            progress.remove_task(shared_fetch_task)

            # Processing used objects set for each location included in the analysis perimeter
            for (context_name, dg) in perimeter:
                dg_fetch_task = progress.add_task(
                    f"{dg.about()['name']} - Processing used objects location",
                    total=self.count_rules(dg.about()['name'])
                )
                self.fetch_used_obj_set(dg.about()['name'], progress, dg_fetch_task)
                self._console.log(f"{dg.about()['name']} used objects set processed")
                progress.remove_task(dg_fetch_task)

            # Starting objects usage optimization
            # From the most "deep" device-group (far from shared), going up to the shared location
            for depth, contexts in sorted(self._depthed_tree.items(), key=lambda x: x[0], reverse=True):
                for context_name in contexts:
                    if context_name in self._analysis_perimeter['direct'] + self._analysis_perimeter['indirect']:
                        # OBJECTS OPTIMIZATION
                        dg_optimize_task = progress.add_task(
                            f"{context_name} - Optimizing objects",
                            total=len(self._used_objects_sets[context_name])
                        )
                        self.optimize_objects(context_name, progress, dg_optimize_task)
                        self._console.log(f"{context_name} objects optimization done")
                        progress.remove_task(dg_optimize_task)

                        # OBJECTS REPLACEMENT IN GROUPS
                        dg_replaceingroups_task = progress.add_task(
                            f"{context_name} - Replacing objects in groups",
                            total=len(self._replacements[context_name]['Address'])
                        )
                        self.replace_object_in_groups(context_name, progress, dg_replaceingroups_task)
                        self._console.log(f"{context_name} objects replaced in groups")
                        progress.remove_task(dg_replaceingroups_task)

                        # OBJECTS REPLACEMENT IN RULEBASES
                        dg_replaceinrules_task = progress.add_task(
                            f"{context_name} - Replacing objects in rules",
                            total=self.count_rules(context_name)
                        )
                        self.replace_object_in_rulebase(context_name, progress, dg_replaceinrules_task)
                        self._console.log(f"{context_name} objects replaced in rulebases")
                        progress.remove_task(dg_replaceinrules_task)

                        # OBJECTS CLEANING (FOR FULLY INCLUDED DEVICE GROUPS ONLY)
                        if context_name in self._analysis_perimeter['full']:
                            self.clean_local_object_set(context_name, progress, dg_optimize_task)
                            self._console.log(f"{context_name} objects cleaned (fully included)")

        # Display the cleaning operation result (display again the hierarchy tree, but with the _cleaning_counts
        # information (deleted / replaced objects of each type for each device-group)
        self._console.log(Panel(self.generate_hierarchy_tree(result=True)))

        # If the --no-report argument was not used at startup, export the console content to an HTML report file
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
        :return:
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
        """
        Get the list of managed devices by Panorama
        And stores it in a dict where they key is the firewall SN, and the value is the panos.Firewall object
        :return:
        """
        devices = self._panorama.refresh_devices(expand_vsys=False, include_device_groups=False)
        for fw in devices:
            if fw.state.connected:
                self._panorama_devices[getattr(fw, "serial")] = fw

    def generate_hierarchy_tree(self, result=False):
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
            if result and 'shared' in self._analysis_perimeter['full']:
                line_value += "   "
                line_value += ' '.join([f"{k} : {v['removed']}/{v['replaced']}" for k, v in self._cleaning_counts['shared'].items()])
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
                            if result and d in self._analysis_perimeter['full']:
                                line_value += "   "
                                line_value += ' '.join([f"{k} : {v['removed']}/{v['replaced']}" for k, v in
                                                        self._cleaning_counts[d].items()])
                            leaf = tree_branch.add(line_value, style="red")
                        elif d in self._analysis_perimeter['indirect']:
                            line_value = "* "
                            line_value += "F " if d in self._analysis_perimeter['full'] else "P "
                            line_value += d
                            if result and d in self._analysis_perimeter['full']:
                                line_value += "   "
                                line_value += ' '.join([f"{k} : {v['removed']}/{v['replaced']}" for k, v in
                                                        self._cleaning_counts[d].items()])
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
        """
        Returns the global count of all objects (Address, Tag, Service) for the provided location

        :param location_name: (string) Name of the location (shared or device-group name) where to count objects
        :return: (int) Total number of objects for the requested location
        """

        counter = 0
        try:
            for t, l in self._objects.get(location_name, dict()).items():
                counter += len(l) if type(l) is list else 0
        finally:
            return counter

    def count_rules(self, location_name):
        """
        Returns the global count of all rules for all rulebases for the provided location

        :param location_name: (string) Name of the location (shared or device-group) where to count the rules
        :return: (int) Total number of rules for the requested location
        """

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

        self._service_valuesearch[location_name] = dict()
        for obj in self._objects[location_name]['Service']:
            if type(obj) is ServiceObject:
                serv_string = self.stringify_service(obj)
                if serv_string not in self._service_valuesearch[location_name].keys():
                    self._service_valuesearch[location_name][serv_string] = list()
                self._service_valuesearch[location_name][serv_string].append(obj)

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

        # create a "context" key on the current location dict which will contain the current location's DeviceGroup object
        self._rulebases[location_name]['context'] = context

        for ruletype in repl_map:

            rulebases = [PreRulebase(), PostRulebase()]
            if ruletype is SecurityRule:
                rulebases += [Rulebase()]

            for rb in rulebases:
                context.add(rb)
                self._rulebases[location_name][rb.__class__.__name__+"_"+ruletype.__name__] = \
                    ruletype.refreshall(rb, add=True)
                #context.remove(rb)

    def fetch_hitcounts(self, context, location_name):
        """
        Get the hitcounts for all rules at the requested location
        last_hit_timestamp can only be get from the devices (not from Panorama)
        rule_modification_timestamp can be get from the devices running PAN-OS 9+

        If no devices are running PAN-OS 9+ for the concerned device-group, the rule_modification_timestamps
        is get from Panorama

        :param context: (panos.DeviceGroup) DeviceGroup object
        :param location_name: (string) The location name (= DeviceGroup name)
        :return:
        """

        dg_firewalls = Firewall.refreshall(context)
        rulebases = [x.__name__.replace('Rule', '').lower() for x in repl_map]
        interest_counters = ["last_hit_timestamp", "rule_modification_timestamp"]
        # 23022022 - Seems that hit timestamps can only be get from device
        # while last modification timestamp has to be get from Panorama
        #interest_counters = ["last_hit_timestamp"]
        self._hitcounts[location_name] = ({x: dict() for x in rulebases})
        min_member_major_version = 0

        def populate_hitcounts(rulebase_name, opstate):
            for rule, counters in opstate.items():
                if not (res := self._hitcounts[location_name][rulebase_name].get(rule)):
                    self._hitcounts[location_name][rulebase_name][rule] = {
                        x: countval if (countval := getattr(counters, x)) else 0 for x in interest_counters}
                else:
                    for ic in interest_counters:
                        if (countval := getattr(counters, ic)):
                            self._hitcounts[location_name][rulebase_name][rule][ic] = max(res[ic], countval)

        for fw in dg_firewalls:
            device = self._panorama_devices.get(getattr(fw, "serial"))
            if device:
                system_settings = device.find("", SystemSettings)
                fw_ip = system_settings.ip_address
                fw_vsys = getattr(fw, "vsys")
                fw_conn = Firewall(fw_ip, self._panorama_user, self._panorama_password, vsys=fw_vsys)
                # TODO : timeout connection + retry ?
                self._console.log(f"Connecting to firewall {fw_ip} on vsys {fw_vsys} ({location_name})")
                fw_panos_version = fw_conn.refresh_system_info().version
                if (current_major_version := int(fw_panos_version.split('.')[0])) > min_member_major_version:
                    min_member_major_version = current_major_version
                if self._superverbose:
                    self._console.log(f"Detected PAN-OS version on {fw_ip} : {fw_panos_version}")
                rb = Rulebase()
                fw_conn.add(rb)
                for rulebase in rulebases:
                    ans = rb.opstate.hit_count.refresh(rulebase, all_rules=True)
                    populate_hitcounts(rulebase, ans)

        if min_member_major_version < 9:
            # if we did not found any member firewall with PANOS >= 9, we need to get the rule modification timestamp from Panorama for this context
            self._console.log(f"Not found any member with PAN-OS version >= 9 for context {location_name}. Getting rule modification timestamp from Panorama")
            for rb_type in [PreRulebase(), PostRulebase()]:
                context.add(rb_type)
                for rulebase in rulebases:
                    ans = rb_type.opstate.hit_count.refresh(rulebase, all_rules=True)
                    populate_hitcounts(rulebase, ans)

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
        Find Address objects referenced by a dynamic group (based on their tags)
        Knowing that dynamic groups can reference any object up to the level at which they are used
        And not only up to the level where they are defined

        :param executable_condition: (string) Executable python statement to match tags as configured on DAG
        :param reference_location: (string) Location where to start to find referenced objects (where the group is used)
        :return:
        """

        found_objects = list()
        # For each object at the reference_location level
        for obj in self._objects[reference_location]['Address']:
            # check if current object has tags
            if obj.tag:
                # initialize dict which will contain the results of the executable_condition execution
                expr_result = dict()
                # obj_tags is the variable name used when generating the condition expression
                # (on the fetch_used_obj_set). Tags will be searched there.
                obj_tags = obj.tag
                # Execute the executable_condition with the locals() context
                exec(executable_condition, locals(), expr_result)
                cond_expr_result = expr_result['cond_expr_result']
                # If the current object tags matches the executable_condition, add it to found_objects
                if cond_expr_result:
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

    def fetch_used_obj_set(self, location_name, progress, task):
        """
        This function generates a "set" of used objects of each type (Address, AddressGroup, Tag, Service, ServiceGroup...)
        at each requested location.
        This set is a set of tuples of (panos.Object, location (str))
        Group objects are explored (recursively) to find all members, which are of course also considered as used.

        :param location_name: (str) The location name where to start used objects exploration
        :param progress: (rich.Progress) The rich Progress object to update during progression
        :param task: (rich.Task) The rich Task object to update during progression
        :return:
        """

        def gen_condition_expression(condition_string: str, field_name: str):
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

        def shorten_object_type(object_type: str):
            """
            (Overkill function) which returns a panos.Object type, after removing the "Group" and "Object" characters

            :param object_type: (str) panos.Object.__class__.__name__
            :return: (str) the panos.Object type name without "Group" nor "Object"
            """

            return object_type.replace('Group', '').replace('Object', '')

        def flatten_object(used_object: panos.objects, object_location: str, usage_base: str,
                           referencer_type: str = None, referencer_name: str = None, recursion_level: int = 1):
            """
            Recursively called function, charged of returning the obj_set (list of (panos.objects, location)) for a given rule
            (first call is from a loop iterating over the different rules of a rulebase at a given location)

            Calls itself recursively for AddressGroups (static or dynamic)

            :param used_object: (panos.object) The used object (found with get_relative_object_location)
            :param object_location: (string) The location where the used objects has been found by get_relative_object_location
            :param usage_base: (string) The location where the object has been found used (from where it has to be flattened)
            :param referencer_type: (string) The type (class.__name__) of the object where the reference to used_object has been found
            :param referencer_name: (string) The name of the object where the reference to used_object has been found
                (can be a rule, an AddressGroup...)
            :param recursion_level: (int) The level of recursion for this call to the flatten_object function
                (is used for log outputs, prepending * recursion_level times at the beginning of each log message)
            :return:
            """

            # Initializes an empty list which will contain tuples of (panos.Object, location_name) of the flattened group content
            obj_set = list()

            # If used_object has been resolved at the time of calling the flatten_object function, mark it as resolved
            # (in cache) for the "usage_base" location (adding its name) and add the (object, location) tuple to the obj_set list
            if not isinstance(used_object, type(None)):
                if self._superverbose:
                    self._console.log(
                        f"  {'*' * recursion_level} Marking {used_object.name!r} ({used_object.__class__.__name__}) as resolved on cache for location {usage_base}",
                        style="green italic")
                resolved_cache[usage_base][shorten_object_type(used_object.__class__.__name__)].append(
                    used_object.name)

                # adding the resolved (used_object, object_location) itself to the obj_set list
                obj_set.append((used_object, object_location))

            # if the resolved object is a "simple" object (not needing recursive search), just display a log indicating
            # that search is over for this one
            if type(used_object) in [panos.objects.AddressObject, panos.objects.ServiceObject, panos.objects.Tag]:
                if self._superverbose:
                    self._console.log(
                        f"  {'*' * recursion_level} Object {used_object.name!r} ({used_object.__class__.__name__}) used on {usage_base!r} (ref by {referencer_type} {referencer_name}) has been found on location {object_location}",
                        style="green italic")

            # if the resolved object needs recursive search for members (AddressGroup), let's go
            # here for an AddressGroup
            elif type(used_object) is panos.objects.AddressGroup:
                # in case of a static group, just call the flatten_object function recursively for each member
                # (which can be only at the group level or below)
                if used_object.static_value:
                    if self._superverbose:
                        self._console.log(
                            f"  {'*' * recursion_level} Object {used_object.name!r} (static AddressGroup) used on {usage_base!r} (ref by {referencer_type} {referencer_name!r}) has been found on location {object_location}",
                            style="green italic")

                    # for each static group member, call the current function recursively
                    # (if the member has not already been resolved for the current location, which means that it would
                    # already have been flattened)
                    for group_member in used_object.static_value:
                        if group_member not in resolved_cache[usage_base]['Address']:
                            if self._superverbose:
                                self._console.log(
                                    f"  {'*' * recursion_level} Found group member of AddressGroup {used_object.name!r} : {group_member!r}",
                                    style="green italic")

                            # call to the flatten_object function with the following parameters :
                            # panos.Object found for the requested object name (returned by a call to get_relative_object_location)
                            # location of this object (returned by a call to get_relative_object_location)
                            # usage_base = the location where the object is used (can be below the real location of the object)
                            # used_object.__class__.__name__ = the object type where the member has been found used (AddressGroup, actually)
                            # used_object.name = the name of the object where the member has been found (= the group name, actually)
                            # recursion_level = the current recursion_level + 1

                            obj_set += flatten_object(
                                *self.get_relative_object_location(group_member,usage_base),
                                usage_base,
                                used_object.__class__.__name__,
                                used_object.name,
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

                # in case of a dynamic group, the group condition is converted to an executable Python statement,
                # for members to be found using their tags
                # for dynamic groups, members can be at any location, upward starting from the usage_base location
                elif used_object.dynamic_value:
                    if self._superverbose:
                        self._console.log(
                            f"  {'*' * recursion_level} Object {used_object.name!r} (dynamic AddressGroup) used on {usage_base!r} (ref by {referencer_type} {referencer_name!r}) has been found on location {object_location}",
                            style="green italic")

                    # call to the gen_condition_expression function, which will convert the DAG value into an executable
                    # python condition
                    executable_condition = gen_condition_expression(used_object.dynamic_value, "obj_tags")

                    # for each object matched by the get_relative_object_location_by_tag (using the generated Python expression)
                    # (= for each object matched by the DAG)
                    for referenced_object, referenced_object_location in self.get_relative_object_location_by_tag(
                            executable_condition, usage_base):
                        if self._superverbose:
                            self._console.log(
                                f"  {'*' * recursion_level} Found group member of dynamic AddressGroup {used_object.name!r} : {referenced_object.name!r}",
                                style="green italic")

                        # for each dynamic group member, call the current function recursively
                        # (if the member has not already been resolved for the current location, which means that it would
                        # already have been flattened)
                        if referenced_object.name not in resolved_cache[usage_base]['Address']:
                            # call to the flatten_object function with the following parameters :
                            # referenced_object = the panos.Object found by the get_relative_object_location_by_tag
                            # referenced_object_location = the location of this object (returned by a call to get_relative_object_location_by_tag)
                            # usage_base = the location where the object is used (can be below the real location of the object)
                            # used_object.__class__.__name__ = the object type where the member has been found used (AddressGroup, actually)
                            # used_object.name = the name of the object where the member has been found (= the group name, actually)
                            # recursion_level = the current recursion_level + 1

                            obj_set += flatten_object(
                                referenced_object,
                                referenced_object_location,
                                usage_base,
                                used_object.__class__.__name__,
                                used_object.name,
                                recursion_level + 1)

                            # add the found referenced_object and its location to the _tag_referenced dict
                            # this dict is used by the replace_object_in_group function, when an object referenced on
                            # a DAG by a tag needs to be replaced. This tag will need to be added to the replacement
                            # object for this new object to be matched by the DAG also
                            self._tag_referenced.add((referenced_object, referenced_object_location))
                            if self._superverbose:
                                self._console.log(
                                    f"  {'*' * recursion_level} Marking {referenced_object.name!r} as tag-referenced",
                                    style="green italic")
                        else:
                            if self._superverbose:
                                self._console.log(
                                    f"  {'*' * recursion_level} Address Object {referenced_object.name!r} already resolved in context {usage_base}",
                                    style="yellow")

            # or here for ServiceGroup
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
                            obj_set += flatten_object(
                                *self.get_relative_object_location(group_member, usage_base),
                                usage_base,
                                used_object.__class__.__name__,
                                used_object.name,
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
                                # call to the flatten_object function with the following parameters :
                                # panos.Object (found by the get_relative_object_location function)
                                # the location of this object (found by the get_relative_object_location function)
                                # usage_base = the location where the object is used (can be below the real location of the object)
                                # used_object.__class__.__name__ = the object type where the member has been found used (AddressGroup, actually)
                                # used_object.name = the name of the object where the member has been found (= the group name, actually)
                                # recursion_level = the current recursion_level (not incremented)

                                obj_set += flatten_object(
                                    *self.get_relative_object_location(tag, object_location, obj_type="tag"),
                                    usage_base,
                                    used_object.__class__.__name__,
                                    used_object.name,
                                    recursion_level)

            # return the populated obj_set (when fully flattened)
            return obj_set

        # Initialized the location obj set list
        location_obj_set = list()

        # This dict contains a list of names for each object type, for which the location has been already found
        # This considerably improves processing time, avoiding to search again an object which has been already found
        # among the upward locations
        resolved_cache = dict()
        # TODO : remove the "location_name" key which is useless for this dict
        resolved_cache[location_name] = dict({'Address': list(), 'Service': list(), 'Tag': list()})

        # Regex statements which permits to identify an AddressObject value to know if it represents an IP/mask or a range
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

                # Use the repl_map descriptor to find the different types of objects which can be found on the current
                # rule based on its type.
                # Initializes a dict where the key is the object type, and the value is an empty list
                rule_objects = {x: [] for x in repl_map.get(type(r))}

                # for each object type / field name in the repl_map descriptor for the current rule type
                for obj_type, obj_fields in repl_map.get(type(r)).items():
                    # for each rule field using the current object type
                    for field in obj_fields:
                        # if the rule field is a string value, add the object to the rule_objects dict (on the corresponding
                        # key matching the object type)
                        if type(field) is str:
                            if (to_add := getattr(r, field)):
                                rule_objects[obj_type].append(to_add)
                        # else if the rule field is a list, add this list to the rule_objects dict
                        else:
                            if (to_add := getattr(r, field[0])):
                                rule_objects[obj_type] += to_add

                    # for each object (of the current object type) used on the current rule
                    for obj in rule_objects[obj_type]:
                        # if the object name is not in the resolved_cache, it needs to be resolved
                        if obj != 'any' and obj not in resolved_cache[location_name][obj_type]:
                            # call to the flatten_object function with the following parameters :
                            # panos.Object, location of this object (returned by a call to get_relative_object_location)
                            # location_name = the current location (where the object is used)
                            # r.__class__.__name__ = the rule type
                            # r.name = the rule name

                            location_obj_set += (
                                flattened := flatten_object(
                                    *self.get_relative_object_location(obj, location_name, obj_type),
                                    location_name,
                                    r.__class__.__name__,
                                    r.name)
                            )

                            # the following will be executed if the object used has not been found by the
                            # get_relative_object_location call (flatten object will not return anything in such a case)
                            if not flattened:
                                # can be in case of an IP address / subnet directly used on a rule
                                if obj_type == "Address":
                                    if ip_regex.match(obj) or range_regex.match(obj):
                                        # create a (temporary) new AddressObject (whose name is the same as the value)
                                        # and add it to the location_obj_set
                                        location_obj_set += [(AddressObject(name=obj, value=obj), location_name)]
                                        self._console.log(
                                            f"  * Created AddressObject for address {obj} used on rule {r.name!r}",
                                            style="yellow")

                                    # else for any un-supported AddressObject type, log an error
                                    else:
                                        self._console.log(
                                            f"  * Un-supported AddressObject seems to be used on rule {r.name!r} ({obj})",
                                            style="red")
                                elif obj_type == "Service":
                                    if not obj == "application-default":
                                        self._console.log(
                                            f"  * Un-supported ServiceObject seems to be used on rule {r.name!r} ({obj})",
                                            style="red")
                                else:
                                    self._console.log(
                                        f"  * Un-supported object type seems to be used on rule {r.name!r} ({obj})",
                                        style="red")
                        # else if the object is in the resolved_cache (and is not "any"), it means it has already been resolved
                        # (if the object is "any", we don't care)
                        elif obj != 'any':
                            if self._superverbose:
                                self._console.log(f" * {obj_type} Object {obj!r} already resolved in context {location_name}",
                                                  style="yellow")
                # update progress bar for each processed rule
                progress.update(task, advance=1)

        # add the processed object set for the current location to the globa _used_objects_set dict
        self._used_objects_sets[location_name] = set(location_obj_set)

    def hostify_address(self, address: str):
        """
        Used to remove /32 at the end of an IP address
        :param address: (string) IP address to be modified
        :return: (string) Host IP address (instead of network /32)
        """

        # removing /32 mask for hosts
        if address[-3:] == '/32':
            return address[:-3:]
        return address

    def stringify_service(self, service: panos.objects.ServiceObject):
        """
        Returns the "string" version of a service (for search purposes)
        The format is (str) PROTOCOL/source_port/dest_port
        IE : TCP/None/22 or UDP/1000/60

        :param service: (panos.Service) A Service object
        :return: (str) The "string" version of the provided object
        """

        return service.protocol.lower() + "/" + str(service.source_port) + "/" + str(service.destination_port)

    def find_upward_obj_by_addr(self, base_location_name: str, obj: panos.objects.AddressObject):
        """
        This function finds all Address objects on upward locations (from the base_location_name) having
        the same value than the provided obj

        :param base_location_name: (str) The location from which to start the duplicates objects search (going upward)
        :param obj: (panos.objects.AddressObject) The base object for which we need to find duplicates
        :return: [(panos.objects.AddressObject, str)] A list of tuples containing the duplicates objects and their
            location, on upward locations
        """

        # Get the "host" value of the object value (removes the /32 at the end)
        obj_addr = self.hostify_address(obj.value)

        # Initializes the list of found duplicates objects
        found_upward_objects = list()
        current_location_search = base_location_name

        # This boolean is used to stop the search loop when the "shared" location has been reached
        reached_max = False
        while not reached_max:
            if current_location_search == "shared":
                reached_max = True
            # Get the list of all matching Address objects at the current search location
            for obj in self._addr_ipsearch[current_location_search].get(obj_addr, list()):
                # add each of them to the result list as a tuple (AddressObject, current location name)
                found_upward_objects.append((obj, current_location_search))
            # Find the next search location (upward device group)
            current_location_search = self._stored_pano_hierarchy.get(current_location_search)
            # If the result of the upward device-group name is "None", it means that the upward device-group is "shared"
            if not current_location_search:
                current_location_search = "shared"

        return found_upward_objects

    def find_upward_obj_group(self, base_location_name: str, ref_obj_group: panos.objects.AddressGroup):
        """
        This function finds all AddressGroup objects on upward locations (from the base_location_name) having
        the same value (static members or DAG condition expression) than the provided group obj

        :param base_location_name: (str) The location from which to start the duplicates objects search (going upward)
        :param obj: (panos.objects.AddressGroup) The base object for which we need to find duplicates
        :return: [(panos.objects.AddressGroup, str)] A list of tuples containing the duplicates objects and their
            location, on upward locations
        """
        # TODO : test if it works !!

        # Initializes the list of found duplicates objects
        found_upward_objects = list()
        current_location_search = base_location_name

        # This boolean is used to stop the search loop when the "shared" location has been reached
        reached_max = False
        while not reached_max:
            if current_location_search == "shared":
                reached_max = True
            # Iterate over the list of all Address objects at the current search location
            for obj in self._objects[current_location_search]['Address']:
                # If the current object has the AddressGroup type
                if type(obj) is panos.objects.AddressGroup:
                    # If this is a static group
                    if ref_obj_group.static_value and obj.static_value:
                        # And if it has the same members values
                        if sorted(ref_obj_group.static_value) == sorted(obj.static_value):
                            # Then add this object to the list of found duplicates as a tuple
                            # (AddressGroup, current location name)
                            found_upward_objects.append((obj, current_location_search))
                    # If this is a dynamic group
                    elif ref_obj_group.dynamic_value and obj.dynamic_value:
                        # And if it has the same condition expression
                        if ref_obj_group.dynamic_value == obj.dynamic_value:
                            # Then add this object to the list of found duplicates as a tuple
                            # (AddressGroup, current location name)
                            found_upward_objects.append((obj, current_location_search))
            # Find the next search location (upward device group)
            current_location_search = self._stored_pano_hierarchy.get(current_location_search)
            # If the result of the upward device-group name is "None", it means that the upward device-group is "shared"
            if not current_location_search:
                current_location_search = "shared"

        return found_upward_objects

    def find_upward_obj_service_group(self, base_location_name: str, obj_group: panos.objects.ServiceGroup):
        """
        This function finds all ServiceGroup objects on upward locations (from the base_location_name) having
        the same value (static members) than the provided group obj

        :param base_location_name: (str) The location from which to start the duplicates objects search (going upward)
        :param obj: (panos.objects.ServiceGroup) The base object for which we need to find duplicates
        :return: [(panos.objects.ServiceGroup, str)] A list of tuples containing the duplicates objects and their
            location, on upward locations
        """
        # TODO : test if it works !!

        # Initializes the list of found duplicates objects
        found_upward_objects = list()
        current_location_search = base_location_name

        # This boolean is used to stop the search loop when the "shared" location has been reached
        reached_max = False
        while not reached_max:
            if current_location_search == "shared":
                reached_max = True
            # Iterate over the list of all Service objects at the current search location
            for obj in self._objects[current_location_search]['Service']:
                # If the current object has the ServiceGroup type
                if type(obj) is panos.objects.ServiceGroup:
                    # If the static members of this ServiceGroup are the same thant the reference group object
                    if sorted(obj_group.value) == sorted(obj.value):
                        # Then add this object to the list of found duplicates as a tuple
                        # (ServiceGroup, current location name)
                        found_upward_objects.append((obj, current_location_search))
            # Find the next search location (upward device group)
            current_location_search = self._stored_pano_hierarchy.get(current_location_search)
            # If the result of the upward device-group name is "None", it means that the upward device-group is "shared"
            if not current_location_search:
                current_location_search = "shared"

        return found_upward_objects

    def find_upward_obj_service(self, base_location_name: str, obj_service: panos.objects.ServiceObject):
        """
        This function finds all Service objects on upward locations (from the base_location_name) having
        the same value than the provided obj

        :param base_location_name: (str) The location from which to start the duplicates objects search (going upward)
        :param obj: (panos.objects.ServiceObject) The base object for which we need to find duplicates
        :return: [(panos.objects.ServiceObject, str)] A list of tuples containing the duplicates objects and their
            location, on upward locations
        """

        # Get the "string" value of the Service object (to be able to search it quicker on the _service_valuesearch dict)
        obj_service_string = self.stringify_service(obj_service)

        # Initializes the list of found duplicates objects
        found_upward_objects = list()
        current_location_search = base_location_name

        # This boolean is used to stop the search loop when the "shared" location has been reached
        reached_max = False
        while not reached_max:
            if current_location_search == "shared":
                reached_max = True
            # Get the list of all matching Service objects at the current search location
            for obj in self._service_valuesearch[current_location_search].get(obj_service_string, list()):
                # Add each of them to the result list as a tuple (ServiceObject, current location name)
                found_upward_objects.append((obj, current_location_search))
            # Find the next search location (upward device group)
            current_location_search = self._stored_pano_hierarchy.get(current_location_search)
            # If the result of the upward device-group name is "None", it means that the upward device-group is "shared"
            if not current_location_search:
                current_location_search = "shared"

        return found_upward_objects

    def find_best_replacement_addr_obj(self, obj_list: list, base_location: str):
        """
        Get a list of tuples (object, location) and returns the best to be used based on location and naming criterias
        TODO : WARNING, can have unpredictable results with nested intermediate device-groups
        TODO : test behavior when having only multiple matching objects at the base location (see changed line below)
        Will return the intermediate group replacement object if any

        :param obj_list: list((AddressObject, string)) List of tuples of AddressObject and location names
        :param base_location: (str) The name of the location from where we need to find the best replacement object
        :return:
        """

        choosen_object = None
        choosen_by_tiebreak = False

        """
        if len(obj_list) == 1:
            choosen_object = obj_list[0]
            if self._superverbose:
                self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as there's no other existing for value {choosen_object[0].value}")
        else:
        """

        # If a tiebreak tag has been specified, this is the decision factor to choose the "best" object
        # Not that if several objects have the tiebreak tag (which is not supposed to happen), the first one of the list
        # will be chosen, which can leads to some randomness
        if self._tiebreak_tag:
            for o in obj_list:
                if not choosen_object:
                    try:
                        if self._tiebreak_tag in o[0].tag:
                            choosen_object = o
                        if self._superverbose:
                            self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen by tiebreak")
                    except:
                        # This exception is matched when checking if the tiebreak tag is on the list of tags of an
                        # object which has no tags
                        pass

        # If the tiebreak tag was not used to find the "best" object
        if not choosen_object:
            # create a list of shared objects from the obj_list
            shared_obj = [x for x in obj_list if x[1] == 'shared']
            # create a list of intermediate DG objects from the obj_list
            # TODO : concerned line here
            # interm_obj = [x for x in obj_list if x[1] != 'shared' and x[1] != base_location]
            interm_obj = [x for x in obj_list if x[1] != 'shared']
            # create a list of objects having name with multiple "." and ending with "corp" or "com" (probably FQDN)
            fqdn_obj = [x for x in obj_list if
                        len(x[0].about()['name'].split('.')) > 1 and x[0].about()['name'].split('.')[-1] in ['corp', 'com']]
            # find objects being both shared and with FQDN-like naming
            shared_fqdn_obj = list(set(shared_obj) & set(fqdn_obj))
            interm_fqdn_obj = list(set(interm_obj) & set(fqdn_obj))

            # if shared and well-named objects are found, return the first one
            if shared_fqdn_obj and not choosen_object:
                for o in shared_fqdn_obj:
                    if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_fqdn_obj] and not choosen_object:
                        choosen_object = o
                        if self._superverbose:
                            self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object with FQDN naming")
            # else return the first found shared object
            if shared_obj and not choosen_object:
                for o in shared_obj:
                    if not choosen_object:
                    #if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_obj] and not choosen_object:
                        choosen_object = o
                        if self._superverbose:
                            self._console.log(f"Object {o[0].about()['name']} (context {o[1]}) choosen as it's a shared object")
            # Repeat the same logic for intermediate device-groups
            if interm_fqdn_obj and not choosen_object:
                temp_object_level = 999
                # This code will permit to keep the "highest" device-group level matching object
                # (nearest to the "shared" location)
                for o in interm_fqdn_obj:
                    if not choosen_object:
                        location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                        if location_level < temp_object_level:
                            temp_object_level = location_level
                            choosen_object = o
                if self._superverbose:
                    self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object with FQDN naming (level = {temp_object_level})")
            if interm_obj and not choosen_object:
                temp_object_level = 999
                for o in interm_obj:
                    if not choosen_object:
                        location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                        if location_level < temp_object_level:
                            temp_object_level = location_level
                            choosen_object = o
                if self._superverbose:
                    self._console.log(f"Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object (level = {temp_object_level})")
        # If no best replacement object has been found at this point, display an alert and return the first one in the
        # input list (can lead to random results)
        if not choosen_object:
            self._console.log(f"ERROR : Unable to choose an object in the following list for address {obj_list[0][0].value} : {obj_list}. Returning the first one by default", style="red")
            choosen_object = obj_list[0]

        # If an object has not been chosen using the tiebreak tag, but the tiebreak tag adding has been requested,
        # then add the tiebreak tag to the chosen object so that it will remain the preferred one for next executions
        if self._apply_tiebreak_tag and not choosen_by_tiebreak:
            tag_changed = False
            # If the object already has some tags, adding the tiebreak tag to the list
            if choosen_object[0].tag:
                if not self._tiebreak_tag in choosen_object[0].tag:
                    choosen_object[0].tag.append(self._tiebreak_tag)
                    tag_changed = True
            # Else if the object has no tags, initialize the list with the tiebreak tag
            else:
                choosen_object[0].tag = [self._tiebreak_tag]
                tag_changed = True
            if self._superverbose and tag_changed:
                self._console.log(f"Adding tiebreak tag {self._tiebreak_tag} to {choosen_object[0].__class__.__name__} {choosen_object[0].about()['name']} on context {choosen_object[1]} ")
            # If cleaning application is requested and tag has been changed, apply it to Panorama
            if self._apply_cleaning and tag_changed:
                choosen_object[0].apply()

        # Returns the chosen object among the provided list
        return choosen_object

    def find_best_replacement_service_obj(self, obj_list: list, base_location: str):
        """
        Get a list of tuples (object, location) and returns the best to be used based on location and naming criterias
        TODO : WARNING, can have unpredictable results with nested intermediate device-groups
        TODO : test behavior when having only multiple matching objects at the base location (see changed line below)
        Will return the intermediate group replacement object if any

        :param obj_list: list((ServiceObject, string)) List of tuples of ServiceObject and location names
        :param base_location: (str) The name of the location from where we need to find the best replacement object
        :return:
        """

        choosen_object = None
        choosen_by_tiebreak = False

        """
        if len(obj_list) == 1:
            choosen_object = obj_list[0]
            if self._superverbose:
                self._console.log(
                    f"Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as there's no other existing for value {self.stringify_service(choosen_object[0])}")
        else:
        """

        # If a tiebreak tag has been specified, this is the decision factor to choose the "best" object
        # Not that if several objects have the tiebreak tag (which is not supposed to happen), the first one of the list
        # will be chosen, which can leads to some randomness
        if self._tiebreak_tag:
            for o in obj_list:
                if not choosen_object:
                    try:
                        if self._tiebreak_tag in o[0].tag:
                            choosen_object = o
                        if self._superverbose:
                            self._console.log(
                                f"Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen by tiebreak")
                    except:
                        # This exception is matched when checking if the tiebreak tag is on the list of tags of an
                        # object which has no tags
                        pass

        # If the tiebreak tag was not used to find the "best" object
        if not choosen_object:
            # create a list of shared objects from the obj_list
            shared_obj = [x for x in obj_list if x[1] == 'shared']
            # create a list of intermediate DG objects from the obj_list
            # TODO : concerned line here
            # interm_obj = [x for x in obj_list if x[1] not in ['shared', base_location]]
            interm_obj = [x for x in obj_list if x[1] != 'shared']
            # create a list of objects having a name like "protocol_port" (ie = tcp_80)
            standard_obj = [x for x in obj_list if
                            x[0].name == x[0].protocol.lower() + '_' + str(x[0].destination_port)]

            # Find objects being both shared and with standard naming for service objects
            # or being at intermediate locations and with standard naming for service objects
            shared_standard_obj = list(set(shared_obj) & set(standard_obj))
            interm_standard_obj = list(set(interm_obj) & set(standard_obj))

            # If shared and well-named objects are found, return the first one
            if shared_standard_obj and not choosen_object:
                for o in shared_standard_obj:
                    if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_standard_obj]:
                        choosen_object = o
                        if self._superverbose:
                            self._console.log(
                                f"Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object with standard naming")
            # Else return the first found shared object
            if shared_obj and not choosen_object:
                for o in shared_obj:
                    if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_obj]:
                        choosen_object = o
                        if self._superverbose:
                            self._console.log(
                                f"Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object")
            # Repeat the same logic for intermediate device-groups
            if interm_standard_obj and not choosen_object:
                temp_object_level = 999
                # This code will permit to keep the "highest" device-group level matching object
                # (nearest to the "shared" location)
                for o in interm_standard_obj:
                    location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                    if location_level < temp_object_level:
                        temp_object_level = location_level
                        choosen_object = o
                if self._superverbose:
                    self._console.log(
                        f"Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object with standard naming (level = {temp_object_level})")
            if interm_obj and not choosen_object:
                temp_object_level = 999
                for o in interm_obj:
                    location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                    if location_level < temp_object_level:
                        temp_object_level = location_level
                        choosen_object = o
                if self._superverbose:
                    self._console.log(
                        f"Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object (level = {temp_object_level})")
        # If no best replacement object has been found at this point, display an alert and return the first one in the
        # input list (can lead to random results)
        if not choosen_object:
            self._console.log(f"ERROR : Unable to choose an object in the following list for service {self.stringify_service(obj_list[0][0])} : {obj_list}. Returning the first one by default", style="red")
            choosen_object = obj_list[0]

        # If an object has not been chosen using the tiebreak tag, but the tiebreak tag adding has been requested,
        # then add the tiebreak tag to the chosen object so that it will remain the preferred one for next executions
        if self._apply_tiebreak_tag and not choosen_by_tiebreak:
            tag_changed = False
            # If the object already has some tags, adding the tiebreak tag to the list
            if choosen_object[0].tag:
                if not self._tiebreak_tag in choosen_object[0].tag:
                    choosen_object[0].tag.append(self._tiebreak_tag)
                    tag_changed = True
            # Else if the object has no tags, initialize the list with the tiebreak tag
            else:
                choosen_object[0].tag = [self._tiebreak_tag]
                tag_changed = True
            if self._superverbose and tag_changed:
                self._console.log(
                    f"Adding tiebreak tag {self._tiebreak_tag} to {choosen_object[0].__class__.__name__} {choosen_object[0].about()['name']} on context {choosen_object[1]}")
            # If cleaning application is requested and tag has been changed, apply it to Panorama
            if self._apply_cleaning and tag_changed:
                choosen_object[0].apply()

        # Returns the chosen object among the provided list
        return choosen_object

    def optimize_objects(self, location_name: str, progress: rich.progress.Progress, task: rich.progress.TaskID):
        """
        Start object optimization processing for device-group given as argument

        :param location_name: (string) Location where to start objects optimization
        :param progress: (rich.progress.Progress) The rich Progress to update while moving forward
        :param task: (rich.progress.Task) The rich Task to update while moving forward
        :return:
        """

        # for each object and associated location found on the _used_objects_set for the current location

        # Initializing a dict (on the global _replacements dict) which will contain information about the replacement
        # done for each object type at the current location
        self._replacements[location_name] = {'Address': dict(), 'Service': dict(), 'Tag': dict()}

        # This dict references the function to be used to match the best replacement for each object type
        find_maps = {
            AddressObject: self.find_upward_obj_by_addr,
            AddressGroup: self.find_upward_obj_group,
            ServiceObject: self.find_upward_obj_service,
            ServiceGroup: self.find_upward_obj_service_group
        }

        # for each object type in the list below
        for obj_type in [panos.objects.AddressObject, panos.objects.AddressGroup, panos.objects.ServiceObject]:
            # for each object of the current type found at the current location
            for (obj, location) in [(o, l) for (o, l) in self._used_objects_sets[location_name] if type(o) is obj_type]:
                # call the function able to find the best replacement object, for the current object type
                # (the proper function is get from the find_maps dict defined above)
                upward_objects = find_maps.get(type(obj))(location_name, obj)

                # If there are more than 1 found object (as the current one will always be found)
                # We need to find the best one (keep the current one or use one of the other duplicates ?)
                if len(upward_objects) > 1:

                    # If the object type is AddressObject, find the best replacement using the find_best_replacement_addr_obj function
                    if type(obj) is AddressObject:
                        replacement_obj, replacement_obj_location = self.find_best_replacement_addr_obj(upward_objects,
                                                                                                        location_name)
                    # Else if the type is ServiceObject, find the best replacement using the find_best_replacement_service_obj function
                    elif type(obj) is ServiceObject:
                        replacement_obj, replacement_obj_location = self.find_best_replacement_service_obj(upward_objects,
                                                                                                           location_name)
                    else:
                        # TODO : find best upward matching object for AddressGroups
                        # actually using the first object found
                        replacement_obj, replacement_obj_location = upward_objects[0]

                    # if the chosen replacement object is different than the actual object
                    if replacement_obj != obj:
                        self._console.log(
                            f"   Replacing {obj.about()['name']} ({obj.__class__.__name__}) at location {location_name} by {replacement_obj.about()['name']} at location {replacement_obj_location}",
                            style="green italic")

                        # Populating the global _replacements dict (for the current location, current object type) with
                        # the details about the current object name, current object instance and location, and replacement
                        # object instance and location
                        # "blocked" is False at this time. It is used later to block a replacement for objects used on
                        # rules having blocking opstates values (last hit timestamp / last change timestamp)

                        if type(obj) in [AddressObject, AddressGroup]:
                            self._replacements[location_name]['Address'][obj.about()['name']] = {
                                'source': (obj, location),
                                'replacement': (replacement_obj, replacement_obj_location),
                                'blocked': False
                            }
                        elif type(obj) in [ServiceObject, ServiceGroup]:
                            self._replacements[location_name]['Service'][obj.about()['name']] = {
                                'source': (obj, location),
                                'replacement': (replacement_obj, replacement_obj_location),
                                'blocked': False
                            }
                progress.update(task, advance=1)

    def replace_object_in_groups(self, location_name: str, progress: rich.progress.Progress, task: rich.progress.TaskID):
        """
        This function replaces the objects for which a better duplicate has been found on the current location groups

        :param location_name: (str) The name of the location where to replace objects in groups
        :param progress: (rich.progress.Progress) The rich Progress object to update
        :param task: (rich.progress.Task) The rich Task object to update
        :return:
        """

        # Initializing a dict which will contain information about the replacements done on the different groups
        # (when an object to be replaced has been found on a group), to display it on the result logs
        replacements_done = dict()

        # for each replacement for object type "Address" (AddressObject, AddressGroup) at the current location level
        for replacement_name, replacement in self._replacements[location_name]['Address'].items():
            # the source object name is the key on the _replacements dict
            source_obj = replacement_name
            # the source_obj_instance and source_obj_location are found in the 'source' key of the dict item
            source_obj_instance, source_obj_location = replacement['source']
            # the replacement_obj_instance and replacement_obj_location are found in the 'replacement' key of the dict item
            replacement_obj_instance, replacement_obj_location = replacement['replacement']

            # if the source object has been referenced thanks to a tag (DAG member), the tags of the source object needs
            # to be replicated on the replacement one, so that it will be still matched by the DAG
            # TODO : replicate only the tags used by the DAG match
            if (source_obj_instance, source_obj_location) in self._tag_referenced:
                # for each tag used on the source object instance
                for tag in source_obj_instance.tag:
                    # if the tag does not exists as a "shared" object
                    if not [x for x in self._objects['shared']['Tag'] if x.name == tag]:
                        # find the original tag (on its actual location)
                        tag_instance, tag_location = self.get_relative_object_location(tag, location_name, obj_type="tag")
                        self._console.log(f"   [shared] Creating tag {tag!r} (copy from {tag_location}), to be used on ({replacement_obj_instance.about()['name']} at location {replacement_obj_location})")
                        # if the cleaning application has been requested, create the new tag on Panorama
                        if self._apply_cleaning:
                            try:
                                self._panorama.add(tag_instance).create()
                            except Exception as e:
                                self._console.log(f"    [shared] Error while creating tag {tag!r} ! : {e.message}", style="red")
                        # also add the new Tag object at the proper location (shared) on the local cache
                        self._objects['shared']['Tag'].append(tag_instance)
                        self._used_objects_sets['shared'].add((tag_instance, 'shared'))

                    self._console.log(f"    [{replacement_obj_location}] Adding tag {tag} to object {replacement_obj_instance.about()['name']!r} ({replacement_obj_instance.__class__.__name__})", style="yellow italic")
                    # add the new tag to the replacement object
                    if replacement_obj_instance.tag:
                        if not tag in replacement_obj_instance.tag:
                            replacement_obj_instance.tag.append(tag)
                    else:
                        replacement_obj_instance.tag = [tag]
                    # if the cleaning application has been requested, apply the change to the replacement object
                    if self._apply_cleaning:
                        replacement_obj_instance.apply()

            # for each Address type object in the current location objects
            for checked_object in self._objects[location_name]['Address']:
                # if the type of the current object is a static AddressGroup
                if type(checked_object) is panos.objects.AddressGroup and checked_object.static_value:
                    changed = False
                    matched = False
                    try:
                        # if the name of the replacement object is different than the origin one, then the static
                        # group members values needs to be updated
                        if source_obj_instance.about()['name'] != replacement_obj_instance.about()['name']:
                            checked_object.static_value.remove(source_obj_instance.about()['name'])
                            checked_object.static_value.append(replacement_obj_instance.about()['name'])
                            changed = True
                            matched = True
                        # if the name of the replacement object is the same than the original one, the static
                        # group members values remains the same
                        elif source_obj_instance.about()['name'] in checked_object.static_value:
                            matched = True

                        # If the current object to be replaced has been matched as a member of a static group at the
                        # current location level, add it to the replacements_done tracking dict
                        if matched:
                            if self._superverbose:
                                self._console.log(f"    [{location_name}] Replacing {source_obj_instance.about()['name']!r} ({source_obj_location}) by {replacement_obj_instance.about()['name']!r} ({replacement_obj_location}) on {checked_object.about()['name']!r} ({checked_object.__class__.__name__})", style="yellow italic")
                            # create a list (if not existing already) for the current static group object
                            # which will contain the list of all replacements done on this group
                            if checked_object.name not in replacements_done:
                                replacements_done[checked_object.name] = list()
                            # then append the current replacement information to this list (as a tuple format)
                            replacements_done[checked_object.name].append((source_obj_instance.about()['name'], source_obj_location, replacement_obj_instance.about()['name'], replacement_obj_location))
                    # TODO : check when this error is matched ?? (don't remember, but it probably needs to be here)
                    except ValueError:
                        continue
                    except Exception as e:
                        self._console.log(f"    [{location_name}] Unknown error while replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r} on {checked_object.about()['name']!r} ({checked_object.__class__.__name__}) : {e.message}", style="red")
                    # if the cleaning application has been requested, update the modified group on Panorama
                    if self._apply_cleaning and changed:
                        checked_object.apply()

            progress.update(task, advance=1)

        # for each group on which a replacement has been done
        for changed_group_name in replacements_done:
            # create a rich.Table, for which the header is the updated group name
            group_table = Table(style="dim", border_style="not dim", expand=False)
            group_table.add_column(changed_group_name)
            # for each replacement done on the current group
            for replaced_item in replacements_done[changed_group_name]:
                # if the name of the original and replacement objects are different, display the original object
                # name in red, and the replacement one in green (as well as their respective location)
                if replaced_item[0] != replaced_item[2]:
                    group_table.add_row(f"[red]- {replaced_item[0]} ({replaced_item[1]})[/red]")
                    group_table.add_row(f"[green]+ {replaced_item[2]} ({replaced_item[3]})[/green]")
                # else if the name of the original and replacement objects are the same, just display the name in yellow
                # as well as the original object and replacement object locations
                else:
                    group_table.add_row(f"[yellow]! {replaced_item[0]} ({replaced_item[1]} --> {replaced_item[3]})[/yellow]")
            # display the generated rich.Table in the console (and eventually on the exported report)
            self._console.log(group_table)

    def replace_object_in_rulebase(self, location_name: str, progress: rich.progress.Progress, task: rich.progress.TaskID):
        """
        This function replaces the objects which needs to be replaced on the different rulebases, at the provided location
        :param location_name: (str) The name of the location where the Rulebases needs to be updated
        :param progress: (rich.progress.Progress) The rich Progress object to update
        :param task: (rich.progress.Task) The rich Task object to update
        :return:
        """

        # Using the repl_map descriptor, create a dict for which the key is the rule type, and the value is a list
        # of the fields to be displayed / treated for this kind of rule
        # (Adding also the "Name" field, and timestamp-related information)
        tab_headers = dict()
        for rule_type in repl_map:
            tab_headers[rule_type.__name__] = ['Name']
            for field_type, field_names in repl_map[rule_type].items():
                for field in field_names:
                    tab_headers[rule_type.__name__].append(field[0] if type(field) is list else field)
            tab_headers[rule_type.__name__] += ["rule_modification_timestamp", "last_hit_timestamp", "changed"]

        def replace_in_rule(rule, editable_rule):
            """
            This function will perform the changes (replacing objects with the best replacement found) on each rule

            :param rule: (panos.policies.Rule) The rule on which the objects needs to be checked / replaced
            :param editable_rule: (bool) If the rule can be changed (based on opstate timestamps if used) or not
            :return:
            """

            # Initializing a dict which will contain information about the replacements done on the different fields of the rule
            # (when an object to be replaced has been found), to display it on the result logs
            replacements_done = dict()

            # This variable contains the total number of replacements done on the different fields of the current rule
            replacements_count = 0

            # This variable counts the highest number of replacements on a given field, for the loop which will display
            # the replacements in a Table object (back to the replace_object_in_rulebase function calling the current one)
            max_replace = 0

            # For each type of object (Address, Service, Tag...) which can be found on the current rule's type
            for obj_type in repl_map.get(type(rule)):
                # Add a key to the replacements_done for the current object type (and initialize with an empty dict)
                replacements_done[obj_type] = dict()

                # iterate over each field containing the current object type, also getting the field_type from the repl_map
                # (fields can be string values or [list of strings])
                for field_name, field_type in [(x[0], list) if type(x) is list else (x, str) for x in repl_map[type(rule)][obj_type]]:
                    # initialize a list of replacements done on each field of the rule (here with the current field)
                    replacements_done[obj_type][field_name] = list()

                    # This variable stores the number of replacements done on the current field (used later to compare
                    # with the max_replace value, use for proper sizing of the rich.Table rows)
                    current_field_replacements_count = 0

                    # Get the value of the current field (put in on the not_null_field variable thanks to Walrus operator)
                    if (not_null_field := getattr(rule, field_name)):
                        # List of items to add or remove to / from the current field value if modified
                        items_to_add = list()
                        items_to_remove = list()

                        # Thanks to the field format obtained from the repl_map descriptor, iterate directly over the
                        # not_null_field list (if it is already a list), or convert it to a list to iterate
                        for o in not_null_field if field_type is list else [not_null_field]:
                            # Using the Walrus operator again to get the replacement information for the current object
                            # (if there's any)
                            if (replacement := self._replacements[location_name][obj_type].get(o)):
                                # Initializing the information about the source and replacement object
                                source_obj_instance, source_obj_location = replacement['source']
                                replacement_obj_instance, replacement_obj_location = replacement['replacement']
                                # Checking if the name of the replacement object is different than the actual one
                                # (and storing the name of the replacement object on the repl_name variable)
                                if o != (repl_name := replacement_obj_instance.about()['name']):
                                    # Add the replacement information to the replacements_done dict (for reporting)
                                    # replacement type 2 = removed
                                    # replacement type 3 = added
                                    replacements_done[obj_type][field_name].append((f"{o} ({source_obj_location})", 2))
                                    replacements_done[obj_type][field_name].append((f"{repl_name} ({replacement_obj_location})", 3))
                                    current_field_replacements_count += 2
                                    items_to_remove.append(o)
                                    items_to_add.append(repl_name)
                                # Else if the name of the replacement object is the same of the original one
                                else:
                                    # replacement type 1 = same name different location
                                    # this change will occur only if the object from the "lowest" location can be deleted
                                    # (= device-group is fully included in the cleaning process)
                                    if source_obj_location in self._analysis_perimeter["full"]:
                                        replacements_done[obj_type][field_name].append((f"{o} ({source_obj_location} --> {replacement_obj_location})", 1))
                                    else:
                                        replacements_done[obj_type][field_name].append((f"{o}", 0))
                                    current_field_replacements_count += 1
                                replacements_count += 1
                            else:
                                # replacement type 0 = no replacement
                                replacements_done[obj_type][field_name].append((f"{o}", 0))
                                current_field_replacements_count += 1

                        # if the rule can be modified (and cleaning application has been requested), change the current
                        # field value to the appropriate one, and apply the change
                        if editable_rule and self._apply_cleaning:
                            if field_type is not list:
                                setattr(rule, field_name, items_to_add[0])
                            else:
                                any(not_null_field.remove(x) for x in items_to_remove)
                                any(not_null_field.append(x) for x in items_to_add)
                                setattr(rule, field_name, not_null_field)
                            rule.apply()

                    # Update the max_replace value with the highest current_field_replacements_count value
                    # (if the current one is highest). This is used for proper display of the rich.Table rows for each
                    # rule (making sure that the row size is adapted to the field having the highest number of changes
                    # to be displayed)
                    if current_field_replacements_count > max_replace:
                        max_replace = current_field_replacements_count

            # Returns the replacements_done dict, the total number of replacements for the current rule (replacements_count),
            # and the max_replace value (highest number of replacements for a given field) for proper display on the output report
            return replacements_done, replacements_count, max_replace

        def format_for_table(repl_name, repl_type):
            """
            This function will return the proper formatting (color, string pattern) for the current change
            It is used for generating the output Table for the rules changes on each rulebase

            :param repl_name:
            :param repl_type:
            :return:
            """

            type_map = {0: '', 1: 'yellow', 2: 'red', 3: 'green'}
            action_map = {0: ' ', 1: '!', 2: '-', 3: '+'}
            formatted_return = f"[{type_map[repl_type]}]" if repl_type > 0 else ""
            formatted_return += f"{action_map[repl_type]} {repl_name}"
            formatted_return += f"[/{type_map[repl_type]}]" if repl_type > 0 else ""
            return formatted_return

        # for each rulebase at the current location
        for rulebase_name, rulebase in self._rulebases[location_name].items():
            # if the current item is a rulebase (and not the context DeviceGroup object), and is not empty
            if rulebase_name != "context" and len(rulebase) > 0:
                # initialize a variable which will count the number of replacements done for this rulebase
                total_replacements = 0
                # find the opstate hitcount name for the current rulebase type (panos-python stuff)
                # IE : SecurityRule becomes "security", NatRule becomes "nat"
                # Note also that the rulebase_name has the following value format : PreRulebase_SecurityRule (for example)
                # so that name is also splitted after the "_" character
                hitcount_rb_name = rulebase_name.split('_')[1].replace('Rule', '').lower()

                # create a rich.Table object for the current rulebase information display
                rulebase_table = Table(
                    title=f"{location_name} : {rulebase_name} (len : {len(rulebase)})",
                    style="dim",
                    border_style="not dim",
                    expand=True)

                # add a column to the table for each field added to the tab_headers dict for the current rulebase type
                for c_name in tab_headers[rulebase_name.split('_')[1]]:
                    rulebase_table.add_column(c_name)

                # for each rule in the current rulebase
                for r in rulebase:
                    # this boolean variable will define is the rule timestamps are in the boundaries to allow modifications
                    # (if opstate check is used for this processing, regarding last_hit_timestamp and last_change_timestamp)
                    editable_rule = False
                    rule_counters = self._hitcounts.get(location_name, dict()).get(hitcount_rb_name, dict()).get(r.name,
                                                                                                                 dict())
                    rule_modification_timestamp = rule_counters.get('rule_modification_timestamp', 0)
                    last_hit_timestamp = rule_counters.get('last_hit_timestamp', 0)

                    # if rule is disabled or if the job does not needs to rely on rule timestamps
                    # or if the hitcounts for a rule cannot be found (ie : new rule not yet pushed on device)
                    # then just consider that the rule can be modified (editable_rule = True)
                    # Note that the rule hitcount information is stored on the rule_counters dict
                    # TODO : validate if disabled rules are considered editable or not (issue #19)
                    if r.disabled or not self._need_opstate or not rule_counters:
                        editable_rule = True
                    elif rule_modification_timestamp > self._max_hit_timestamp and last_hit_timestamp > self._max_hit_timestamp:
                        editable_rule = True

                    # call the replace_in_rule function for the current rule, which will reply with :
                    # replacements_in_rule : dict with the details of replacements for the current rule
                    # replacements_count : total number of replacements for the rule
                    # max_replace : the highest number of replacements for a given field, for rich.Table rows sizing
                    replacements_in_rule, replacements_count, max_replace = replace_in_rule(r, editable_rule)

                    # If there's at least one replacement on the current rule, it needs to be displayed and applied
                    if replacements_count:
                        # Add the number of replacements for the current rule to the total number of replacements for
                        # the current rulebase
                        total_replacements += replacements_count

                        # if the rule has changes but is not considered as editable (not in timestamp boundaries
                        # regarding opstate timestamps), protect the rule objects from deletion
                        if not editable_rule:
                            for obj_type, fields in repl_map[type(r)].items():
                                for f in fields:
                                    if (field_values := getattr(r, f[0]) if type(f) is list else [getattr(r, f)]):
                                        for object_name in field_values:
                                            if object_name in self._replacements[location_name][obj_type]:
                                                self._replacements[location_name][obj_type][object_name][
                                                    "blocked"] = True

                        # Iterate up to the value of the max_replace variable (which is the highest number of
                        # replacements for a given field of the current rule
                        # This number is the "line number" in the current row (1 row = 1 rule)
                        for table_add_loop in range(max_replace):
                            # row_values is the list of values for the current row (current rule) for the rich.Table
                            # The values have to be put in the same order than the columns headers, defined in the
                            # tab_headers variable
                            row_values = list()

                            # First column contains the name of the rule
                            row_values.append(r.name if table_add_loop == 0 else "")

                            # For each object type (Address, Service, Tag...) / field name for the current rule
                            # type (as defined on the repl_map descriptor)
                            for obj_type, fields in repl_map.get(type(r)).items():
                                # For each field name for the current object type
                                for f in [x[0] if type(x) is list else x for x in fields]:
                                    # Call the format_for_table function, which will return the text to put on the
                                    # current column for the current line in the current row
                                    # (if the current line number is not above the number of replacements to be displayed
                                    # for the current field)
                                    # (yes, that's tricky)
                                    row_values.append(
                                        format_for_table(*replacements_in_rule[obj_type][f][table_add_loop])
                                        if table_add_loop < len(replacements_in_rule[obj_type][f])
                                        else ""
                                    )
                            # if we are on the first line of the current row, display the rule interesting timestamps
                            row_values.append(str(rule_modification_timestamp) if table_add_loop == 0 else "")
                            row_values.append(str(last_hit_timestamp) if table_add_loop == 0 else "")
                            # Display Y or N on the last column, depending if the current rule is indeed modified or not
                            # (based on timestamp values)
                            if table_add_loop == 0:
                                row_values.append("Y" if editable_rule else "N")
                            else:
                                row_values.append("")
                            # Add the current line to the rich.Table
                            # The end_section parameter will be set to True if the current line is the last line for the
                            # current row (moving to the next rule)
                            rulebase_table.add_row(
                                *row_values,
                                end_section=True if table_add_loop == max_replace - 1 else False,
                                style="dim" if r.disabled else None,
                            )

                    progress.update(task, advance=1)

                # If there are replacements on the current rulebase, display the generated rich.Table on the console
                if total_replacements:
                    self._console.log(rulebase_table)

    def clean_local_object_set(self, location_name: str, progress: rich.progress.Progress, task: rich.progress.TaskID):
        """
        In charge of removing the unused objects at a given location (if this location is fully included in the analysis,
        = all child device-groups also included)

        :param location_name: (str) The name of the current location
        :param progress: (rich.progress.Progress) The rich.Progress object to update while progressing
        :param task: (rich.progress.Task) The rich.Task object to update while progressing
        :return:
        """

        # Populating the global _cleaning_count object, which is used to display the number of objects
        # cleaned / replaced on each device-group on the final report
        self._cleaning_counts[location_name] = {
            x: {'removed': 0, 'replaced': 0} for x in self._replacements.get(location_name, list())
        }

        # removing replaced objects from used_objects_set for current location_name
        for type in self._replacements.get(location_name, list()):
            for name, infos in self._replacements[location_name][type].items():
                # Remind that objects marked as "blocked" on the _replacements tracker should not be removed :
                # They have not been replaced as expected, because used on rules where the opstate values
                # (last_hit_timestamp and last_change_timestamp) are not in the allowed boundaries
                if not infos['blocked']:
                    try:
                        # For the current replacement, remove the original object from the _used_objects_set for the
                        # current location, and replace it with the replacement object
                        self._used_objects_sets[location_name].remove(infos['source'])
                        self._used_objects_sets[location_name].add(infos['replacement'])
                        if self._superverbose:
                            self._console.log(f"[{location_name}] Removing unprotected object {name} (location {infos['source'][1]}) from used objects set")
                        # If the name of the current replacement object is different than the replacement one, count it
                        # as a replacement on the _cleaning_counts tracker
                        if infos['source'][1] == location_name and infos['source'][0].name != infos['replacement'][0].name:
                            self._cleaning_counts[location_name][type]['replaced'] += 1
                    # This exception should never be raised but protects the execution
                    except ValueError:
                        self._console.log(f"ValueError when trying to remove {name} from used objects set at location {location_name} : object not found on object set")
                elif self._superverbose:
                    self._console.log(f"[{location_name}] Not removing {name} (location {infos['source'][1]}) from used objects set, as protected by hitcount")

        # After cleaning the current device-group, adding the current location _used_objects_set values to the
        # _used_objects_set of the parent.
        # This will permit to protect used objects on the childs of the hierarchy to be deleted when they exist but are
        # not used on the parents
        parent_dg = self._stored_pano_hierarchy.get(location_name)
        if not parent_dg:
            parent_dg = "shared"
        self._used_objects_sets[parent_dg] = self._used_objects_sets[parent_dg].union(self._used_objects_sets[location_name])


        # Iterating over each object type / object for the current location, and check if each object is member
        # (or still member, as the replaced ones have been suppressed) of the _used_objects_set for the same location
        # If they are not, they can be deleted
        for type in self._objects[location_name]:
            if type != "context":
                for o in self._objects[location_name][type]:
                    if not (o, location_name) in self._used_objects_sets[location_name]:
                        self._console.log(f"Object {o.name} ({o.__class__.__name__}) can be deleted at location {location_name}")
                        self._cleaning_counts[location_name][type]['removed'] += 1

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