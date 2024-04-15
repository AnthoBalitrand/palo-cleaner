import rich.progress
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.traceback import install
import panos.objects
from panos.panorama import Panorama, DeviceGroup, PanoramaDeviceGroupHierarchy
from panos.objects import AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, PreRulebase, PostRulebase, Rulebase, NatRule, AuthenticationRule, PolicyBasedForwarding, DecryptionRule, ApplicationOverride
from panos.predefined import Predefined
from panos.errors import PanXapiError
from panos.firewall import Firewall
from panos.device import SystemSettings
from hierarchy import HierarchyDG
import PaloCleanerTools
from PaloCleanerConf import repl_map, cleaning_order
import re
import time
import functools
import signal
from multiprocessing import cpu_count
from threading import Thread, Lock
from queue import Queue
from ctypes import c_int32

# TODO : when using bulk-actions, make sure that tag-protected objects are not deleted (can be added to device-group for deletion before this check !)
# TODO : block bulk operations depending of Panorama / PAN-OS version !!!
# TODO : check if replace in rules behavior is the same than replace in groups (when using bulk actions) : merge instead to update ? 


class PaloCleaner:
    def __init__(self, report_folder, **kwargs):
        """
        PaloCleaner class initialization function

        :param report_folder: (string) The path to the folder where to store the operation report
        :param kwargs: (dict) Dict of arguments provided by argparse
        """
        self._panorama_url = kwargs['panorama_url']             # the target Panorama URL
        self._panorama_user = kwargs['api_user']                # the XML API user for interacting with Panorama
        self._panorama_password = kwargs['api_password']        # the associated XML API password

        # Remove api_password from args to avoid it to be printed later (startup arguments are printed in log file)
        kwargs['api_password'] = None

        self._dg_filter = kwargs['device_groups']               # list of device-groups to be included in the operation
        self._protect_tags = kwargs['protect_tags'] if kwargs['protect_tags'] else list()   # list of tags for which associated objects need to be preserverd
        self._analysis_perimeter = None                         # initialized in the get_pano_dg_hierarchy() function. Contains a dict with fully, direct and indirect included device-groups 
        self._depthed_tree = dict({0: ['shared']})              # initialized in the get_pano_dg_hierarchy() function. Contains a dict representing the DG hierarchy depth level (key is the depth level, associated with the list of DG at this level)
        self._reversed_tree = dict()                            # initialized in the get_pano_dg_hierarchy() function. Each key (device group name) contains the list of names of the child device groups 
        self._apply_cleaning = kwargs['apply_cleaning']         # boolean, indicating if this is just a dry-run or a real cleaning operation
        self._tiebreak_tag = kwargs['tiebreak_tag']             # the tiebreak tag name to be applied on tiebreaked objects 
        self._tiebreak_tag_set = set(self._tiebreak_tag) if self._tiebreak_tag else set() # the tiebreak tag in a set() instance, used later in this form 
        self._apply_tiebreak_tag = kwargs['apply_tiebreak_tag'] # boolean, indicating if the tiebreak tag needs to be applied to tiebreaked objects or not 
        self._no_report = kwargs['no_report']                   # boolean, indicating if the generation of a report should be avoided or not 
        self._split_report = kwargs['split_report']             # boolean, indicating if we need to generate a distinct report for each device-group 
        self._favorise_tagged_objects = kwargs['favorise_tagged_objects']   # boolean, indicated if tagged objects should be favorised by the tiebreak logic
        self._same_name_only = kwargs['same_name_only']         # boolean, indicating if we are running in a mode where we only replace objects existing with same name (and value) upward
        self._nb_thread = kwargs['number_of_threads']           # number of threads to generate when using multithread mode 
        self._unused_only = kwargs['unused_only']               # list of device-groups on which we want to delete unused only objects. If this argument has been provided at startup without specifying device-groups, it will be an empty list. If not provided at all, will be None 
        if self._nb_thread is not None:
            if self._nb_thread == 0: # No value provided, we take the number of system's CPU
                try:
                    self._nb_thread = cpu_count()
                    kwargs['number_of_threads'] = self._nb_thread # We force back the kwargs value for the STARTUP ARGUMENTS value diplay
                except NotImplementedError as e:
                    self._console.log(f"Error: cannot collect the number of available CPUs for multithreading : {e}", style="red")     
            elif self._nb_thread < 0:
                self._console.log(f"Error: number of threads must be positive", style="red")   
                exit()
        self._report_folder = report_folder                     # The path to the folder were the report will eventually be stored (if generated)
        self._panorama = None                                   # Will hold the panos.Panorama object 
        self._objects = dict()                                  # Huge dict datastructure which will hold all of the panos.objects instances by device-group and type 
        self._addr_namesearch = dict()                          # Search datastructure which permits to find a panos.objects.AddressObject or panos.objects.AddressGroup by its name (per device-group) 
        self._tag_namesearch = dict()                           # Search datastructure which permits to find a panos.objects.Tag by its name (per device-group) 
        self._addr_ipsearch = dict()                            # Search datastructure which permits to find all panos.objects.AddressObject matching a given IP address (per device-group)
        self._tag_objsearch = dict()                            # Search datastructure which permits to find all panos.objects.AddressObject and panos.objects.AddressGroup by their associated tags (per device-group)
        self._service_namesearch = dict()                       # Search datastructure which permits to find all panos.objects.ServiceObject and panos.objects.ServiceGroup by its name (per device-group)
        self._service_valuesearch = dict()                      # Search datastructure which permits to find all panos.objects.ServiceObject matching a value (generated by PaloCleanerTools.stringify_service) (per device-group)
        self._used_objects_sets = dict()                        # Huge dict datastructure which contains, for each device-group, a list of tuples (panos.objects, location) of used objects at this level
        self._rulebases = dict()                                # Dict datastructure which contains the reference to the different panos.policies instances (per device-group) 
        self._dg_hierarchy = dict()                             # initialized in the get_pano_dg_hierarchy() function. Contains a hierarchy.HierarchyDG object representing the device-groups hierarchy at each level
        self._tag_referenced = set()                            # Contains a set of tuples (panos.objects, location) listing all tag-referenced objects (used on DAG). Used for replacement of such objects (duplicating tags to the replacement object)
        self._verbosity = int(kwargs['verbosity'])              # Verbosity level of the rich console logs 
        self._max_change_timestamp = int(time.time()) - int(kwargs['max_days_since_change']) * 86400 if kwargs['max_days_since_change'] else 0      # Contains the timestamp after which updated rules cannot be cleaned (when specifying it) 
        self._max_hit_timestamp = int(time.time()) - int(kwargs['max_days_since_hit']) * 86400 if kwargs['max_days_since_hit'] else 0               # Contains the timestamp after which hitted rules cannot be cleaned (when specifying it)
        self._need_opstate = self._max_change_timestamp or self._max_hit_timestamp                                                                  # Boolean, indicating if opstate information will have to be used (using timestamps ?) 
        self._ignore_opstate_ip = [] if kwargs['ignore_appliances_opstate'] is None else kwargs['ignore_appliances_opstate']                        # List of IP addresses of appliances for which we explicitly don't want to check opstate information
        self._console = None                                    # Holds the rich.Console object 
        self._console_context = None                            # Contains the current console context (init, or location). Used in conjunction with self._split_report 
        self.init_console() 
        self._replacements = dict()                             # Huge dict datastructure containing the replacement info (source / replacement) for each type of object (per device-group) 
        self._panorama_devices = dict()                         # When using opstate inforation, dict whose key is the serial number and the value is a panos.firewall.Firewall object 
        self._hitcounts = dict()                                # Dict containing the last_hit_timestamp and rule_modification_timestamp for each rule of each type (per device-group) 
        self._cleaning_counts = dict()                          # Dict tracking the number of deleted / replaced objects of each type (per device-group)
        self._protect_potential_replacements = kwargs['protect_potential_replacements']     # boolean, indicating wether potential replacement objects need to be kept (when using unused-only argument) 
        self._bulk_operations = kwargs['bulk_operations']       # boolean, indicating wether we use bulk XML API requests or not 

        signal.signal(signal.SIGINT, self.signal_handler)
        self._console.log(f"STARTUP ARGUMENTS : {kwargs}")

    def print_contexts(self):
        for l in self._objects:
            self._console.log(f"{l} ({self._objects[l]['context']}) --> {self._objects[l]['context'].children}")

    def loglevel_decorator(self, log_func):
        """
        This is a decorator for the rich.Console.log function which permits to log according to the loglevel configured
        (each Console.log call will contain a "level" argument (if not, the log function will be returned), and the
        log function will be returned (and thus executed) only if the "level" of the current call is below or equal to
        the global loglevel asked when starting the script

        Commenting : OK (16062023)

        :param log_func: A function (here, will be used only with the rich.Console.log function)
        :return: (func) The called function after checking the loglevel
        """

        # Functools.wraps is a better way to use wrappers decorators, which permits to copy the __name__, __doc__
        # and all other elements of the wrapped function into the wrapping function
        @functools.wraps(log_func)
        def wrapper(*xargs, **kwargs):
            if not kwargs.get('level'):
                return log_func(*xargs, **kwargs)
            elif kwargs.pop('level') <= self._verbosity:
                return log_func(*xargs, **kwargs)

        return wrapper

    def status_decorator(self, status_func):
        class FalseStatus:
            def __init__(self):
                self.id = 1

            def __enter__(self):
                return self

            def status(self, *xargs):
                pass

            def update(self, *xargs):
                pass

            def __exit__(self, *xargs):
                pass

        @functools.wraps(status_func)
        def wrapper(*xargs, **kwargs):
            if self._no_report:
                return status_func(*xargs, **kwargs)
            else:
                return FalseStatus()

        return wrapper

    def signal_handler(self, signum, frame):
        """
        Signal handler function which is triggered when SIGINT is received. It permits asking for the used if he really
        wants to interrupt the ongoing processing
        :param signum: SIGNUM information about the interrupt signal handled
        :param frame:
        :return:
        """

        res = input("\n\n  Do you really want to interrupt the running operations ? y/n ")
        if res == 'y':
            raise KeyboardInterrupt
        pass

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
                                                
        by Anthony BALITRAND v1.2                                           

""")
        self._console.print(header_text, style="green", justify="left")

        try:
            if self._unused_only and not self._dg_filter and not "shared" in self._unused_only:
                self._console.log("/!\ No device-group filter provided while using unused-only list used, replicating unused-only list into the device-group filter")
                self._dg_filter = self._unused_only

            # if the API user password has not been provided within the CLI start command, prompt the user
            while self._panorama_password == "":
                self._panorama_password = Prompt.ask(f"Please provide password for API user {self._panorama_user!r}",
                                                     password=True)

            self._console.print("\n\n")
            with self._console.status("Connecting to Panorama...", spinner="dots12") as status:
                try:
                    self._panorama = Panorama(self._panorama_url, self._panorama_user, self._panorama_password)
                    self.get_pano_dg_hierarchy()
                    self._console.log("[ Panorama ] Connection established")
                except PanXapiError as e:
                    self._console.log(f"[ Panorama ] Error while connecting to Panorama : {e.message}", style="red")
                    return 0
                except Exception as e:
                    self._console.log("[ Panorama ] Unknown error occurred while connecting to Panorama", style="red")
                    return 0

                # if list of device-groups has been provided, check if all those device-groups exists in the
                # Panorama downloaded hierarchy. If not, stop.
                if self._dg_filter:
                    if not set(self._dg_filter).issubset(self._dg_hierarchy):
                        self._console.log("[ Panorama ] One of the provided device-groups does not exist !", style="red")
                        return 0

                # get the full device-groups hierarchy and displays is in the console with color code to identify which
                # device-groups will be concerned by the cleaning process
                status.update("Parsing device groups list")
                hierarchy_tree = self._dg_hierarchy['shared'].get_tree()
                time.sleep(1)
                self._console.print("Discovered hierarchy tree is the following :")
                self._console.print(
                    "( [red] + are directly included [/red] / [yellow] * are indirectly included [/yellow] / [green] - are not included [/green] )")
                self._console.print(
                    " F (Fully included = cleaned) / P (Partially included = not cleaned) "
                )
                self._console.print(Panel(hierarchy_tree))
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
                self._console.print(
                    Panel("[bold green]Downloading objects and rulebases",
                          style="green"),
                    justify="left")
                download_task = progress.add_task("", total=len(perimeter) + 1)

                # ----------------------------------------------------------------------------------
                # --           Download of Panorama (shared) / predefined objects                 --
                # ----------------------------------------------------------------------------------
                progress.update(download_task, description="[ Panorama ] Downloading shared objects")
                self.fetch_objects(self._panorama, 'shared')
                self.fetch_objects(self._panorama, 'predefined')
                self._console.log(f"[ Panorama ] Shared objects downloaded ({self.count_objects('shared')} found)")

                # calling a function which will make sure that the tiebreak-tag exists (if requested as argument)
                # and will create it if it does not
                self.validate_tiebreak_tag()

                progress.update(download_task, description="[ Panorama ] Downloading shared rulebases")
                self.fetch_rulebase(self._panorama, 'shared')
                self._console.log(f"[ Panorama ] Shared rulebases downloaded ({self.count_rules('shared')} rules found)")

                progress.update(download_task, description="[ Panorama ] Downloading managed devices information")
                self.get_panorama_managed_devices()
                self._console.log(f"[ Panorama ] Managed devices information downloaded (found {len(self._panorama_devices)} devices)")

                progress.update(download_task, advance=1)

                # ----------------------------------------------------------------------------------
                # --             Download of the device-groups objects                            --
                # ----------------------------------------------------------------------------------
                for (context_name, dg) in perimeter:
                    progress.update(download_task, description=f"[ {context_name} ] Downloading objects")
                    self.fetch_objects(dg, context_name)
                    self._console.log(f"[ {context_name} ] Objects downloaded ({self.count_objects(context_name)} found)")
                    progress.update(download_task, description=f"[ {context_name} ] Downloading rulebases")
                    self.fetch_rulebase(dg, context_name)
                    self._console.log(f"[ {context_name} ] Rulebases downloaded ({self.count_rules(context_name)} rules found)")

                    # if opstate (hit counts) has to be cared, download on each device member of the device-group
                    # if this device-group has no child device-group
                    if self._need_opstate and not self._reversed_tree.get(context_name):
                        progress.update(
                            download_task,
                            description=f"[ {context_name} ] Downloading hitcounts (connecting to devices)"
                        )
                        self.fetch_hitcounts(dg, context_name)
                        self._console.log(f"[ {context_name} ] Hitcounts downloaded for all rulebases")

                    progress.update(download_task, advance=1)
                progress.remove_task(download_task)

                # ----------------------------------------------------------------------------------
                # --             Processing used objects set for shared + device-groups           --
                # ----------------------------------------------------------------------------------
                self._console.print(
                    Panel("[bold green]Analyzing objects usage",
                          style="green"),
                    justify="left")
                # Processing used objects set at location "shared"
                shared_fetch_task = progress.add_task("[Panorama] Processing used objects location",
                                                      total=self.count_rules('shared'))
                self.fetch_used_obj_set("shared", progress, shared_fetch_task)
                self._console.log("[ Panorama ] Used objects set processed")
                progress.remove_task(shared_fetch_task)

                # Processing used objects set for each location included in the analysis perimeter
                for (context_name, dg) in perimeter:
                    dg_fetch_task = progress.add_task(
                        f"[{dg.about()['name']}] Processing used objects location",
                        total=self.count_rules(dg.about()['name'])
                    )
                    self.fetch_used_obj_set(dg.about()['name'], progress, dg_fetch_task)
                    self._console.log(f"[ {dg.about()['name']} ] Used objects set processed")
                    progress.remove_task(dg_fetch_task)

                # ----------------------------------------------------------------------------------
                # --       Starting objects optimization (from deepest DG to shared)              --
                # ----------------------------------------------------------------------------------
                self._console.print(
                    Panel("[bold green] Optimizing objects duplicates",
                          style="green"),
                    justify="left")
                # starting objects optimization from the most "depth" device-groups, up to "shared"
                for depth, contexts in sorted(self._depthed_tree.items(), key=lambda x: x[0], reverse=True):
                    for context_name in contexts:
                        if context_name in self._analysis_perimeter['direct'] + self._analysis_perimeter['indirect']:
                            # initialize the console with a new context name (used when splitting reports)
                            self.init_console(context_name)
                            self._console.print(Panel(f"  [bold magenta]{context_name}  ", style="magenta"),
                                              justify="left")

                            # Initializing a dict (on the global _replacements dict) which will contain information about the replacement
                            # done for each object type at the current location
                            self._replacements[context_name] = {'Address': dict(), 'Service': dict(), 'Tag': dict()}

                            if context_name not in ['shared', 'predefined']:
                                self._panorama.add(self._objects[context_name]['context'])

                            # if unused-only has not been specified (normal use-case), or if it has been used with protect-potential-replacements 
                            # we need to start an objects optimization for the current context 
                            # (note that the tiebreak tag will be added to choosen objects at this step)
                            if self._unused_only is None or self._protect_potential_replacements:
                                # OBJECTS OPTIMIZATION
                                dg_optimize_task = progress.add_task(
                                    f"[ {context_name} ] - Optimizing objects",
                                    total=len(self._used_objects_sets[context_name])
                                )
                                self.optimize_objects(context_name, progress, dg_optimize_task)
                                self._console.log(f"[ {context_name} ] Objects optimization done")
                                progress.remove_task(dg_optimize_task)

                            # if we have not specified an unused-only cleaning operation, we need to replace the non-optimal objects by their processed replacements (in groups, rules, etc)
                            if self._unused_only is None:
                                # OBJECTS REPLACEMENT IN GROUPS
                                dg_replaceingroups_task = progress.add_task(
                                    f"[ {context_name} ] Replacing objects in groups",
                                    total=len(self._replacements[context_name]['Address']) + len(self._replacements[context_name]['Service'])
                                )
                                self.replace_object_in_groups(context_name, progress, dg_replaceingroups_task)
                                self._console.log(f"[ {context_name} ] Objects replaced in groups")
                                progress.remove_task(dg_replaceingroups_task)

                                #input("Press any key to continue...")

                                # OBJECTS REPLACEMENT IN RULEBASES
                                dg_replaceinrules_task = progress.add_task(
                                    f"[ {context_name} ] Replacing objects in rules",
                                    total=self.count_rules(context_name)
                                )

                                self.replace_object_in_rulebase(context_name, progress, dg_replaceinrules_task)
                                self._console.log(f"[ {context_name} ] Objects replaced in rulebases")
                                progress.remove_task(dg_replaceinrules_task)

                                #input("Press any key to continue...")

                            # OBJECTS CLEANING (FOR FULLY INCLUDED DEVICE GROUPS ONLY)
                            if context_name in self._analysis_perimeter['full']:
                                self.clean_local_object_set(context_name)
                                self._console.log(f"[ {context_name} ] Objects cleaned (fully included)")

                            if context_name not in ['shared', 'predefined']:
                                self._panorama.remove(self._objects[context_name]['context'])

                            #input("Press any key to continue...")

            self.init_console("report")
            # Display the cleaning operation result (display again the hierarchy tree, but with the _cleaning_counts
            # information (deleted / replaced objects of each type for each device-group)
            self._console.print(Panel(self._dg_hierarchy['shared'].get_tree(self._cleaning_counts)))
        except KeyboardInterrupt as e:
            self._console.log("PROCESS INTERRUPTED BY USER")
        finally:
            # If the --no-report argument was not used at startup, export the console content to an HTML report file
            if not self._no_report:
                self._console.save_html(self._report_folder+'/report.html')

    def init_console(self, context_name=None):
        """
        Initializes a new rich.Console object if the split_report argument has been specified at startup
        Save the previous (replaced) Console to html file before creating the new one
        :param context_name: (str) The name of the context (device-group) concerned by the logs which will be sent to
        this Console
        :return:

        """

        if not context_name and not self._console:
            self._console = Console(record=not self._no_report)
            self._console_context = "init"
        elif context_name and not self._no_report and self._split_report:
            self._console.save_html(self._report_folder+'/'+self._console_context+'.html')
            self._console = Console(record=True)
            self._console_context = context_name
        self._console.log = self.loglevel_decorator(self._console.log)
        self._console.status = self.status_decorator(self._console.status)
        rich.traceback.install(console=self._console)

    def get_devicegroups(self) -> [DeviceGroup]:
        """
        Gets list of DeviceGroups from Panorama
        :return: (list) List of DeviceGroup objects

        Commenting : OK (16062023)
        """

        # Gets the DeviceGroup list from Panorama
        # Does not get full tree (only DeviceGroup name instances)
        # Retrieved DG are not added to Panorama as childs (add=False)
        dg_list = DeviceGroup.refreshall(self._panorama, name_only=True, add=False)
        return dg_list

    def get_pano_dg_hierarchy(self):
        """
        Get DeviceGroupHierarchy from Panorama
        :return:
        """
        try:
            if not self._dg_hierarchy:
                temp_pano_hierarchy = PanoramaDeviceGroupHierarchy(self._panorama).fetch()
                shared_dg = HierarchyDG('shared')
                shared_dg.level = 0
                self._dg_hierarchy['shared'] = shared_dg
                while len(self._dg_hierarchy) < len(temp_pano_hierarchy) + 1:
                    for k, v in temp_pano_hierarchy.items():
                        if (v in self._dg_hierarchy or v is None) and k not in self._dg_hierarchy:
                            self._dg_hierarchy[k] = HierarchyDG(k)
                            if v:
                                self._dg_hierarchy[k].add_parent(self._dg_hierarchy[v])
                            else:
                                self._dg_hierarchy[k].add_parent(shared_dg)
                        if v is None:
                            v = 'shared'
                        self._reversed_tree[v] = self._reversed_tree[v] + [k] if v in self._reversed_tree.keys() else [k]
                        if k not in self._reversed_tree.keys():
                            self._reversed_tree[k] = list()
                if self._dg_filter:
                    for dg in self._dg_filter:
                        self._dg_hierarchy[dg].set_included(direct=True)
                else:
                    self._dg_hierarchy['shared'].set_included(direct=True)

                self._analysis_perimeter = HierarchyDG.get_perimeter(self._dg_hierarchy)
                self._depthed_tree = HierarchyDG.gen_depth_tree(self._dg_hierarchy)

        except Exception as e:
            self._console.log(f"[ Panorama ] Error occurred while parsing device groups : {e}", style="red")
            raise Exception

    def get_panorama_managed_devices(self):
        """
        Get the list of managed devices by Panorama
        And stores it in a dict where they key is the firewall SN, and the value is the panos.Firewall object
        Commenting : OK (15062023)
        :return:
        """
        devices = self._panorama.refresh_devices(expand_vsys=False, include_device_groups=False)
        for fw in devices:
            if fw.state.connected:
                self._panorama_devices[getattr(fw, "serial")] = fw

    def count_objects(self, location_name):
        """
        Returns the global count of all objects (Address, Tag, Service) for the provided location
        Commenting : OK (15062023)

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
        Commenting : OK (15062023)

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
        Gets the list of objects (AddressObject,AddressGroup,Tag,ServiceObject,ServiceGroup) for the provided location
        Stores it in the global _objects dict (per location name as a key) and initializes search structures
        Commenting : OK (15062023)

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
            self._panorama.children.remove(predef)

        else:
            # for any other location, download all objects instances

            # store the context (Panorama or DeviceGroup) object on the 'context' key
            self._objects[location_name]['context'] = context

            # download all AddressObjects and AddressGroups for the location, and add it to the 'Address' key
            self._objects[location_name]['Address'] = AddressObject.refreshall(context, add=False) + \
                                                      AddressGroup.refreshall(context, add=False)

            # populate the _addr_namesearch structure which permits to find AddressObjects and AddressGroups by name
            self._addr_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['Address']}
            self._console.log(f"[ {location_name} ] Objects namesearch structures initialized", level=2)

            # initialize specific search structures
            self._addr_ipsearch[location_name] = dict()
            self._tag_objsearch[location_name] = dict()

            # populate IP and tag search structures for all Address objects (AddressObject and AddressGroup)
            for obj in self._objects[location_name]['Address']:
                if type(obj) is panos.objects.AddressObject:
                    # call to hostify_address to remove /32 for host addresses (keeps mask for subnets)
                    addr = PaloCleanerTools.hostify_address(obj.value)

                    # add the object to the _addr_ipsearch structure which permits to find all AddressObjects for a
                    # given location having the same IP address
                    if addr not in self._addr_ipsearch[location_name].keys():
                        self._addr_ipsearch[location_name][addr] = list()
                    self._addr_ipsearch[location_name][addr].append(obj)

                if type(obj) in [panos.objects.AddressObject, panos.objects.AddressGroup]:
                    # if the object has tags, add it to the _tag_objsearch structure which permits to find all
                    # AddressObjects and AddressGroups at a given location having a certain tag
                    # (a given object is added to each self._tag_objsearch[location_name][t] for each tag it uses)
                    if obj.tag:
                        for t in obj.tag:
                            if t not in self._tag_objsearch[location_name]:
                                self._tag_objsearch[location_name][t] = {obj}
                            else:
                                self._tag_objsearch[location_name][t].add(obj)
            self._console.log(f"[ {location_name} ] Objects ipsearch structures initialized", level=2)

            # download all Tag objects for the location, and add it to the 'Tag' key
            self._objects[location_name]['Tag'] = Tag.refreshall(context, add=False)
            # populate the _tag_namesearch structure which permits to find Tags by name
            self._tag_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['Tag']}
            self._console.log(f"[ {location_name} ] Tags namesearch structure initialized", level=2)

            # download all ServiceObject and ServiceGroups for the location, and add it to the 'Service' key
            self._objects[location_name]['Service'] = ServiceObject.refreshall(context, add=False) + \
                                                      ServiceGroup.refreshall(context, add=False)
            # populate the _service_namesearch structure which permits to find Services by name
            self._service_namesearch[location_name] = {x.name: x for x in self._objects[location_name]['Service']}
            self._console.log(f"[ {location_name} ] Services namesearch structures initialized", level=2)

        # for all locations (including predefined), populate the _service_valuesearch structure which permits to find
        # Services by "stringified" value (see PaloCleanerTools.stringify_service())
        self._service_valuesearch[location_name] = dict()
        for obj in self._objects[location_name]['Service']:
            if type(obj) is ServiceObject:
                serv_string = PaloCleanerTools.stringify_service(obj)
                if serv_string not in self._service_valuesearch[location_name].keys():
                    self._service_valuesearch[location_name][serv_string] = list()
                self._service_valuesearch[location_name][serv_string].append(obj)
        self._console.log(f"[ {location_name} ] Services valuesearch structures initialized", level=2)

    def fetch_rulebase(self, context, location_name):
        """
        Downloads rulebase for the requested context
        Commenting : OK (15062023)

        :param context: (Panorama or DeviceGroup) instance to be used for fetch operation
        :param location_name: (string) Name of the location (Panorama or DeviceGroup name)
        :return:
        """

        # create _rulebases[location] if not yet existing
        if location_name not in self._rulebases.keys():
            self._rulebases[location_name] = dict()

        # create a "context" key on the current location dict which will contain the current location DeviceGroup object
        self._rulebases[location_name]['context'] = context

        for ruletype in repl_map:
            rulebases = [PreRulebase(), PostRulebase()]

            # SecurityRule type has a "Default Rule" section, which is not considered PreRulebase() nor PostRulebase()
            if ruletype is SecurityRule:
                rulebases += [Rulebase()]

            for rb in rulebases:
                # add the current rulebase to the context
                context.add(rb)

                # get all rules for the given RuleType / Rulebase tuple
                self._rulebases[location_name][rb.__class__.__name__+"_"+ruletype.__name__] = ruletype.refreshall(
                    rb,
                    add=False)

                # Remove rulebase from DG
                context.remove(rb)
        #self._rulebases[location_name]['context'].children=list()

    def fetch_hitcounts(self, context, location_name):
        """
        Get the hitcounts for all rules at the requested location
        last_hit_timestamp can only be get from the devices (not from Panorama)
        rule_modification_timestamp can be get from the devices running PAN-OS 9+

        If no devices are running PAN-OS 9+ for the concerned device-group, the rule_modification_timestamps
        is get from Panorama

        Commenting : OK (15062023)

        :param context: (panos.DeviceGroup) DeviceGroup object
        :param location_name: (string) The location name (= DeviceGroup name)
        :return:
        """

        # get the Firewall() objects instance for the current context
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
            # get the device information from _panorama_devices using the firewall appliance serial number
            device = self._panorama_devices.get(getattr(fw, "serial"))
            if device:
                system_settings = device.find("", SystemSettings)
                fw_ip = system_settings.ip_address

                # if the current firewall instance has not been ignored using the --ignore-appliances-opstate argument
                # connect to it to get the opstate values
                if fw_ip not in self._ignore_opstate_ip:
                    fw_vsys = getattr(fw, "vsys")
                    fw_conn = Firewall(fw_ip, self._panorama_user, self._panorama_password, vsys=fw_vsys)
                    # TODO : timeout connection + retry ?
                    self._console.log(f"[ {location_name} ] Connecting to firewall {fw_ip} on vsys {fw_vsys}")
                    fw_panos_version = fw_conn.refresh_system_info().version
                    if (current_major_version := int(fw_panos_version.split('.')[0])) > min_member_major_version:
                        min_member_major_version = current_major_version
                    self._console.log(f"[ {location_name} ] Detected PAN-OS version on {fw_ip} : {fw_panos_version}",
                                      level=2)
                    rb = Rulebase()
                    fw_conn.add(rb)
                    # iterat through each rulebase to get opstate information
                    for rulebase in rulebases:
                        ans = rb.opstate.hit_count.refresh(rulebase, all_rules=True)
                        # call to the populate_hitcounts() function to populate information on the _hitcounts structure
                        populate_hitcounts(rulebase, ans)
            else:
                self._console.log(f"[ {location_name} ] Appliance with SN {getattr(fw, 'serial')} has not been found !",
                                  style="red")

        if min_member_major_version < 9:
            # if we did not found any member firewall with PANOS >= 9, we need to get the rule modification timestamp
            # from Panorama for this context
            self._console.log(
                f"[ {location_name} ] Not found any member with PAN-OS version >= 9. Getting rule modification timestamp from Panorama",
                level=2)
            for rb_type in [PreRulebase(), PostRulebase()]:
                context.add(rb_type)
                for rulebase in rulebases:
                    ans = rb_type.opstate.hit_count.refresh(rulebase, all_rules=True)
                    populate_hitcounts(rulebase, ans)

    def validate_tiebreak_tag(self):
        """
        This function will check that the tiebreak tag exists (on shared context) if it has been requested
        If it does not exists, it will be created and added to the (already fetched) objects set for shared context

        Commenting : OK (15062023)

        :return:
        """

        if self._tiebreak_tag:
            if not self._tiebreak_tag[0] in self._tag_namesearch['shared']:
                self._console.log(f"[ Panorama ] Creating tiebreak tag {self._tiebreak_tag[0]} on shared context")
                tiebreak_tag = Tag(name=self._tiebreak_tag[0])
                self._objects['shared']['Tag'].append(tiebreak_tag)
                self._tag_namesearch['shared'][self._tiebreak_tag[0]] = tiebreak_tag
                if self._apply_cleaning:
                    self._panorama.add(tiebreak_tag).create()
                    self._panorama.remove(tiebreak_tag)

    def get_relative_object_location(self, obj_name, reference_location, obj_type="Address", find_all=False, iterative_call=False):
        """
        Find referenced object by location (permits to get the referenced object on current location if
        existing at this level, or on upper levels of the device-groups hierarchy)
        Commenting : OK (15062023)

        :param obj_name: (string) Name of the object to find
        :param reference_location: (string) Where to start to find the object (device-group name or 'shared')
        :param obj_type: (string) Type of object to look for (default = AddressGroup or AddressObject)
        :return: (AddressObject, string) Found object (or group), and its location name
        """

        # Initialize return variables
        found_tuples = list()
        found_object = None

        # For each object at the reference_location level, find any object having the searched name
        if obj_type == "Address":
            found_object = self._addr_namesearch[reference_location].get(obj_name, None)
        elif obj_type == "Tag":
            found_object = self._tag_namesearch[reference_location].get(obj_name, None)
        elif obj_type == "Service":
            found_object = self._service_namesearch[reference_location].get(obj_name, None)

        if found_object:
            found_tuples.append((found_object, reference_location))

        # if no object is found at current reference_location, find the upward device-group on the hierarchy
        # and call the current function recursively with this upward level as reference_location
        if (not found_tuples or find_all) and reference_location not in ['shared', 'predefined']:
            upward_dg = self._dg_hierarchy[reference_location].parent.name
            found_tuples += self.get_relative_object_location(obj_name, upward_dg, obj_type, find_all, iterative_call=True)
        elif (not found_tuples or find_all) and (obj_type == "Service" and reference_location == 'shared'):
            upward_dg = "predefined"
            found_tuples += self.get_relative_object_location(obj_name, upward_dg, obj_type, find_all, iterative_call=True)

        # log an error message if the requested object has not been found at this step
        if not found_tuples:
            self._console.log(
                f"[ {reference_location} ] ERROR Unable to find object {obj_name} (type {obj_type}) here and above",
                level=2,
            )

        # finally return the tuple of the found object and its location
        if iterative_call:
            return found_tuples
        elif find_all:
            return found_tuples
        else:
            if not found_tuples:
                return (None, None)
            return found_tuples[0]

    def gen_condition_expression(self, condition_string: str, search_location: str):
        """
        Creates dynamically an executable Python statement used to find objects matching a DAG condition
        on the self._tag_objsearch structure
        Example :
        condition_string = "'tag1' and ('tag2' or 'tag3')"
        search_location = "fwtest"
        Output :
        cond_expr_result = "self._tag_objsearch[fwtest].get('tag1', set()) & (self._tag_objsearch[fwtest].get('tag2', set()) ^ self._tag_objsearch[fwtest].get('tag3', set()))"

        :param condition_string: The DAG (AddressGroup) dynamic statement
        :param search_location: The location where to find the matching objects
        :return:
        """

        condition = condition_string.replace('and', '&')
        condition = condition.replace('or', '^')
        condition = condition.replace('AND', '&')
        condition = condition.replace('OR', '^')
        # remove all quotes from the logical expression
        condition = condition.replace('\'', '')
        condition = condition.replace('\"', '')
        condition = re.sub("((\w|-|:|\+)+)", rf"self._tag_objsearch['{search_location}'].get('\1', set())", condition)

        condition = "cond_expr_result = " + condition
        return condition

    def get_relative_object_location_by_tag(self, dag_condition, reference_location, dag_name):
        """
        Recursive function, used to find all objects matching a DAG statement

        :param dag_condition: The AddressGroup.dynamic_value
        :param reference_location: The location where to find matching objects for this recursive iteration
        :param dag_name: The name of the DAG being analyzed (only used for logging purposes if exception is matched)
        :return: list((obj, location)): List of tuples of (Object, location) matching the DAG statement
        """

        found_objects = list()
        condition_expr = self.gen_condition_expression(dag_condition, reference_location)
        expr_result = dict()
        try:
            exec(condition_expr, locals(), expr_result)
        except Exception as e:
            self._console.log(f"[ {reference_location} ] Exception {e} while executing DAG {dag_name} match condition {dag_condition} (transformed to {condition_expr}", style="red")
        found_objects += [(x, reference_location) for x in expr_result['cond_expr_result']]

        if reference_location != 'shared':
            upward_dg = self._dg_hierarchy[reference_location].parent.name
            found_objects += self.get_relative_object_location_by_tag(dag_condition, upward_dg, dag_name)

        return found_objects

    def flatten_object(self, used_object: panos.objects, object_location: str, usage_base: str,
                           referencer_type: str = None, referencer_name: str = None,
                       resolved_cache=None):
        """
        Recursive caller for the inner flatten_object_recurser function.
        Commenting : OK (15062023)

        :param used_object:
        :param object_location:
        :param usage_base:
        :param referencer_type:
        :param referencer_name:
        :param resolved_cache:
        :return:
        """

        if resolved_cache is None:
            resolved_cache = dict()

        def flatten_object_recurser(used_object: panos.objects, object_location: str, usage_base: str,
                           referencer_type: str = None, referencer_name: str = None, recursion_level: int = 1,
                           protect_call=False):
            """
            Recursively called function, charged of returning the obj_set (list of (panos.objects, location)) for a given rule
            (first call is from a loop iterating over the different rules of a rulebase at a given location)

            Calls itself recursively for AddressGroups (static or dynamic)

            Commenting : OK (15062023)

            :param used_object: (panos.object) The used object (found with get_relative_object_location)
            :param object_location: (string) The location where the used objects has been found by get_relative_object_location
            :param usage_base: (string) The location where the object has been found used (from where it has to be flattened)
            :param referencer_type: (string) The type (class.__name__) of the object where the reference to used_object has been found
            :param referencer_name: (string) The name of the object where the reference to used_object has been found
                (can be a rule, an AddressGroup...)
            :param recursion_level: (int) The level of recursion for this call to the flatten_object function
                (is used for log outputs, prepending * recursion_level times at the beginning of each log message)
            :param protect_call: (bool) Whether this call is intended to protect group members at the group level if
                they have been overridden at a lower location

            :return:
            """

            # Initializes an empty list which will contain tuples of (panos.Object, location_name) of the flattened group content
            obj_set = list()

            # If used_object has been resolved at the time of calling the flatten_object function, mark it as resolved
            # (in cache) for the "usage_base" location (adding its name) and add the (object, location) tuple to the obj_set list
            if not isinstance(used_object, type(None)):
                self._console.log(
                        f"[ {usage_base} ] {'*' * recursion_level} Marking {used_object.name!r} ({used_object.__class__.__name__}) as resolved on cache",
                        style="green", level=2)
                resolved_cache[PaloCleanerTools.shorten_object_type(used_object.__class__.__name__)].append(
                    used_object.name)

                # adding the resolved (used_object, object_location) itself to the obj_set list
                obj_set.append((used_object, object_location))

            # if the resolved object is a "simple" object (not needing recursive search), just display a log indicating
            # that search is over for this one
            if type(used_object) in [panos.objects.AddressObject, panos.objects.ServiceObject, panos.objects.Tag]:
                self._console.log(
                        f"[ {usage_base} ] {'*' * recursion_level} Object {used_object.name!r} ({used_object.__class__.__name__}) (ref by {referencer_type} {referencer_name}) has been found on location {object_location}",
                        style="green", level=3)

            # if the resolved object needs recursive search for members (AddressGroup), let's go
            # here for an AddressGroup
            elif type(used_object) is panos.objects.AddressGroup:
                # in case of a static group, just call the flatten_object function recursively for each member
                # (which can be only at the group level or above)
                if used_object.static_value:
                    self._console.log(
                            f"[ {usage_base} ] {'*' * recursion_level} Object {used_object.name!r} (static AddressGroup) (ref by {referencer_type} {referencer_name!r}) has been found on location {object_location}",
                            style="green", level=3)

                    # for each static group member, call the current function recursively
                    # (if the member has not already been resolved for the current location, which means that it would
                    # already have been flattened)
                    # or if it is a protect_call (voluntarily calling the flatten_object_recurser for the group member
                    # at the same level of the group itself if overridden below, to avoid deletion later)
                    for group_member in used_object.static_value:
                        if group_member not in resolved_cache['Address'] or protect_call:
                            self._console.log(
                                    f"[ {usage_base} ] {'*' * recursion_level} Found group member of AddressGroup {used_object.name!r} : {group_member!r}",
                                    style="green", level=2)

                            # call to the flatten_object function with the following parameters :
                            # panos.Object found for the requested object name (returned by a call to get_relative_object_location)
                            # location of this object (returned by a call to get_relative_object_location)
                            # usage_base = the location where the object is used (can be below the real location of the object)
                            # used_object.__class__.__name__ = the object type where the member has been found used (AddressGroup, actually)
                            # used_object.name = the name of the object where the member has been found (= the group name, actually)
                            # recursion_level = the current recursion_level + 1

                            obj_set += flatten_object_recurser(
                                *self.get_relative_object_location(group_member,usage_base),
                                usage_base,
                                used_object.__class__.__name__,
                                used_object.name,
                                recursion_level + 1)

                    # the condition below permits to "protect" the group members (at group level) if they are overriden at a lower location
                    if object_location != usage_base:
                        self._console.log(
                                f"[ {usage_base} ] {'*' * recursion_level} AddressGroup {used_object.name!r} location ({object_location}) is different than referencer location ({usage_base}). Protecting group at its location level",
                                style="red", level=2)
                        group_protection_flattened = flatten_object_recurser(used_object, object_location, object_location, referencer_type,
                                                  referencer_name, recursion_level, protect_call=True)
                        obj_set += group_protection_flattened

                        # copying the result at the group object location as it needs to be protected there !!
                        # (group might not be used at its location but only below, and it could have unexpected results !!)
                        # TODO : find a solution to make sure that the same replacement object will be choosen there !!!
                        self._used_objects_sets[object_location].update(set(group_protection_flattened))


                # in case of a dynamic group, the group condition is converted to an executable Python statement,
                # for members to be found using their tags
                # for dynamic groups, members can be at any location, upward starting from the usage_base location
                elif used_object.dynamic_value:
                    self._console.log(
                            f"[ {usage_base} ] {'*' * recursion_level} Object {used_object.name!r} (dynamic AddressGroup) (ref by {referencer_type} {referencer_name!r}) has been found on location {object_location}",
                            style="green", level=3)

                    # for each object matched by the get_relative_object_location_by_tag
                    # (= for each object matched by the DAG)
                    for referenced_object, referenced_object_location in self.get_relative_object_location_by_tag(
                        used_object.dynamic_value,
                        usage_base,
                        used_object.name
                    ):
                        self._console.log(
                                f"[ {usage_base} ] {'*' * recursion_level} Found group member of dynamic AddressGroup {used_object.name!r} : {referenced_object.name!r}",
                                style="green", level=2)

                        # the condition below permits to alert for circular references
                        if referenced_object == used_object:
                            self._console.log(
                                f"[ {usage_base} ] {'*' * recursion_level} Circular reference found on dynamic AddressGroup {used_object.name!r}",
                                style="red"
                            )

                        # for each dynamic group member, call the current function recursively
                        # (if the member has not already been resolved for the current location, which means that it would
                        # already have been flattened)
                        if referenced_object.name not in resolved_cache['Address']:
                            # call to the flatten_object function with the following parameters :
                            # referenced_object = the panos.Object found by the get_relative_object_location_by_tag
                            # referenced_object_location = the location of this object (returned by a call to get_relative_object_location_by_tag)
                            # usage_base = the location where the object is used (can be below the real location of the object)
                            # used_object.__class__.__name__ = the object type where the member has been found used (AddressGroup, actually)
                            # used_object.name = the name of the object where the member has been found (= the group name, actually)
                            # recursion_level = the current recursion_level + 1

                            obj_set += flatten_object_recurser(
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
                            # TODO : add the matching tag information to replicate only the needed tags
                            self._tag_referenced.add((referenced_object, referenced_object_location))
                            self._console.log(
                                    f"[ {usage_base} ] {'*' * recursion_level} Marking {referenced_object.name!r} as tag-referenced",
                                    style="green", level=2)
                        else:
                            self._console.log(
                                    f"[ {usage_base} ] {'*' * recursion_level} Address Object {referenced_object.name!r} already resolved in current context",
                                    style="yellow", level=3)

            # or here for ServiceGroup
            elif type(used_object) is panos.objects.ServiceGroup:
                if used_object.value:
                    self._console.log(
                            f"[ {usage_base} ] {'*' * recursion_level} Object {used_object.name!r} (ServiceGroup) has been found on location {object_location}", level=3)
                    for group_member in used_object.value:
                        if group_member not in resolved_cache['Service'] or protect_call:
                            self._console.log(
                                    f"[ {usage_base} ] {'*' * recursion_level} Found group member of ServiceGroup {used_object.name} : {group_member}", level=2)
                            obj_set += flatten_object_recurser(
                                *self.get_relative_object_location(group_member, usage_base, obj_type="Service"),
                                usage_base,
                                used_object.__class__.__name__,
                                used_object.name,
                                recursion_level + 1)

            # checking if the resolved objects has tags (which needs to be added to the used_object_set too)
            # checking if used_object is not None permits to avoid cases where unsupported objects are used on the rule
            # IE : EDL at the time of writing this comment

            if not isinstance(used_object, type(None)):
                if type(used_object) is not panos.objects.Tag:
                    if used_object.tag:
                        for tag in used_object.tag:
                            self._console.log(
                                    f"[ {usage_base} ] {'*' * recursion_level} Object {used_object.name} ({used_object.__class__.__name__}) uses tag {tag}",
                                    style="green", level=2)
                            if tag not in resolved_cache['Tag']:
                                # call to the flatten_object function with the following parameters :
                                # panos.Object (found by the get_relative_object_location function)
                                # the location of this object (found by the get_relative_object_location function)
                                # usage_base = the location where the object is used (can be below the real location of the object)
                                # used_object.__class__.__name__ = the object type where the member has been found used (AddressGroup, actually)
                                # used_object.name = the name of the object where the member has been found (= the group name, actually)
                                # recursion_level = the current recursion_level (not incremented)

                                obj_set += flatten_object_recurser(
                                    *self.get_relative_object_location(tag, object_location, obj_type="Tag"),
                                    usage_base,
                                    used_object.__class__.__name__,
                                    used_object.name,
                                    recursion_level)

            # return the populated obj_set (when fully flattened)
            return obj_set

        if not resolved_cache:
            resolved_cache = dict({'Address': list(), 'Service': list(), 'Tag': list()})

        return flatten_object_recurser(used_object, object_location, usage_base,
                           referencer_type, referencer_name)

    def fetch_used_obj_set(self, location_name, progress, task):
        """
        This function generates a "set" of used objects of each type (Address, AddressGroup, Tag, Service, ServiceGroup...)
        at each requested location.
        This set is a set of tuples of (panos.Object, location (str))
        Group objects are explored (recursively) to find all members, which are of course also considered as used.
        Commenting : OK (15062023)

        :param location_name: (str) The location name where to start used objects exploration
        :param progress: (rich.Progress) The rich Progress object to update during progression
        :param task: (rich.Task) The rich Task object to update during progression
        :return:
        """

        # Initialized the location obj set list which will contain all objects used at this location
        location_obj_set = list()

        # This dict contains a list of names for each object type, for which the location has been already found
        # This considerably improves processing time, avoiding to search again an object which has been already found
        # among the upward locations
        resolved_cache = dict({'Address': list(), 'Service': list(), 'Tag': list()})

        # Regex statements which permits to identify an AddressObject value to know if it represents an IP/mask or a range
        ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$')
        range_regex = re.compile(r'^((\d{1,3}\.){3}\d{1,3}-?){2}$')

        # initializing a list which will create "on-the-fly" created objects for direct IP used in rules
        created_addr_object = list()
        # iterates on all rulebases for the concerned location
        for k, v in self._rulebases[location_name].items():
            if k == "context":
                # if the current key is 'context', pass (as it contains the DeviceGroup object instance)
                continue
            # for each rule in the current rulebase
            for r in v:
                self._console.log(f"[ {location_name} ] Processing used objects on rule {r.name!r}", level=2)

                # Use the repl_map descriptor to find the different types of objects which can be found on the current
                # rule based on its type.
                # Initializes a dict where the key is the object type, and the value is an empty list
                rule_objects = {x: [] for x in repl_map.get(type(r))}

                # for each object type / field name in the repl_map descriptor for the current rule type
                for obj_type, obj_fields in repl_map.get(type(r)).items():
                    # for each rule field using the current object type
                    for field in obj_fields:
                        # if the rule field is a string value, add the object to the rule_objects dict (on the
                        # corresponding key matching the object type)
                        if type(field) is str:
                            if (to_add := getattr(r, field)):
                                rule_objects[obj_type].append(to_add)
                        # else if the rule field is a list, add this list to the rule_objects dict
                        else:
                            # if the rule is a PolicyBasedForwarding rule, the object type can vary...
                            # handling this specific case
                            if type(r) is PolicyBasedForwarding:
                                if type(to_add := getattr(r, field[0])) is str:
                                    rule_objects[obj_type].append(to_add)
                                elif type(to_add) is list:
                                    rule_objects[obj_type] += to_add
                            elif (to_add := getattr(r, field[0])):
                                rule_objects[obj_type] += to_add

                    # for each object (of the current object type) used on the current rule
                    for obj in rule_objects[obj_type]:
                        # if the object name is not in the resolved_cache, it needs to be resolved
                        if obj not in ['any', 'application-default'] and obj not in resolved_cache[obj_type]:
                            # call to the flatten_object function with the following parameters :
                            # panos.Object, location of this object (returned by a call to get_relative_object_location)
                            # location_name = the current location (where the object is used)
                            # r.__class__.__name__ = the rule type
                            # r.name = the rule name
                            # resolved_cache = the already resolved objects cache which will be updated

                            location_obj_set += (
                                flattened := self.flatten_object(
                                    *self.get_relative_object_location(obj, location_name, obj_type),
                                    location_name,
                                    r.__class__.__name__,
                                    r.name,
                                    resolved_cache
                                )
                            )

                            # the following will be executed if the object used has not been found by the
                            # get_relative_object_location call (flatten object will not return anything in such a case)
                            if not flattened:
                                # can be in case of an IP address / subnet directly used on a rule
                                if obj_type == "Address":
                                    if ip_regex.match(obj) or range_regex.match(obj):
                                        # create a (temporary) new AddressObject (whose name is the same as the value)
                                        # and add it to the location_obj_set
                                        addr_value = PaloCleanerTools.hostify_address(obj)
                                        # adding the new created object to the _addr_ipsearch datastructure for the
                                        # current location level, else the replacement process will potentially find
                                        # only 1 replacement object (if there's one), while the current one should be
                                        # found also (replacement will be processed only if at least 2 objects are found)
                                        if addr_value not in self._addr_ipsearch[location_name].keys():
                                            self._addr_ipsearch[location_name][addr_value] = list()
                                        if not addr_value in created_addr_object:
                                            new_addr_obj = AddressObject(name=obj, value=addr_value)
                                            # the description "palocleaner_temp_addressobject" is important as it permits
                                            # later to distiguish this AddressObjects so that it is the least prefered
                                            # one for the replacement process
                                            new_addr_obj.description = "palocleaner_temp_addressobject"
                                            self._addr_ipsearch[location_name][addr_value].append(new_addr_obj)
                                            location_obj_set += [(new_addr_obj, location_name)]
                                            self._console.log(
                                                f"[ {location_name} ] * Created AddressObject for address {obj} used on rule {r.name!r}",
                                                style="yellow")
                                            created_addr_object.append(addr_value)
                                        else:
                                            self._console.log(
                                                f"[ {location_name} ] * Using previously created AddressObject for address {obj} used on rule {r.name!r}",
                                                style="yellow",
                                                level=2,
                                            )

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
                        elif obj not in ['any', 'application-default']:
                            self._console.log(f"[ {location_name} ] * {obj_type} Object {obj!r} already resolved in current context",
                                                  style="yellow", level=3)
                # update progress bar for each processed rule
                progress.update(task, advance=1)

        # add the processed object set for the current location to the global _used_objects_set dict
        self._used_objects_sets[location_name] = set(location_obj_set)

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
        obj_addr = PaloCleanerTools.hostify_address(obj.value)

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
            upward_dg = self._dg_hierarchy[current_location_search].parent
            current_location_search = "shared" if not upward_dg else upward_dg.name

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
            upward_dg = self._dg_hierarchy[current_location_search].parent
            # If the result of the upward device-group name is "None", it means that the upward device-group is "shared"
            current_location_search = "shared" if not upward_dg else upward_dg.name

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
            upward_dg = self._dg_hierarchy[current_location_search].parent
            # If the result of the upward device-group name is "None", it means that the upward device-group is "shared"
            current_location_search = "shared" if not upward_dg else upward_dg.name

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
        obj_service_string = PaloCleanerTools.stringify_service(obj_service)

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
            upward_dg = self._dg_hierarchy[current_location_search].parent
            # If the result of the upward device-group name is "None", it means that the upward device-group is "shared"
            current_location_search = "shared" if not upward_dg else upward_dg.name

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
        if self._tiebreak_tag_set:
            for o in sorted(obj_list, key=lambda x: x[0].about()['name']):
                if not choosen_object:
                    try:
                        if (tag_intersect := self._tiebreak_tag_set.intersection(o[0].tag)):
                            choosen_object = o
                            self._console.log(f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen by tiebreak. Intersection set : {tag_intersect}", level=2)
                    except TypeError as e:
                        # This exception is matched when checking if the tiebreak tag is on the list of tags of an
                        # object which has no tags
                        # self._console.log(f"[ {base_location} ] TypeError : {e} checking tags on object {o} --> {o[0].tag}")
                        pass

        # If the tiebreak tag was not used to find the "best" object
        # if some replacements objects are tag-referenced (used on DAG) and if we decided to favorise those ones, they'll be chosen first
        if self._favorise_tagged_objects and not choosen_object:
            for x in obj_list:
                if x in self._tag_referenced and not choosen_object:
                    choosen_object = x
                    self._console.log(f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as tag-referenced", level=2)

        # else continue with the normal process
        if not choosen_object:
            # create a list of shared objects from the obj_list
            shared_obj = [x for x in obj_list if x[1] == 'shared' and getattr(x[0], 'description') != 'palocleaner_temp_addressobject']
            # create a list of intermediate DG objects from the obj_list
            # TODO : concerned line here
            # interm_obj = [x for x in obj_list if x[1] != 'shared' and x[1] != base_location]
            interm_obj = [x for x in obj_list if x[1] != 'shared' and getattr(x[0], 'description') != 'palocleaner_temp_addressobject']
            # create a list of objects having name with multiple "." and ending with "corp" or "com" (probably FQDN)
            fqdn_obj = [x for x in obj_list if
                        len(x[0].about()['name'].split('.')) > 1 and x[0].about()['name'].split('.')[-1] in ['corp', 'com'] and getattr(x[0], 'description') != 'palocleaner_temp_addressobject']
            # find objects being both shared and with FQDN-like naming
            shared_fqdn_obj = list(set(shared_obj) & set(fqdn_obj))
            interm_fqdn_obj = list(set(interm_obj) & set(fqdn_obj))


            # if shared and well-named objects are found, return the first one after sorting by name
            if shared_fqdn_obj and not choosen_object:
                if self._favorise_tagged_objects and len(shared_fqdn_obj) > 1:
                    shared_fqdn_obj.sort(key=PaloCleanerTools.tag_counter)
                    if PaloCleanerTools.tag_counter(shared_fqdn_obj[0]) > PaloCleanerTools.tag_counter(shared_fqdn_obj[1]):
                        choosen_object = shared_fqdn_obj[0]
                        self._console.log(
                            f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object with FQDN naming, and highest number of tags",
                            level=2)
                if not choosen_object:
                    choosen_object = sorted(shared_fqdn_obj, key=lambda x: x[0].about()['name'])[0]
                    self._console.log(
                        f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object with FQDN naming",
                        level=2)
                """
                for o in sorted(shared_fqdn_obj, key=lambda x: x[0].about()['name']):
                    # line below modified to fix issue signaled by Laetitia. Impact has to be evaluated
                    # even if intermediate object has the same name than the shared replacement one, it needs to be the
                    # one used (until deletion of the intermediate one to match the shared one)
                    #if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_fqdn_obj] and not choosen_object:
                    choosen_object = o
                    self._console.log(f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object with FQDN naming", level=2)
                    break
                """
            # else return the first found shared object after sorting by name
            if shared_obj and not choosen_object:
                if self._favorise_tagged_objects and len(shared_obj) > 1:
                    shared_obj.sort(key=PaloCleanerTools.tag_counter)
                    if PaloCleanerTools.tag_counter(shared_obj[0]) > PaloCleanerTools.tag_counter(shared_obj[1]):
                        choosen_object = shared_obj[0]
                        self._console.log(
                            f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object, and highest number of tags",
                            level=2)
                if not choosen_object:
                    choosen_object = sorted(shared_obj, key=lambda x: x[0].about()['name'])[0]
                    self._console.log(
                        f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object",
                        level=2)
                """
                for o in sorted(shared_obj, key=lambda x: x[0].about()['name']):
                    if not choosen_object:
                    #if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_obj] and not choosen_object:
                        choosen_object = o
                        self._console.log(f"[ {base_location} ] Object {o[0].about()['name']} (context {o[1]}) choosen as it's a shared object", level=2)
                """
            # Repeat the same logic for intermediate device-groups
            if interm_fqdn_obj and not choosen_object:
                temp_object_level = 999
                # This code will permit to keep the "highest" device-group level matching object
                # (nearest to the "shared" location)
                for o in sorted(interm_fqdn_obj, key=lambda x: x[0].about()['name']):
                    if not choosen_object:
                        location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                        if location_level < temp_object_level:
                            temp_object_level = location_level
                            choosen_object = o
                self._console.log(f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object with FQDN naming (level = {temp_object_level})", level=2)
            if interm_obj and not choosen_object:
                temp_object_level = 999
                for o in sorted(interm_obj, key=lambda x: x[0].about()['name']):
                    if not choosen_object:
                        location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                        if location_level < temp_object_level:
                            temp_object_level = location_level
                            choosen_object = o
                self._console.log(f"[ {base_location} ] Object {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object (level = {temp_object_level})", level=2)
        # If no best replacement object has been found at this point, display an alert and return the first one in the
        # input list (can lead to random results)
        if not choosen_object:
            self._console.log(f"[ {base_location} ] ERROR : Unable to choose an object in the following list for address {obj_list[0][0].value} : {obj_list}. Returning the first one by default", style="red")
            choosen_object = sorted(obj_list, key=lambda x: x[0].about()['name'])[0]

        # If an object has not been chosen using the tiebreak tag, but the tiebreak tag adding has been requested,
        # then add the tiebreak tag to the chosen object so that it will remain the preferred one for next executions
        # avoid objects having description 'palocleaner_temp_addressobject' as those are temporary objects created
        # 'on-the-fly' by the fetch_used_obj_set() function
        if self._apply_tiebreak_tag and not choosen_by_tiebreak and getattr(choosen_object[0], 'description') != 'palocleaner_temp_addressobject':
            tag_changed = False
            # If the object already has some tags, adding the tiebreak tag to the list
            if choosen_object[0].tag:
                if not self._tiebreak_tag[0] in choosen_object[0].tag:
                    choosen_object[0].tag.append(self._tiebreak_tag[0])
                    tag_changed = True
            # Else if the object has no tags, initialize the list with the tiebreak tag
            else:
                choosen_object[0].tag = [self._tiebreak_tag[0]]
                tag_changed = True

            # If cleaning application is requested and tag has been changed, apply it to Panorama
            if tag_changed:
                if self._apply_cleaning and not self._bulk_operations:
                    try:
                        self._console.log(
                            f"[ {base_location} ] Adding tiebreak tag {self._tiebreak_tag[0]} to {choosen_object[0].__class__.__name__} {choosen_object[0].about()['name']} on context {choosen_object[1]} ")
                        choosen_object[0].apply()
                    except Exception as e:
                        self._console.log(f"[ {base_location} ] ERROR when adding tiebreak tag to object {choosen_object[0].about()['name']} : {e}", style="red")
                else:
                    self._console.log(
                        f"[ {base_location} ] Tiebreak tag {self._tiebreak_tag[0]} application to {choosen_object[0].__class__.__name__} {choosen_object[0].about()['name']} added to bulk operation pool for context {choosen_object[1]} ")
                    self._objects[choosen_object[1]]['context'].add(choosen_object[0])

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

        # If a tiebreak tag has been specified, this is the decision factor to choose the "best" object
        # Not that if several objects have the tiebreak tag (which is not supposed to happen), the first one of the list
        # will be chosen, which can leads to some randomness
        if self._tiebreak_tag_set:
            for o in sorted(obj_list, key=lambda x: x[0].about()['name']):
                if not choosen_object:
                    try:
                        if (tag_intersect := self._tiebreak_tag_set.intersection(o[0].tag)):
                            choosen_object = o
                            self._console.log(
                                f"[ {base_location} ] Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen by tiebreak. Intersection set : {tag_intersect}", level=2)
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
                            x[0].name.lower() == x[0].protocol.lower() + '_' + str(x[0].destination_port)]

            # Find objects being both shared and with standard naming for service objects
            # or being at intermediate locations and with standard naming for service objects
            shared_standard_obj = list(set(shared_obj) & set(standard_obj))
            interm_standard_obj = list(set(interm_obj) & set(standard_obj))

            # If shared and well-named objects are found, return the first one
            if shared_standard_obj and not choosen_object:
                for o in sorted(shared_standard_obj, key=lambda x: x[0].about()['name']):
                    if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_standard_obj]:
                        choosen_object = o
                        self._console.log(
                                f"[ {base_location} ] Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object with standard naming", level=2)
            # Else return the first found shared object
            if shared_obj and not choosen_object:
                for o in sorted(shared_obj, key=lambda x: x[0].about()['name']):
                    if o[0].about()['name'] not in [x[0].about()['name'] for x in interm_obj]:
                        choosen_object = o
                        self._console.log(
                                f"[ {base_location} ] Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's a shared object", level=2)
            # Repeat the same logic for intermediate device-groups
            if interm_standard_obj and not choosen_object:
                temp_object_level = 999
                # This code will permit to keep the "highest" device-group level matching object
                # (nearest to the "shared" location)
                for o in sorted(interm_standard_obj, key=lambda x: x[0].about()['name']):
                    location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                    if location_level < temp_object_level:
                        temp_object_level = location_level
                        choosen_object = o
                self._console.log(
                        f"[ {base_location} ] Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object with standard naming (level = {temp_object_level})", level=2)
            if interm_obj and not choosen_object:
                temp_object_level = 999
                for o in sorted(interm_obj, key=lambda x: x[0].about()['name']):
                    location_level = [k for k, v in self._depthed_tree.items() if o[1] in v][0]
                    if location_level < temp_object_level:
                        temp_object_level = location_level
                        choosen_object = o
                self._console.log(
                        f"[ {base_location} ] Service {choosen_object[0].about()['name']} (context {choosen_object[1]}) choosen as it's an intermediate object (level = {temp_object_level})", level=2)
        # If no best replacement object has been found at this point, display an alert and return the first one in the
        # input list (can lead to random results)
        if not choosen_object:
            self._console.log(f"ERROR : Unable to choose an object in the following list for service {PaloCleanerTools.stringify_service(obj_list[0][0])} : {obj_list}. Returning the first one by default", style="red")
            choosen_object = sorted(obj_list, key=lambda x: x[0].about()['name'])[0]

        # If an object has not been chosen using the tiebreak tag, but the tiebreak tag adding has been requested,
        # then add the tiebreak tag to the chosen object so that it will remain the preferred one for next executions
        if self._apply_tiebreak_tag and not choosen_by_tiebreak:
            tag_changed = False
            # If the object already has some tags, adding the tiebreak tag to the list
            if choosen_object[0].tag:
                if not self._tiebreak_tag[0] in choosen_object[0].tag:
                    choosen_object[0].tag.append(self._tiebreak_tag[0])
                    tag_changed = True
            # Else if the object has no tags, initialize the list with the tiebreak tag
            else:
                choosen_object[0].tag = [self._tiebreak_tag[0]]
                tag_changed = True

            # If cleaning application is requested and tag has been changed, apply it to Panorama
            if tag_changed:
                if self._apply_cleaning and not self._bulk_operations:
                    try:
                        self._console.log(
                            f"[ {base_location} ] Adding tiebreak tag {self._tiebreak_tag[0]} to {choosen_object[0].__class__.__name__} {choosen_object[0].about()['name']} on context {choosen_object[1]}")
                        choosen_object[0].apply()
                    except Exception as e:
                        self._console.log(f"[ {base_location} ] ERROR when adding tiebreak tag to object {choosen_object[0].about()['name']} : {e}", style="red")
                else:
                    self._console.log(f"[ {base_location} ] Tiebreak tag {self._tiebreak_tag[0]} application to {choosen_object[0].__class__.__name__} {choosen_object[0].about()['name']} added to bulk operation pool for context {choosen_object[1]} ")
                    self._objects[choosen_object[1]]['context'].add(choosen_object[0])

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

        # This dict references the function to be used to match the best replacement for each object type
        find_maps = {
            AddressObject: self.find_upward_obj_by_addr,
            AddressGroup: self.find_upward_obj_group,
            ServiceObject: self.find_upward_obj_service,
            ServiceGroup: self.find_upward_obj_service_group
        }

        # for each object type in the list below
        # TODO : find best replacement for servicegroup ?

        for obj_type in [panos.objects.AddressObject, panos.objects.AddressGroup, panos.objects.ServiceObject]:
            #self._console.log(f"[ {location_name} ] Child for DeviceGroup {self._objects[location_name]['context']} when optimizing {obj_type} is {self._objects[location_name]['context'].children}")

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
                            f"[ {location_name} ] Replacing {obj.about()['name']!r} ({obj.__class__.__name__}) at location {location} by {replacement_obj.about()['name']!r} at location {replacement_obj_location}",
                            style="green", level=2)

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

            # applying bulk operation update (apply tiebreak tag to objects modified by find_best_replacement_addr_obj()
            # or find_best_replacement_service_obj()
            # There should be only objects of type obj_type as children at this point, but filtering on it anyway
            if self._bulk_operations and (bulk_targets := [x for x in self._objects[location_name]['context'].children if type(x) is obj_type]):
                self._console.log(f"[ {location_name} ] Applying bulk operation for {obj_type} updates (tiebreak-tag add) ({len(bulk_targets)} objects targeted)")
                if self._apply_cleaning:
                    try:
                        # Using create_similar instead of update_similar
                        # This method is non-destructive for other objects and combines the modified attributes with the existing objects on the device
                        bulk_targets[0].create_similar()
                    except Exception as e:
                        self._console.log(
                            f"[ {location_name} ] ERROR when applying bulk operation for {obj_type} updates (tiebreak tag add) : {e}",
                            style="red")

                # remove all updated objects from the current context children list
                any(self._objects[location_name]['context'].remove(x) for x in bulk_targets)

        if self._objects[location_name]['context'].children:
            self._console.log(f"[ {location_name} ] WARNING : {len(self._objects[location_name]['context'].children)} objects still on context children list. Should be empty at this point. PLEASE INVESTIGATE !")

    def multithread_wrapper(self, wrapped_func):
        @functools.wraps(wrapped_func)
        def wrapper(*xargs, **kwargs):
            if self._nb_thread:
                lock = Lock()
                kwargs['lock'] = lock
                for n in range(self._nb_thread):
                    try:
                        kwargs['thread_id'] = n + 1
                        t = Thread(target=wrapped_func, args=(*xargs,), kwargs=kwargs, daemon=True)
                        t.start()
                        self._console.log(
                            f"[ ] Started thread {n + 1} for function {wrapped_func.__name__}", level=2)
                    except Exception as e:
                        self._console.log(
                            f"[ ] Error while creating and starting thread {n + 1} for function {wrapped_func.__name__} : {e}",
                            style="red")
            else:
                return wrapped_func(*xargs, **kwargs)

        return wrapper

    def replace_object_in_groups(self, location_name: str, progress: rich.progress.Progress, task: rich.progress.TaskID):
        """
        This function replaces the objects for which a better duplicate has been found on the current location groups
        This cannot be done using bulk requests :
            update_similar would delete all groups at the current location, except the ones we want to modify
            create_similar would modify only the concerned groups, but would merge the new members with the existing ones

        :param location_name: (str) The name of the location where to replace objects in groups
        :param progress: (rich.progress.Progress) The rich Progress object to update
        :param task: (rich.progress.Task) The rich Task object to update
        :return:
        """

        # Initializing a dict which will contain information about the replacements done on the different groups
        # (when an object to be replaced has been found on a group), to display it on the result logs
        replacements_done = dict()

        @self.multithread_wrapper
        def replace_in_addr_groups(jobs_queue, progress, task, lock=None, thread_id=0):
            """
            This function replaces the addr objects for which a better duplicate has been found on the current location groups

            :param replacement_name: (str)
            :param replacement: ()
            :return:
            """

            while True:
                if jobs_queue.empty():
                    break

                try:
                    replacement_name, replacement = jobs_queue.get()
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
                            # TODO : test replaced line
                            if not tag in self._tag_namesearch['shared']:
                                # find the original tag (on its actual location)
                                tag_instance, tag_location = self.get_relative_object_location(tag, location_name,
                                                                                               obj_type="tag")
                                self._console.log(
                                    f"[ Panorama ] [Thread-{thread_id}] Creating tag {tag!r} (copy from {tag_location}), to be used on ({replacement_obj_instance.about()['name']} at location {replacement_obj_location})")
                                # if the cleaning application has been requested, create the new tag on Panorama
                                # (this operation is never done using bulk XML API calls)
                                if self._apply_cleaning:
                                    try:
                                        self._panorama.add(tag_instance).create()
                                    except Exception as e:
                                        self._console.log(f"[ Panorama ] [Thread-{thread_id}] Error while creating tag {tag!r} ! : {e.message}",
                                                          style="red")
                                # also add the new Tag object at the proper location (shared) on the local cache
                                # and the various search structures
                                self._objects['shared']['Tag'].append(tag_instance)
                                self._used_objects_sets['shared'].add((tag_instance, 'shared'))
                                self._tag_namesearch['shared'][tag] = tag_instance

                            tag_changed = False
                            # add the new tag to the replacement object
                            if self._nb_thread: lock.acquire()
                            if replacement_obj_instance.tag:
                                if not tag in replacement_obj_instance.tag:
                                    replacement_obj_instance.tag.append(tag)
                                    tag_changed = True
                            else:
                                replacement_obj_instance.tag = [tag]
                                tag_changed = True
                                self._console.log(
                                    f"[ {replacement_obj_location} ] [Thread-{thread_id}] Adding tag {tag} to object {replacement_obj_instance.about()['name']!r} ({replacement_obj_instance.__class__.__name__})",
                                    style="yellow")

                            if tag_changed:
                                if self._apply_cleaning and not self._bulk_operations:
                                    try:
                                        self._console.log(
                                            f"[ {location_name} ] [Thread-{thread_id}] Adding tag {tag} to object {replacement_obj_instance.about()['name']!r} ({replacement_obj_instance.__class__.__name__}) on context {replacement_obj_location}",
                                            style="yellow")
                                        replacement_obj_instance.apply()
                                    except Exception as e:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR when adding tag {tag} to object {replacement_obj_instance.about()['name']!r} ({replacement_obj_instance.__class__.__name__}) on context {replacement_obj_location}", style="red")
                                else:
                                    if replacement_obj_instance not in self._objects[replacement_obj_location]['context'].children:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Tag {tag} application to object {replacement_obj_instance.about()['name']!r} ({replacement_obj_instance.__class__.__name__}) added to bulk operation pool for context {replacement_obj_location}")
                                        self._objects[replacement_obj_location]['context'].add(replacement_obj_instance)
                                    else:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Tag {tag} application to object {replacement_obj_instance.about()['name']!r} ({replacement_obj_instance.__class__.__name__}) : object already in bulk operation pool for context {replacement_obj_location}")

                            if self._nb_thread: lock.release()

                    # for each Address type object in the current location objects
                    for checked_object in self._objects[location_name]['Address']:
                        # if the type of the current object is a static AddressGroup
                        if type(checked_object) is panos.objects.AddressGroup and checked_object.static_value:
                            changed = False
                            matched = source_obj_instance.about()['name'] in checked_object.static_value
                            if matched and source_obj_instance.about()['name'] != replacement_obj_instance.about()['name']:
                                checked_object.static_value.remove(source_obj_instance.about()['name'])
                                # acquiring lock to avoid multiple threads to try to change a static group members list at the same time 
                                if self._nb_thread: lock.acquire()
                                if not replacement_obj_instance.about()['name'] in checked_object.static_value:
                                    checked_object.static_value.append(replacement_obj_instance.about()['name'])
                                if self._nb_thread: lock.release()
                                changed = True
                            try:
                                # If the current object to be replaced has been matched as a member of a static group at the
                                # current location level, add it to the replacements_done tracking dict
                                if matched:
                                    self._console.log(
                                        f"[ {location_name} ] [Thread-{thread_id}] Replacing {source_obj_instance.about()['name']!r} ({source_obj_location}) by {replacement_obj_instance.about()['name']!r} ({replacement_obj_location}) on {checked_object.about()['name']!r} ({checked_object.__class__.__name__})",
                                        style="yellow", level=2)
                                    # create a list (if not existing already) for the current static group object
                                    # which will contain the list of all replacements done on this group
                                    if self._nb_thread: lock.acquire()
                                    if checked_object.name not in replacements_done:
                                        replacements_done[checked_object.name] = list()
                                    # then append the current replacement information to this list (as a tuple format)
                                    replacements_done[checked_object.name].append((source_obj_instance.about()['name'],
                                                                                   source_obj_location,
                                                                                   replacement_obj_instance.about()['name'],
                                                                                   replacement_obj_location))
                                    if self._nb_thread: lock.release()
                            except Exception as e:
                                self._console.log(
                                    f"[ {location_name} ] [Thread-{thread_id}] Unknown error while replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r} on {checked_object.about()['name']!r} ({checked_object.__class__.__name__}) : {e}",
                                    style="red")

                            # if the cleaning application has been requested, update the modified group on Panorama
                            # this part cannot be done with bulk operations because of the reason mentioned on the function docstring
                            if changed:
                                if self._apply_cleaning:
                                    try:
                                        checked_object.apply()
                                        self._console.log(
                                            f"[ {location_name} ] [Thread-{thread_id}] Updated group {checked_object.about()['name']} ({checked_object.__class__.__name__}) for replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r}")
                                    except Exception as e:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR when updating group {checked_object.about()['name']} ({checked_object.__class__.__name__}) for replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r} : {e}")
                    self._console.log(
                        f"[ {location_name} ] [Thread-{thread_id}] Finished replacement of {source_obj_instance.about()['name']!r} ({source_obj_location}) by {replacement_obj_instance.about()['name']!r} ({replacement_obj_location}). {jobs_queue.qsize()} replacements remaining on queue"
                    )

                except Exception as e:
                    self._console.log(
                        f"[ {location_name} ] [Thread-{thread_id}] Unknown error on replace_in_addr_groups() : {e}"
                    )
                finally:
                    jobs_queue.task_done()
                    progress.update(task, advance=1)
                    if self._nb_thread and lock.locked():
                        lock.release()

        @self.multithread_wrapper
        def replace_in_service_groups(jobs_queue, progress, task, lock=None, thread_id=0):
            """
            This function replaces the services objects for which a better duplicate has been found on the current location groups

            :param replacement_name: (str)
            :param replacement: ()
            :return:
            """

            while True:
                if jobs_queue.empty():  # TODO MANAGE EXCPETION
                    break
                try:
                    replacement_name, replacement = jobs_queue.get()

                    # the source object name is the key on the _replacements dict
                    source_obj = replacement_name
                    # the source_obj_instance and source_obj_location are found in the 'source' key of the dict item
                    source_obj_instance, source_obj_location = replacement['source']
                    # the replacement_obj_instance and replacement_obj_location are found in the 'replacement' key of the dict item
                    replacement_obj_instance, replacement_obj_location = replacement['replacement']

                    # for each ServiceObject type object in the current location objects
                    for checked_object in self._objects[location_name]['Service']:
                        # if the type of the current object is a ServiceGroup
                        if type(checked_object) is panos.objects.ServiceGroup and checked_object.value:
                            changed = False
                            matched = source_obj_instance.about()['name'] in checked_object.value
                            if matched and source_obj_instance.about()['name'] != replacement_obj_instance.about()['name']:
                                checked_object.value.remove(source_obj_instance.about()['name'])
                                if self._nb_thread: lock.acquire()
                                if not replacement_obj_instance.about()['name'] in checked_object.value:
                                    checked_object.value.append(replacement_obj_instance.about()['name'])
                                if self._nb_thread: lock.release()
                                changed = True
                            try:
                                if matched:
                                    self._console.log(
                                        f"[ {location_name} ] [Thread-{thread_id}] Replacing {source_obj_instance.about()['name']!r} ({source_obj_location}) by {replacement_obj_instance.about()['name']!r} ({replacement_obj_location}) on {checked_object.about()['name']!r} ({checked_object.__class__.__name__})",
                                        style="yellow", level=2)
                                    # create a list (if not existing already) for the current static group object
                                    # which will contain the list of all replacements done on this group
                                    if self._nb_thread: lock.acquire()
                                    if checked_object.name not in replacements_done:
                                        replacements_done[checked_object.name] = list()
                                    # then append the current replacement information to this list (as a tuple format)
                                    replacements_done[checked_object.name].append((source_obj_instance.about()['name'],
                                                                                   source_obj_location,
                                                                                   replacement_obj_instance.about()['name'],
                                                                                   replacement_obj_location))
                                    if self._nb_thread: lock.release()
                            except Exception as e:
                                self._console.log(
                                    f"[ {location_name} ] Unknown error while replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r} on {checked_object.about()['name']!r} ({checked_object.__class__.__name__}) : {e}",
                                    style="red")

                            # if the cleaning application has been requested, update the modified group on Panorama
                            if changed:
                                if self._apply_cleaning and not self._bulk_operations:
                                    try:
                                        checked_object.apply()
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Updated group {checked_object.about()['name']} ({checked_object.__class__.__name__}) for replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r}")
                                    except Exception as e:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR when updating group {checked_object.about()['name']} ({checked_object.__class__.__name__}) for replacing {source_obj_instance.about()['name']!r} by {replacement_obj_instance.about()['name']!r} : {e}")
                                else:
                                    if checked_object not in self._objects[location_name]['context'].children:
                                        self._objects[location_name]['context'].add(checked_object)
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Update of group {checked_object.about()['name']} ({checked_object.__class__.__name__}) added to bulk operation pool for context {location_name}")
                                    else:
                                        self._console.log(
                                            f"[ {location_name} ] [Thread-{thread_id}] Update of group {checked_object.about()['name']} ({checked_object.__class__.__name__}) : object already in bulk operation pool for context {location_name}")
                    self._console.log(
                        f"[ {location_name} ] [Thread-{thread_id}] Finished replacement of {source_obj_instance.about()['name']!r} ({source_obj_location}) by {replacement_obj_instance.about()['name']!r} ({replacement_obj_location}). {jobs_queue.qsize()} replacements remaining on queue"
                    )
                except Exception as e:
                    self._console.log(
                        f"[ {location_name} ] [Thread-{thread_id}] Unknown error on replace_in_service_groups() : {e}"
                    )
                finally:
                    jobs_queue.task_done()
                    progress.update(task, advance=1)
                    if self._nb_thread and lock.locked():
                        lock.release()

        jobs_queue = Queue()
        # for each replacement for object type "Address" (AddressObject, AddressGroup) at the current location level
        for replacement_name, replacement in self._replacements[location_name]['Address'].items():
            jobs_queue.put((replacement_name, replacement))

        replace_in_addr_groups(jobs_queue, progress, task)
        jobs_queue.join()

        jobs_queue = Queue()
        for replacement_name, replacement in self._replacements[location_name]['Service'].items():
            jobs_queue.put((replacement_name, replacement))

        replace_in_service_groups(jobs_queue, progress, task)
        jobs_queue.join()

        # applying bulk operations in the pool
        # THIS SHOULD NEVER BE USED AS GROUP UPDATES ARE NOT DONE THROUGH BULK XML CALLS 
        if self._bulk_operations:
            # extract objects types in DG childrens
            child_obj_types = {type(x) for x in self._objects[location_name]['context'].children if "Group" in str(type(x))}
            for curr_type in child_obj_types:
                bulk_targets = [x for x in self._objects[location_name]['context'].children if type(x) is curr_type]
                self._console.log(
                    f"[ {location_name} ] Applying bulk operation for {bulk_targets[0].__class__.__name__} updates ({len(bulk_targets)} objects targeted). THIS SHOULD NOT BE USED !!!", style="red")
                if self._apply_cleaning:
                    try:
                        bulk_targets[0].apply_similar()
                    except Exception as e:
                        self._console.log(f"[ {location_name} ] ERROR when applying bulk operation for {bulk_targets[0].__class__.__name__} updates : {e}", style="red")
                any(self._objects[location_name]['context'].children.remove(x) for x in bulk_targets)
            """
            while self._objects[location_name]['context'].children:
                bulk_targets = [x for x in self._objects[location_name]['context'].children if type(x) is type(self._objects[location_name]['context'].children[0])]
                self._console.log(f"[ {location_name} ] Applying bulk operation for {bulk_targets[0].__class__.__name__} updates ({len(bulk_targets)} objects targeted)")
                if self._apply_cleaning:
                    try:
                        bulk_targets[0].apply_similar()
                    except Exception as e:
                        self._console.log(f"[ {location_name} ] ERROR when applying bulk operation for {bulk_targets[0].__class__.__name__} updates : {e}", style="red")
                any(self._objects[location_name]['context'].children.remove(x) for x in bulk_targets)
            """

        # for each group on which a replacement has been done
        for changed_group_name in replacements_done:
            # create a rich.Table, for which the header is the updated group name
            group_table = Table(style="dim", border_style="not dim", expand=False)
            group_table.add_column(changed_group_name)
            # create a list which contains the list of new added objects to the group to avoid adding the same one
            # multiple times (case of duplicate objects already in the group).
            # The application of such stuff on the group directly is protected above on the code, here's just for display
            already_added_objects = list()

            # for each replacement done on the current group
            for replaced_item in replacements_done[changed_group_name]:
                # if the name of the original and replacement objects are different, display the original object
                # name in red, and the replacement one in green (as well as their respective location)
                if replaced_item[0] != replaced_item[2]:
                    group_table.add_row(f"[red]- {replaced_item[0]} ({replaced_item[1]})[/red]")
                    if not replaced_item[2] in already_added_objects:
                        group_table.add_row(f"[green]+ {replaced_item[2]} ({replaced_item[3]})[/green]")
                        already_added_objects.append(replaced_item[2])
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

            any_change_done = False

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

                        # modified to use directly the obtained field format instead of relying on the repl_map descriptor information
                        #field_values = not_null_field if field_type is list else [not_null_field]
                        field_values = not_null_field if type(not_null_field) is list else [not_null_field]
                        for o in field_values:
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
                                    current_field_replacements_count += 1
                                    items_to_remove.append(o)
                                    # blocking cases where duplicates objects are used on a field of the rule and would
                                    # be replaced by the same target object
                                    if repl_name not in field_values + items_to_add:
                                        replacements_done[obj_type][field_name].append((f"{repl_name} ({replacement_obj_location})", 3))
                                        current_field_replacements_count += 1
                                        items_to_add.append(repl_name)
                                    any_change_done = True
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
                        if editable_rule:
                            if field_type is not list and items_to_add:
                                setattr(rule, field_name, items_to_add[0])
                            else:
                                any(not_null_field.remove(x) for x in items_to_remove)
                                any(not_null_field.append(x) for x in items_to_add)
                                setattr(rule, field_name, not_null_field)

                    # Update the max_replace value with the highest current_field_replacements_count value
                    # (if the current one is highest). This is used for proper display of the rich.Table rows for each
                    # rule (making sure that the row size is adapted to the field having the highest number of changes
                    # to be displayed)
                    if current_field_replacements_count > max_replace:
                        max_replace = current_field_replacements_count

            if editable_rule and any_change_done:
                if self._apply_cleaning:
                    try:
                        rule.apply()
                        self._console.log(f"[ {location_name} ] Cleaning applied to rule {rule.name!r}")
                    except Exception as e:
                        self._console.log(
                            f"[ {location_name} ] Error when applying cleaning to rule {rule.name!r} : {e}",
                            style="red")

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
                # add the first rule parent (PreRulebase() PostRulebase() or Rulebase()) to the device group
                self._objects[location_name]['context'].add(rulebase[0].parent)
                # initialize a variable which will count the number of replacements done for this rulebase
                total_replacements = c_int32(0)
                # initialize a variable which will count the number of edited rules for the current rulebase
                modified_rules = c_int32(0)
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

                @self.multithread_wrapper
                def replace_objects(jobs_queue, total_replacements, modified_rules, progress, task, lock=None, thread_id=0):
                    """
                    This function will be run by each thread which will perform the objects replacement for all the rules in the rulebase
                    :param queue: Queue for objects treatment by multithreading
                    :return:
                    """
                    
                    while True:
                        if jobs_queue.empty():
                            break
                        try:
                            r = jobs_queue.get()
                            # this boolean variable will define if the rule timestamps are in the boundaries to allow modifications
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
                            elif rule_modification_timestamp > self._max_change_timestamp and last_hit_timestamp > self._max_hit_timestamp:
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
                                total_replacements.value += replacements_count

                                # if the rule has changes but is not considered as editable (not in timestamp boundaries
                                # regarding opstate timestamps), protect the rule objects from deletion
                                if not editable_rule or "noopstate" in r.name:
                                    for obj_type, fields in repl_map[type(r)].items():
                                        for f in fields:
                                            field_values = getattr(r, f[0])
                                            field_values = [field_values] if type(field_values) is str else field_values
                                            #if (field_values := getattr(r, f[0]) if type(f) is list else [getattr(r, f)]):
                                            if field_values:
                                                for object_name in field_values:
                                                    if object_name in self._replacements[location_name][obj_type]:
                                                        self._replacements[location_name][obj_type][object_name][
                                                            "blocked"] = True
                                else:
                                    modified_rules.value += 1

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
                            self._console.log(
                                f"[ {location_name} ] [Thread-{thread_id}] Finished replacements on rule {r.name!r}. {jobs_queue.qsize()} rules remaining on queue",
                                level=2
                            )
                        except Exception as e:
                            self._console.log(
                                f"[ {location_name} ] [Thread-{thread_id}] Unknown error : {e}"
                            )
                        finally:
                            jobs_queue.task_done()
                            progress.update(task, advance=1)
                            if self._nb_thread and lock.locked():
                                lock.release()

                jobs_queue = Queue()
                for r in rulebase:
                    jobs_queue.put(r)
                replace_objects(jobs_queue, total_replacements, modified_rules, progress, task)
                jobs_queue.join()

                # If there are replacements on the current rulebase, display the generated rich.Table on the console
                if total_replacements:
                    self._console.print(rulebase_table)
                    self._console.log(
                        f"[ {location_name} ] {modified_rules} rules edited for the current rulebase ({rulebase_name})")

                self._objects[location_name]['context'].remove(rulebase[0].parent)

    def clean_local_object_set(self, location_name: str):
        """
        In charge of removing the unused objects at a given location (if this location is fully included in the analysis,
        = all child device-groups also included)

        :param location_name: (str) The name of the current location
        :param progress: (rich.progress.Progress) The rich.Progress object to update while progressing
        :param task: (rich.progress.Task) The rich.Task object to update while progressing
        :return:
        """

        def parse_PanDeviceXapiError_references(dependencies_error_message: str) -> (dict, bool):
            addr_groupinfo_regex = re.compile(r'^.+?(?=->)-> (?P<location>.+?(?=->))-> address-group -> (?P<groupname>.+?(?=->))')
            serv_groupinfo_regex = re.compile(r'^.+?(?=->)-> (?P<location>.+?(?=->))-> service-group -> (?P<groupname>.+?(?=->))')
            ruleinfo_regex = re.compile(r'^.+?(?=->)-> (?P<location>.+?(?=->))-> (?P<rbtype>.+?(?=->))-> (?P<rb>.+?(?=->))-> rules -> (?P<rulename>.+?(?=->))-> (?P<field>.+)')

            dependencies = {"AddressGroups": list(), "ServiceGroups": list(), "Rules": list()}
            matched_dependencies = 0

            for dependency_line in dependencies_error_message.split('\n'):
                dependency_line = dependency_line.strip()
                grp_result_dict = None
                dependency_type = None

                grp_result = re.match(addr_groupinfo_regex, dependency_line)
                if grp_result:
                    grp_result_dict = grp_result.groupdict()
                    dependency_type = "AddressGroups"
                else:
                    grp_result = re.match(serv_groupinfo_regex, dependency_line)
                    if grp_result:
                        grp_result_dict = grp_result.groupdict()
                        dependency_type = "ServiceGroups"

                if grp_result_dict and dependency_type:
                    for k, v in grp_result_dict.items():
                        grp_result_dict[k] = v.strip()
                    dependencies[dependency_type].append(grp_result_dict)
                    matched_dependencies += 1
                    continue

                # This part should never be matched, as we are not supposed to try to delete an object which is used
                # on a rule at this time
                try:
                    rule_result = re.match(ruleinfo_regex, dependency_line).groupdict()
                    for k, v in rule_result.items():
                        rule_result[k] = v.strip()
                    rule_result['rule_location'] = ''.join([x[0].upper()+x[1::].lower() for x in rule_result['rbtype'].split('-')])
                    rule_result['rule_location'] += "_" + rule_result['rb'][0].upper() + rule_result['rb'][1::] + "Rule"
                    del(rule_result['rbtype'])
                    del(rule_result['rb'])
                    dependencies["Rules"].append(rule_result)
                    matched_dependencies += 1
                except AttributeError:
                    pass

            all_matched = True if matched_dependencies == len(dependencies_error_message.split('\n')) - 1 else False
            return dependencies, all_matched


        # Populating the global _cleaning_count object, which is used to display the number of objects
        # cleaned / replaced on each device-group on the final report
        self._cleaning_counts[location_name] = {
            x: {'removed': 0, 'replaced': 0} for x in self._replacements.get(location_name, list())
        }

        # Cache used for flatten objects when using tags protection
        # TODO : better comments
        resolved_cache = dict({'Address': list(), 'Service': list(), 'Tag': list()})

        # optimized_only set to True if we are on unused-only mode with a list of device-groups specified, and the current location being cleaned is not in this list
        # (which means that we don't want to delete anything at this level, but we need to make sure that used objects at this level will be protected upward, if the upward device-group is on the list)
        optimized_only = True if (self._unused_only is not None and len(self._unused_only) > 0 and location_name not in self._unused_only) else False

        # removing replaced objects from used_objects_set for current location_name
        for obj_type in self._replacements.get(location_name, list()):
            for name, infos in self._replacements[location_name][obj_type].items():
                # Remind that objects marked as "blocked" on the _replacements tracker should not be removed :
                # They have not been replaced as expected, because used on rules where the opstate values
                # (last_hit_timestamp and last_change_timestamp) are not in the allowed boundaries
                if not infos['blocked']:
                    try:
                        # For the current replacement, remove the original object from the _used_objects_set for the
                        # current location (if not using the --unused-only argument),
                        # and replace it with the replacement object
                        if self._unused_only is None:
                            self._used_objects_sets[location_name].remove(infos['source'])
                        if self._unused_only is None or (self._unused_only is not None and self._protect_potential_replacements):
                            if infos['replacement'] not in self._used_objects_sets[location_name]:
                                # flattening the replacement object to add also its dependencies (ie : Tags)
                                # TODO : check if any issue can appear when using multithreading (need to use another lock here ?)
                                replacements_dependencies_set = self.flatten_object(*infos['replacement'], location_name)
                                any(self._used_objects_sets[location_name].add(x) for x in replacements_dependencies_set)
                                self._console.log(f"[ {location_name} ] Added replacement object and dependencies ({replacements_dependencies_set}) to used objects set", level=2)
                            else:
                                self._console.log(f"[ {location_name} ] Replacement object ({infos['replacement']}) already processed for local context", level=2)
                        self._console.log(f"[ {location_name} ] Removing unprotected object {name} (location {infos['source'][1]}) from used objects set", level=2)
                        # If the name of the current replacement object is different than the replacement one, count it
                        # as a replacement on the _cleaning_counts tracker
                        if not optimized_only and not self._unused_only and infos['source'][1] == location_name and infos['source'][0].name != infos['replacement'][0].name:
                            self._cleaning_counts[location_name][obj_type]['replaced'] += 1
                    # This exception should never be raised but protects the execution
                    except ValueError:
                        self._console.log(f"[ {location_name} ] ValueError when trying to remove {name} from used objects set : object not found on object set")
                else:
                    # TODO : flatten protected object for dependencies protection ?
                    self._console.log(f"[ {location_name} ] Not removing {name} (location {infos['source'][1]}) from used objects set, as protected by hitcount", level=2)

        # After cleaning the current device-group, adding the current location _used_objects_set values to the
        # _used_objects_set of the parent.
        # This will permit to protect used objects on the childs of the hierarchy to be deleted when they exist but are
        # not used on the parents
        upward_dg = self._dg_hierarchy[location_name].parent
        upward_dg_name = "shared" if not upward_dg else upward_dg.name
        self._console.log(f"[ {location_name} ] Found parent DG is {upward_dg_name}", level=3)

        # improvement : try to replicate upward only objects not attached to the current device-group (useless) 
        #self._used_objects_sets[upward_dg_name] = self._used_objects_sets[upward_dg_name].union(self._used_objects_sets[location_name])
        self._used_objects_sets[upward_dg_name] = self._used_objects_sets[upward_dg_name].union([x for x in self._used_objects_sets[location_name] if not x[1]==location_name])

        if optimized_only:
            return None

        @self.multithread_wrapper
        def delete_local_objects_mthread(jobs_queue: Queue, dg: DeviceGroup, lock=None, thread_id=0):
            while True:
                if jobs_queue.empty():
                    break
                try:
                    obj = jobs_queue.get()
                    shortened_obj_type = PaloCleanerTools.shorten_object_type(obj.__class__.__name__)
                    self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Checking tag protection of object {obj.name} ({obj.__class__.__name__})", level=2)
                    try:
                        if obj.tag:
                            self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Object has tags : {obj.tag}", level=2)
                            if set(obj.tag).intersection(self._protect_tags) or obj.name in indirect_protect[shortened_obj_type]:
                                indirect_protect["Tag"].update(obj.tag)

                                if "Group" in obj.__class__.__name__:
                                    if obj.static_value:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Object {obj.name} ({obj.__class__.__name__}) has static members. Flattening to protect all linked objects")
                                        linked_objects = self.flatten_object(obj, location_name, location_name, resolved_cache=resolved_cache)
                                        for (o, o_location) in linked_objects:
                                            self._console.log(f"[ {o_location} ] [Thread-{thread_id}] Protecting object {o.name} ({o.__class__.__name__} / {shortened_obj_type})", level=2)
                                            indirect_protect[shortened_obj_type].add(o.name)
                                continue
                    except AttributeError as e:
                        pass
                    except Exception as e:
                        self._console.log(f"[Thread-{thread_id}] UNKNOWN EXCEPTION : {e}", style="red")

                    if obj.name in indirect_protect[shortened_obj_type]:
                        continue

                    if self._apply_cleaning and not (obj, location_name) in self._used_objects_sets[location_name]:
                        delete_ok = False
                        while not delete_ok:
                            try:
                                self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Trying to delete object {obj.name} ({obj.__class__.__name__})")
                                dg.add(obj)
                                obj.delete()
                                self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Object {obj.name} ({obj.__class__.__name__}) has been successfuly deleted ")
                                self._cleaning_counts[location_name][shortened_obj_type]['removed'] += 1
                                delete_ok = True
                            except panos.errors.PanDeviceXapiError as e:
                                dependencies, all_matched = parse_PanDeviceXapiError_references(e.message)
                                if not all_matched:
                                    self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR : It seems that object {obj.name} ({obj.__class__.__name__}) is used somewhere in the configuration, on device-group {location_name}. It will not be deleted. Please check manually")
                                    self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR content : {e.message}")
                                    delete_ok = True
                                    continue
                                else:
                                    # The following should never be matched, as we are not supposed to try to delete
                                    # an object which is still used on a rule at this time of the process
                                    # Keeping it for security purposes

                                    # first catching error where Panorama refuses to delete an object while it does not returns any valid dependency
                                    if sum(len(dep) for dep_type, dep in dependencies.items()) == 0:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR : It seems that object {obj.name} ({obj.__class__.__name__}) has invalid dependencies. Please try to fix it manually !!!")
                                        delete_ok = True

                                    # then proceed with actions for the different types of dependencies
                                    for rule_dependency in dependencies["Rules"]:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR : It seems that object {obj.name} ({obj.__class__.__name__}) is still used on the following rule : {rule_dependency['rule_location']} / {rule_dependency['rulename']}. It will not be deleted. Please check manually")
                                        delete_ok = True
                                    if delete_ok:
                                        continue

                                    for group_dependency in dependencies["AddressGroups"]:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Group {obj.name} ({obj.__class__.__name__}) is still used on another AddressGroup : {group_dependency['groupname']} at location {group_dependency['location']}. Removing this dependency for cleaning.")
                                        referencer_group, referencer_group_location = self.get_relative_object_location(group_dependency['groupname'], group_dependency['location'])
                                        referencer_group.static_value.remove(obj.name)
                                        referencer_group.apply()

                                    for group_dependency in dependencies["ServiceGroups"]:
                                        self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Group {obj.name} ({obj.__class__.__name__}) is still used on another ServiceGroup : {group_dependency['groupname']} at location {group_dependency['location']}. Removing this dependency for cleaning.")
                                        referencer_group, referencer_group_location = self.get_relative_object_location(group_dependency['groupname'], group_dependency['location'], obj_type="Service")
                                        referencer_group.value.remove(obj.name)
                                        referencer_group.apply()
                            except Exception as e:
                                self._console.log(f"[ {location_name} ] [Thread-{thread_id}] ERROR when trying to delete object {obj.name} ({obj.__class__.__name__}) : {e}")

                    elif not (obj, location_name) in self._used_objects_sets[location_name]:
                        self._console.log(
                            f"[ {location_name} ] [Thread-{thread_id}] Object {obj.name} ({obj.__class__.__name__}) can be deleted")
                        self._cleaning_counts[location_name][shortened_obj_type]['removed'] += 1
                except Exception as e:
                    self._console.log(
                        f"[ {location_name} ] [Thread-{thread_id}] Unknown error on delete_local_objects() : {e}"
                    )
                finally:
                    jobs_queue.task_done()
                    if self._nb_thread and lock.locked():
                        lock.release()


        # Iterating over each object type / object for the current location, and check if each object is member
        # (or still member, as the replaced ones have been suppressed) of the _used_objects_set for the same location
        # If they are not, they can be deleted
        # We start by the groups (removing all members before deleting the group, to avoid inter-dependency between groups)
        # Then we delete AddressObjects and ServiceObjects, then Tags
        def delete_local_objects_bulk(jobs_queue: Queue, dg: DeviceGroup, lock=None, thread_id=0):

            while True:
                if jobs_queue.empty():
                    break
                try:
                    obj_item = jobs_queue.get()
                    obj_type = list(obj_item.keys())[0]
                    obj_instance = obj_item[obj_type]

                    # This is for delete_similar reference
                    first_to_be_deleted = None

                    for o in self._objects[location_name][obj_type]:
                        if type(o) is obj_instance:
                            self._console.log(f"[ {location_name} ] Checking tag protection of object {o.name} ({obj_instance.__name__})", level=2)
                            try:
                                if o.tag:
                                    self._console.log(f"[ {location_name} ] Object has tags : {o.tag}", level=2)
                                    if set(o.tag).intersection(self._protect_tags) or o.name in indirect_protect[obj_type]:
                                        # protecting the other tags used on the protected object from being deleted later
                                        # this is done for all type of objects (Service, Address, ServiceGroup, AddressGroup)
                                        indirect_protect["Tag"].update(o.tag)

                                        # in case of a protected group, protecting the members from being deleted later (+ all associated objects, like tags)
                                        # this is done only for static groups, using the flatten_objects method
                                        # dynamic groups members are not protected (except if they have a --protect-tags matching tag)
                                        if "Group" in obj_instance.__name__:
                                            if o.static_value:
                                                self._console.log(f"[ {location_name} ] Object {o.name} ({obj_instance.__name__}) has static members. Flattening to protect all linked objects")
                                                linked_objects = self.flatten_object(o, location_name, location_name, resolved_cache=resolved_cache)

                                                for (o, o_location) in linked_objects:
                                                    shorten_type = PaloCleanerTools.shorten_object_type(o.__class__.__name__)
                                                    self._console.log(f"[ {o_location} ] Protecting object {o.name} ({o.__class__.__name__} / {shorten_type})", level=2)
                                                    indirect_protect[shorten_type].add(o.name)
                                        continue
                            except AttributeError as e:
                                pass
                            except Exception as e:
                                self._console.log(f"UNKNOWN EXCEPTION : {e}", style="red")

                            if o.name in indirect_protect[obj_type]:
                                continue

                            if self._apply_cleaning and not (o, location_name) in self._used_objects_sets[location_name]:
                                dg.add(o)
                                if not first_to_be_deleted:
                                    first_to_be_deleted = o
                            elif not (o, location_name) in self._used_objects_sets[location_name]:
                                self._console.log(
                                    f"[ {location_name} ] [Thread-{thread_id}] Object {o.name} ({o.__class__.__name__}) can be deleted")
                                self._cleaning_counts[location_name][obj_type]['removed'] += 1

                    if self._apply_cleaning and first_to_be_deleted:
                        try:
                            # if objects to be deleted are static groups, first empty them to avoid deletion issues because of circular references
                            # this cannot be done as a bulk action as apply_similar would delete all other groups, and create_similar would not to anything (merging members)
                            if isinstance(first_to_be_deleted, AddressGroup):
                                #filtering on static groups only
                                for child_add_group in [g for g in dg.children if g.static_value]:
                                    self._console.log(f"[ {location_name} ] Preparing bulk action to empty group {child_add_group.name}")
                                    child_add_group.static_value = list()
                                    child_add_group.apply()
                            else:
                                self._console.log(f"[ {location_name} ] Sending bulk action for deletion of {o.__class__.__name__}")
                            first_to_be_deleted.delete_similar()
                        except Exception as e:
                            self._console.log(f"[ {location_name} ] ERROR with bulk action : {e}", style="red")
                except Exception as e:
                    self._console.log(
                        f"[ {location_name} ] [Thread-{thread_id}] Unknown error on delete_local_objects() : {e}"
                    )
                finally:
                    jobs_queue.task_done()

                    self._console.log(f"[ {location_name} ] [Thread-{thread_id}] Cleaning done for object type {obj_instance.__name__}")

        # Queue to which the jobs will be stored, waiting to be executed
        # It will be used differently, based if we are in single / multithreading mode (each job will consist in deleting a single object)
        # while if in bulk delete mode, each job will consist in deleting all objects of a given type 
        jobs_queue = Queue()

        # dict used to store indirectly protected object (because of protect-tags parameter used at startup)
        indirect_protect = dict()
        indirect_protect['Tag'] = set()
        indirect_protect['Tag'].update(self._protect_tags)
        indirect_protect['Tag'].update(self._tiebreak_tag if self._tiebreak_tag else [])

        local_dg = self._objects[location_name]['context']

        if self._bulk_operations:
            for obj_item in [v for k, v in sorted(cleaning_order.items())]:
                jobs_queue.put(obj_item)
                if not indirect_protect.get(list(obj_item.keys())[0]):
                    indirect_protect[list(obj_item.keys())[0]] = set()
            delete_local_objects_bulk(jobs_queue, local_dg)
            jobs_queue.join()
        else:
            for obj_item in [v for k, v in sorted(cleaning_order.items())]:
                for obj in self._objects[location_name][list(obj_item.keys())[0]]:
                    if type(obj) is obj_item[list(obj_item.keys())[0]]:
                        jobs_queue.put(obj)
                if not indirect_protect.get(list(obj_item.keys())[0]):
                    indirect_protect[list(obj_item.keys())[0]] = set()
                delete_local_objects_mthread(jobs_queue, local_dg)
                jobs_queue.join()
                self._console.log(f"[ {location_name} ] Queue joined before moving to next object type", level=2)

        #if local_dg != self._panorama:
        #    self._panorama.remove(local_dg)