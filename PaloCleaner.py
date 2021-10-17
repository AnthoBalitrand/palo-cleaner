import panos.objects
from panos.panorama import Panorama, DeviceGroup, PanoramaDeviceGroupHierarchy
from panos.objects import AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, PreRulebase, PostRulebase, Rulebase
from panos.predefined import Predefined

class PaloCleaner:
    def __init__(self, panorama_url, panorama_user, panorama_password, dg_filter, inline_mode):
        self._panorama_url = panorama_url
        self._panorama_credentials = (panorama_user, panorama_password)
        self._dg_filter = dg_filter
        self._inline_mode = inline_mode
        self._panorama = self.panorama_connector(self._panorama_url, *self._panorama_credentials)
        self._objects = dict()
        self._used_objects_sets = dict()
        self._rulebases = dict()
        self._stored_pano_hierarchy = None
        self._removable_objects = list()

    def panorama_connector(self, url, user, password):
        print(f"Connecting to {url} with user {user}... ")
        return Panorama(url, user, password)

    def get_devicegroups(self):
        dg_list = DeviceGroup.refreshall(self._panorama)
        return dg_list

    def get_pano_dg_hierarchy(self):
        # caching device-groups hierarchy returned by Panorama
        if not self._stored_pano_hierarchy:
            self._stored_pano_hierarchy = PanoramaDeviceGroupHierarchy(self._panorama).fetch()
        return self._stored_pano_hierarchy

    def reverse_dg_hierarchy(self, pano_hierarchy, print_result=False):
        #TODO : add colors to identify device-groups impacted by the cleaning process
        reversed_tree = dict()

        for k, v in pano_hierarchy.items():
            reversed_tree[v] = reversed_tree[v] + [k] if v in reversed_tree.keys() else [k]
            if k not in reversed_tree.keys():
                reversed_tree[k] = list()

        if print_result:
            def print_tree_branch(tree, start = None, indent = 0):
                for k, v in reversed_tree.items():
                    if k == start:
                        for d in v:
                            print("      " * indent + "|--- " + d)
                            print_tree_branch(tree, d, indent + 1)

            print("\nObjects inheritance tree is : ")
            print("\nshared")
            print_tree_branch(reversed_tree)
        print(reversed_tree)
        return reversed_tree

    def fetch_objects(self, context, location_name):
        if location_name not in self._objects.keys():
            self._objects[location_name] = dict()

        if location_name == 'predefined':
            predef = Predefined()
            self._panorama.add(predef)
            predef.refreshall()
            self._objects[location_name]['service'] = [v for k, v in predef.service_objects.items()]
            self._objects[location_name]['context'] = context
            self._objects[location_name]['address_obj'] = list()
            self._objects[location_name]['address_group'] = list()
            self._objects[location_name]['tag'] = list()
            self._objects[location_name]['service_group'] = list()
        else:
            self._objects[location_name]['context'] = context
            self._objects[location_name]['address_obj'] = AddressObject.refreshall(context)
            self._objects[location_name]['address_group'] = AddressGroup.refreshall(context)
            self._objects[location_name]['tag'] = Tag.refreshall(context)
            self._objects[location_name]['service'] = ServiceObject.refreshall(context)
            self._objects[location_name]['service_group'] = ServiceGroup.refreshall(context)
        print(self._objects[location_name])

    def fetch_rulebase(self, context, location_name):
        if location_name not in self._rulebases.keys():
            self._rulebases[location_name] = dict()

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

    def get_relative_object_location(self, obj_name, reference_location):
        #print(f"Get relative object location for {obj_name} on {reference_location}")
        found_location = None
        found_object = None
        for obj in self._objects[reference_location]['address_obj'] + self._objects[reference_location]['address_group']:
            if obj.about()['name'] == obj_name:
                found_location = reference_location
                found_object = obj
        if not found_location:
            upward_dg = self.get_pano_dg_hierarchy()[reference_location]
            if not upward_dg:
                upward_dg = 'shared'
            found_object, found_location = self.get_relative_object_location(obj_name, upward_dg)
        return (found_object, found_location)

    def fetch_address_obj_set(self, location_name):
        # it is possible to create an object group using the name of an upward address object
        # but the object group cannot be deleted to be replaced by a reference to the upward address object
        # WARNING : unexpected behaviors if groups and address objects have the same names

        def flatten_group(group, location_name):
            group_obj_set = list()
            for a in group.static_value:
                referenced_object, referenced_object_location = self.get_relative_object_location(a, location_name)
                if type(referenced_object) == panos.objects.AddressGroup:
                    group_obj_set += flatten_group(referenced_object, referenced_object_location)
                group_obj_set.append((referenced_object, referenced_object_location))
            group_obj_set.append((group, location_name))
            return group_obj_set

        obj_ref_set = list()
        for k, v in self._rulebases[location_name].items():
            if k == "context":
                continue
            for r in v:
                for obj in r.source + r.destination:
                    if obj != 'any':
                        referenced_object, referenced_object_location = self.get_relative_object_location(obj, location_name)
                        if type(referenced_object) == panos.objects.AddressGroup:
                            #TODO : check if location needs to be changed by location_name (use of local object on upward group ?)
                            obj_ref_set += flatten_group(referenced_object, referenced_object_location)
                        else:
                            obj_ref_set.append(self.get_relative_object_location(obj, location_name))

        self._used_objects_sets[location_name] = set(obj_ref_set)

    def find_upward_obj_by_addr(self, base_location_name, obj_addr):
        def hostify_address(address):
            # removing /32 mask for hosts
            if address[-3:] == '/32':
                return address[:-3:]
            return address

        obj_addr = hostify_address(obj_addr)
        print(f"Hostified address : {obj_addr}")
        found_upward_objects = list()
        upward_devicegroup = self.get_pano_dg_hierarchy().get(base_location_name)
        if not upward_devicegroup:
            upward_devicegroup = 'shared'
        print(f"Upward device group : {upward_devicegroup}")
        print(self._objects[upward_devicegroup])
        for obj in self._objects[upward_devicegroup]['address_obj']:
            if hostify_address(obj.value) == obj_addr:
                found_upward_objects.append((obj, upward_devicegroup))
        if upward_devicegroup != 'shared':
            found_upward_objects += self.find_upward_obj_by_addr(upward_devicegroup, obj_addr)
        return found_upward_objects

    def find_best_replacement_addr_obj(self, obj_list):
        shared_obj = [x for x in obj_list if x[1] == 'shared']
        fqdn_obj = [x for x in obj_list if len(x[0].about()['name'].split('.')) > 1 and x[0].about()['name'].split('.')[-1] in ['corp', 'com']]
        shared_fqdn_obj = list(set(shared_obj) & set(fqdn_obj))
        if shared_fqdn_obj:
            return shared_fqdn_obj[0]
        if shared_obj:
            return shared_obj[0]

    def optimize_address_objects(self, location_name):
        print(f"Optimizing objects for {location_name}")
        for obj, location in self._used_objects_sets[location_name]:
            if type(obj) == panos.objects.AddressObject and location == location_name:
                upward_objects = self.find_upward_obj_by_addr(location_name, obj.value)
                if upward_objects:
                    replacement_obj = self.find_best_replacement_addr_obj(upward_objects)
                    print(f"Object {obj.about()['name']} ({obj.value}) can be replaced by {replacement_obj[0].about()['name']} ({replacement_obj[0].value}) on {replacement_obj[1]}")
                    self.replace_object(location_name, (obj, location), replacement_obj)

    def replace_object(self, location_name, ref_obj, replacement_obj):
        ref_obj_instance, ref_obj_location = ref_obj
        ref_obj_name = ref_obj_instance.about()['name']
        replacement_obj_instance, replacement_obj_location = replacement_obj
        replacement_obj_name = replacement_obj_instance.about()['name']
        if ref_obj_name != replacement_obj_name:
            # replacement on direct calls on rulebase
            for l, rb in self._rulebases[location_name].items():
                if l == 'context':
                    continue
                for r in rb:
                    replace_in_source = False
                    replace_in_destination = False
                    if ref_obj_name in r.source:
                        replace_in_source = True
                    if ref_obj_name in r.destination:
                        replace_in_destination = True
                    if replace_in_source:
                        r.source.remove(ref_obj_name)
                        r.source.append(replacement_obj_name)
                        print(f"{ref_obj_name} (inherited from {ref_obj_location}) has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on rule {r.name} as source")
                    if replace_in_destination:
                        r.destination.remove(ref_obj_name)
                        r.destination.append(replacement_obj_name)
                        print(
                            f"{ref_obj_name} (inherited from {ref_obj_location}) has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on rule {r.name} as destination")
                    if replace_in_source or replace_in_destination:
                        r.apply()
            # replacement on groups
            for g in self._objects[location_name]['address_group']:
                replace = False
                if ref_obj_name in g.static_value:
                    replace = True
                if replace:
                    g.static_value.remove(ref_obj_name)
                    g.static_value.append(replacement_obj_name)
                    print(f"{ref_obj_name} (inherited from {ref_obj_location} has been replaced by {replacement_obj_name} (inherited from {replacement_obj_location}) on group {g.name}")
                    g.apply()

        # add objects to the deletion list
        self._removable_objects.append(ref_obj)

    def remove_objects(self):
        # remove replaced objects
        for obj_tuple in self._removable_objects:
            obj_instance, obj_location = obj_tuple
            print(f"Trying to remove object {obj_instance.about()['name']} from {obj_location}")
            print(self._objects[obj_location]['address_obj'])
            self._objects[obj_location]['address_obj'].remove(obj_instance)
            # TODO : test behavior is object on parent (intermediate) DG is removed from 1 child DG and remains used on another one
            for loc in self._used_objects_sets.keys():
                try:
                    self._used_objects_sets[loc].remove(obj_instance)
                except Exception as e:
                    print(f"Object {obj_instance.about()['name']} not found in {loc}")
            obj_instance.delete()
            print(f"Object {obj_instance.about()['name']} deleted from DG {obj_location}")

        # remove unused objects (including groups)
        cleaning_order = ['service_group', 'service', 'address_group', 'address_obj', 'tag']
        global_used_objects_set = set()
        for k, v in self._used_objects_sets.items():
            for obj_tuple in v:
                global_used_objects_set.add(obj_tuple)

        depthed_tree = dict({0: ['shared']})
        def gen_tree_depth(input_tree, start=None, depth=1):
            for loc in input_tree[start]:
                if depth not in depthed_tree.keys():
                    depthed_tree[depth] = list()
                depthed_tree[depth].append(loc)
                gen_tree_depth(input_tree, loc, depth+1)

        dg_reversed_tree = self.reverse_dg_hierarchy(self.get_pano_dg_hierarchy())
        gen_tree_depth(dg_reversed_tree)

        dg_clean_order = list()
        for key in sorted(depthed_tree.keys(), reverse=True):
            dg_clean_order += depthed_tree[key]
        print(f"Cleaning DG in the following order : {dg_clean_order} ")

        for k in dg_clean_order:
            v = self._objects[k]
            for type in cleaning_order:
                for obj in v[type]:
                    if (obj, k) not in global_used_objects_set:
                        print(f"Deleting object {obj.about()['name']} from {k}")
                        obj.delete()