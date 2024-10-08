import panos.objects
import ipaddress
import dns.exception

def hostify_address(address: str, dns_resolver: str = None) -> str:
    """
    Used to remove /32 at the end of an IP address

    Commenting : OK (15062023)

    :param address: (string) IP address to be modified
    :return: (string) Host IP address (instead of network /32)
    """

    # removing /32 mask for hosts
    try:
        ip = ipaddress.ip_address(address.split('/')[0])
        if address[-3:] == '/32':
            return address[:-3:], None
        return address, None
    except ValueError:
        test_range = address.split('-')
        if len(test_range) == 2:
            try:
                _ = ipaddress.ip_address(test_range[0])
                _ = ipaddress.ip_address(test_range[1])
                return address, None
            except Exception as e:
                pass
        if dns_resolver:
            try:
                answer = dns_resolver.resolve(address, 'A')
                if len(answer) == 1:
                    print(f"Resolved {address} to {answer[0].to_text()}")
                    return address, answer[0].to_text()
                else:
                    print(f"{address} resolves with {len(answer)} records. Not taking resolution into account")
                    return address, None
            except Exception as e:
                print(f"Unable to resolve {address}")
                return address, None
    return address, None


def stringify_service(service: panos.objects.ServiceObject) -> str:
    """
    Returns the "string" version of a service (for search purposes)
    The format is (str) PROTOCOL/source_port/dest_port
    IE : TCP/None/22 or UDP/1000/60

    Commenting : OK (15062023)

    :param service: (panos.Service) A Service object
    :return: (str) The "string" version of the provided object
    """

    return service.protocol.lower() + "/" + str(service.source_port) + "/" + str(service.destination_port)


def tag_counter(obj: (panos.objects.PanObject, str)) -> int:
    """
    Returns the number of tags assigned to an object. Returns 0 if the tag attribute value is None
    :param tuple: (PanObject, location) The object on which to count the number of tags
    :return: (int) The number of tags assigned to the concerned object

    Commenting : OK (15062023)

    """
    if not getattr(obj[0], 'tag', None):
        return 0
    else:
        return len(obj[0].tag)


def shorten_object_type(object_type: str) -> str:
    """
    (Overkill function) which returns a panos.Object type, after removing the "Group" and "Object" characters
    ie : AddressGroup and AddressObject both becomes Address

    Commenting : OK (15062023)

    :param object_type: (str) panos.Object.__class__.__name__
    :return: (str) the panos.Object type name without "Group" nor "Object"
    """

    return object_type.replace('Group', '').replace('Object', '')

def surcharge_addressobjects():
    """
    Adds the following functions to the panos.objects.AddressObject to be used by the groups comparison feature
    """
    panos.objects.AddressObject.init_object_group_membership = init_object_group_membership
    panos.objects.AddressObject.add_membership = add_membership

def init_object_group_membership(self):
    if not hasattr(self, "group_membership"):
        self.group_membership = dict()
        self.group_member_only = True

def add_membership(self, location, group):
    if not location in self.group_membership:
        self.group_membership[location] = set()
    self.group_membership[location].add(group)
    #print(f"{self} : added membership to {group} at location {location}")

def surcharge_addressgroups():
    """
    Adds the following functions to the panos.objects.AddressGroup to be used by the groups comparison feature
    """

    panos.objects.AddressGroup.init_group_comparison = init_group_comparison
    panos.objects.AddressGroup.add_range = add_range
    panos.objects.AddressGroup.merge_ip_tuples = merge_ip_tuples
    panos.objects.AddressGroup.calc_group_size = calc_group_size

# the following functions are added to the panos.objects.AddressGroup class when using the group replacement mode 

def init_group_comparison(self):
    self.members = list()
    self.ip_tuples = list()
    self.ip_count = 0
    self.max_ip = 0
    self.min_ip = None

def add_range(self, range_in, dns_res=None):
    r = range_in
    if type(range_in) is not ipaddress.IPv4Network:
        try:
            if '-' in range_in:
                # if the range_in value is range (ie : 192.168.1.1-192.168.1.3), split it
                # and create a "temporary" IPv4Network object to which we spoof the network_address
                # and broadcast_address values with the ranges values 
                min_add, max_add = range_in.split('-')
                #print(f"IP address range detected : {range_in}")
                r = ipaddress.IPv4Network("0.0.0.0/0")
                r.network_address = ipaddress.IPv4Address(min_add)
                r.broadcast_address = ipaddress.IPv4Address(max_add)
            else:
                r = ipaddress.ip_network(range_in, False)
        except ValueError:
            if dns_res:
                r = dns_res
                print(f"{range_in!r} added to group member list for {self} with DNS-resolved IP {dns_res}")
            else:
                print(f"{range_in!r} is not a valid IPv4 or IPv6 address. Not added to group members list for {self}")
                return False
    self.members.append(r)

    self.ip_tuples.append((int(r.network_address), int(r.broadcast_address)))

    if int(r.broadcast_address) > self.max_ip:
        self.max_ip = int(r.broadcast_address)

    if self.min_ip is None:
        self.min_ip = int(r.network_address)
    elif self.min_ip > int(r.network_address):
        self.min_ip = int(r.network_address)

    return True

def merge_ip_tuples(self):
    # this function merges contiguous IP ranges on the AddressGroup
    merge_finished = False
    tuples_list = sorted(self.ip_tuples)
    merged_tuples = set()

    # if group size is not more than 1, no need to merge anything
    if len(self.ip_tuples) > 1:
        # loop while merges have been done on the previous iterations
        while not merge_finished:
            merged_tuples = set()
            #merge_done is moved to True as soon as 1 merging operation occurs in the current loop 
            merge_done = False
            last_loop_merged = False

            # looping on all groups member, from the second one (index=1) to the last one + 1 (len)
            for tup_index in range(1, len(tuples_list)):
                # if a merging operation has been done on the previous for loop iteration, ignore this one (groups are merged by pairs of 2)
                # except if we are on the last member if the group 
                if last_loop_merged:
                    if tup_index + 1 == len(tuples_list):
                        merged_tuples.add(tuples_list[tup_index])
                    last_loop_merged = False
                    continue

                # of tuple at current index - 1 and at current index can merge, find the intersection between both tuples and add it to the merged_tuples set 
                if tuples_list[tup_index - 1][1] + 1 >= tuples_list[tup_index][0]:
                    min_add = min(tuples_list[tup_index - 1][0], tuples_list[tup_index][0])
                    max_add = max(tuples_list[tup_index - 1][1], tuples_list[tup_index][1])
                    merged_tuples.add((min_add, max_add))
                    #print(f"Merged {tuples_list[tup_index-1]} with {tuples_list[tup_index]} --> ({min_add},{max_add})")
                    merge_done = True
                    last_loop_merged = True

                # else just add the tuple at current index - 1 to the merged_tuples set and move to the next for loop iteration 
                else:
                    merged_tuples.add(tuples_list[tup_index - 1])
                    #print(f"Adding {tuples_list[tup_index-1]}")

                    # if we are at the last index of the group, add the lat member to the merged_tuples set 
                    if tup_index + 1 == len(tuples_list):
                        #print(f"Last index : adding {tuples_list[tup_index]}")
                        merged_tuples.add(tuples_list[tup_index])

            # merge_finished is set to True if no merge has been processed on the last for loop (iteration over the full tuples set)
            merge_finished = True if not merge_done else False
            #print(f"merge_finished : {merge_finished} / merge_done : {merge_done}")
            tuples_list = list(sorted(merged_tuples)) if merge_done else tuples_list
            #print(tuples_list)
        self.ip_tuples = list(sorted(tuples_list))

    # once all ip_tuples have been merged, calculate the group size (number of IPs on the AddressGroup)
    self.ip_count = self.calc_group_size()

def calc_group_size(self):
    size = 0
    for g in self.ip_tuples:
        size += g[1] - g[0] + 1
        #print(f"Diff between {ipaddress.ip_address(g[0])} and {ipaddress.ip_address(g[1])} is {g[1] - g[0]}")
    return size

def compare_groups(g1, g2, detail=False):
    i, j = 0, 0 
    intersect_nb = 0
    left_diff = 0
    right_diff = 0
    left_diff_detail = list()
    right_diff_detail = list()
    last_comparison_step = min(g1.min_ip, g2.min_ip)

    while last_comparison_step <= max(g1.max_ip, g2.max_ip):
        left_active = i < len(g1.ip_tuples) and last_comparison_step >= g1.ip_tuples[i][0] and last_comparison_step <= g1.ip_tuples[i][1]
        right_active = j < len(g2.ip_tuples) and last_comparison_step >= g2.ip_tuples[j][0] and last_comparison_step <= g2.ip_tuples[j][1]

        if left_active and right_active:
            # we are on an intersection range
            intersect_stop = min(g1.ip_tuples[i][1], g2.ip_tuples[j][1])
            intersect_nb += intersect_stop - last_comparison_step + 1
            last_comparison_step = intersect_stop + 1

            if last_comparison_step > g1.ip_tuples[i][1]:
                i += 1
            if last_comparison_step > g2.ip_tuples[j][1]:
                j += 1
        elif left_active:
            # adding to left diff
            if j < len(g2.ip_tuples):
                left_diff_stop = min(g1.ip_tuples[i][1], g2.ip_tuples[j][0] - 1)
            else:
                left_diff_stop = g1.ip_tuples[i][1]
            left_diff += left_diff_stop - last_comparison_step + 1
            if detail:
                left_diff_detail.append((last_comparison_step + 1, left_diff_stop))
            last_comparison_step = left_diff_stop + 1

            if last_comparison_step > g1.ip_tuples[i][1]:
                i += 1
        elif right_active:
            # adding to right diff
            if i < len(g1.ip_tuples):
                right_diff_stop = min(g2.ip_tuples[j][1], g1.ip_tuples[i][0] - 1)
            else:
                right_diff_stop = g2.ip_tuples[j][1]
            right_diff += right_diff_stop - last_comparison_step + 1
            if detail:
                right_diff_detail.append((last_comparison_step + 1, right_diff_stop))
            last_comparison_step = right_diff_stop + 1

            if last_comparison_step > g2.ip_tuples[j][1]:
                j += 1
        else:
            if i < len(g1.ip_tuples) and j < len(g2.ip_tuples):
                last_comparison_step = min(g1.ip_tuples[i][0], g2.ip_tuples[j][0])
            elif i < len(g1.ip_tuples):
                last_comparison_step = g1.ip_tuples[i][0]
            else: 
                last_comparison_step = g2.ip_tuples[j][0]

    # calculate the percent of match between G1 and G2 with the calculated values of intersect 
    percent_match = round(abs(intersect_nb) / (g1.ip_count + g2.ip_count - intersect_nb) * 100, 2) 

    if detail:
        return abs(intersect_nb), abs(left_diff), abs(right_diff), percent_match, left_diff_detail, right_diff_detail
    return abs(intersect_nb), abs(left_diff), abs(right_diff), percent_match