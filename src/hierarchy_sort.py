class DeviceGroup:
    def __init__(self, name):
        self.name = name 
        self.childs = list()
        self.parent = None
        self.level = 1
        # 0 = not included / 1 = partially included / 2 = fully included 
        self.inclusion_state = 0
        self.directly_included = False
        self.indirectly_included = False
        print(f"Added device-group {name}")

    def add_parent(self, parent):
        self.parent = parent 
        self.level = parent.level + 1
        parent.add_child(self)
        print(f"New parent for {self.name} is {self.parent.name}. New level for {self.name} is {self.level}")
    
    def add_child(self, child):
        if not child in self.childs: self.childs.append(child)

    def set_included(self, state=2, direct=False):
        if self.inclusion_state <= state:
            self.inclusion_state = state
            if self.parent: self.parent.set_included(1)
            if direct:
                for c in self.childs:
                    c.set_included()
            if len([x for x in self.childs if x.inclusion_state > 0]) == len(self.childs):
                self.inclusion_state = 2
        if not self.directly_included and direct:
            self.directly_included = direct 
            if self.indirectly_included : self.indirectly_included = False
        self.indirectly_included = True


    def __repr__(self):
        return f"{self.name} - inclusion_state : {self.inclusion_state} - direct : {self.directly_included} - indirect : {self.indirectly_included}"

pano_hierarchy = {
        'child1':'shared', 
        'child2':'shared',
        'child3':'shared',
        'child11':'child1',
        'child12':'child1',
        'child21':'child2',
        'child31':'child3',
        'child32':'child3',
        'child33':'child3'}

device_groups = dict() 
tree_depth = dict()

def populate_dg():
    loop = 0
    while len(device_groups) < len(pano_hierarchy):
        loop += 1
        for k, v in pano_hierarchy.items():
            if (v in device_groups.keys() or v == 'shared') and k not in device_groups.keys():
                device_groups[k] = DeviceGroup(k)
                if v != 'shared':
                    device_groups[k].add_parent(device_groups[v])
        print(f"While loop {loop}")

def gen_tree_depth():
    for k, v in device_groups.items():
        if not v.level in tree_depth:
            tree_depth[v.level] = list()
        tree_depth[v.level].append(v.name)


populate_dg()
gen_tree_depth()

device_groups['child33'].set_included(direct=True) 
device_groups['child32'].set_included(direct=True)
device_groups['child2'].set_included(direct=True)
device_groups['child31'].set_included(direct=True)

for k, v in device_groups.items():
    print(v)
