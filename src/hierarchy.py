from rich.tree import Tree

class HierarchyDG:
    def __init__(self, dg_name):
        self.name = dg_name
        self.childs = list()
        self.parent = None
        self.level = 1

        # 0 = not included / 1 = partially included / 2 = fully included
        self.inclusion_state = 0

        self.directly_included = False
        self.indirectly_included = False

    def add_parent(self, parent):
        self.parent = parent
        self.level = parent.level + 1
        parent.add_child(self)

    def add_child(self, child):
        if not child in self.childs:
            self.childs.append(child)

    def set_included(self, state=2, direct=False, from_child=False, from_parent=False):
        if self.inclusion_state <= state:
            self.inclusion_state = state
            if self.parent and not from_parent:
                self.parent.set_included(1, from_child=True)
            if not from_child:
                for c in self.childs:
                    c.set_included(1, from_parent=True)
            if len([x for x in self.childs if x.inclusion_state > 0]) == len(self.childs):
                self.inclusion_state = 2
        if not self.directly_included and direct:
            self.directly_included = direct
            if self.indirectly_included:
                self.indirectly_included = False
        else:
            self.indirectly_included = True

    def tree_repr(self, clean_counts=None):
        style = "red" if self.inclusion_state == 2 else "yellow" if self.inclusion_state == 1 else "green"
        label = ""
        label += "+" if self.directly_included else "*" if self.indirectly_included else "-"
        label += " "
        label += "F" if self.inclusion_state == 2 else "P" if self.inclusion_state == 1 else " "
        label += " "
        label += self.name
        if clean_counts:
            label += "   " + ' '.join([f"{k} : {v['removed']}/{v['replaced']}" for k, v in clean_counts[self.name].items()])
        return {'label': label, 'style': style}

    def add_to_tree(self, tree, root=False, clean_counts=None):
        if not root:
            tree = tree.add(**self.tree_repr(clean_counts))
        for c in self.childs:
            c.add_to_tree(tree)

    def get_tree(self, clean_counts=None):
        init_tree = Tree(**self.tree_repr(clean_counts))
        self.add_to_tree(init_tree, root=True, clean_counts=clean_counts)
        return init_tree

    @classmethod
    def gen_depth_tree(cls, dg_dict):
        depth_tree = dict()
        for k, v in dg_dict.items():
            if not v.level in depth_tree:
                depth_tree[v.level] = list()
            depth_tree[v.level].append(v.name)

        return depth_tree

    @classmethod
    def get_perimeter(cls, dg_dict):
        return {
            "direct": [k for k, v in dg_dict.items() if v.directly_included],
            "indirect": [k for k, v in dg_dict.items() if v.indirectly_included],
            "full": [k for k, v in dg_dict.items() if v.inclusion_state == 2]
        }
