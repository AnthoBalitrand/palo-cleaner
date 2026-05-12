"""
Shadow Object Detection Module for PaloCleaner

Detects address objects that are "shadowed" within the same rule field or group -
i.e., objects whose IP coverage is already included by another object or group
present in the same context (same rule source/destination, or same group members).

This allows safe removal of redundant objects without changing the effective
network coverage of the rule or group.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import List, Tuple, Set, Optional, Dict, Any, TYPE_CHECKING
import panos.objects

from ShadowRuleDetector import ip_to_tuple, merge_ip_tuples, is_ip_subset

if TYPE_CHECKING:
    from PaloCleaner import PaloCleaner


@dataclass
class ShadowObjectResult:
    """Result of shadow object detection within a rule or group"""
    location: str
    container_type: str  # "rule" or "group"
    container_name: str
    field_name: str  # "source", "destination", or "static_value" for groups
    shadowed_object: str  # name of the redundant object
    shadowing_objects: List[str]  # name(s) of the object(s) that cover it
    shadow_type: str  # "included" (IP subset) or "duplicate" (exact same IPs)


class ShadowObjectDetector:
    """Detects shadow/redundant address objects within rules and groups"""

    def __init__(self, palo_cleaner: 'PaloCleaner'):
        self._cleaner = palo_cleaner
        self._results: List[ShadowObjectResult] = []
        self._rule_removals: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
        self._group_removals: Dict[str, Dict[str, List[str]]] = {}

    def _resolve_object_ips(self, obj_name: str, location: str) -> Optional[List[Tuple[int, int]]]:
        """
        Resolve an address object/group to its IP tuples.
        Returns None if the object is an FQDN (skip those).
        """
        if obj_name == "any":
            return [(0, 4294967295)]

        ip_tuple = ip_to_tuple(obj_name)
        if ip_tuple:
            return [ip_tuple]

        obj, obj_loc = self._cleaner.get_relative_object_location(obj_name, location, "Address")
        if obj is None:
            return None

        flattened = self._cleaner.flatten_object(
            obj, obj_loc, location,
            referencer_type="ShadowObjectDetector",
            referencer_name="shadow_object_analysis"
        )

        ip_result = []
        for flat_obj, _ in flattened:
            if isinstance(flat_obj, panos.objects.AddressObject):
                value = flat_obj.value
                ip_tuple = ip_to_tuple(value)
                if ip_tuple:
                    ip_result.append(ip_tuple)
                else:
                    # FQDN detected - skip this entire object
                    return None

        return merge_ip_tuples(ip_result) if ip_result else None

    def _find_shadows_in_object_list(self, obj_names: List[str], location: str) -> List[Tuple[str, List[str], str]]:
        """
        Given a list of object names (from a rule field or group members),
        find which ones are shadowed by others in the same list.

        Returns list of (shadowed_obj_name, [shadowing_obj_names], shadow_type)
        """
        resolved = {}
        for name in obj_names:
            ips = self._resolve_object_ips(name, location)
            if ips is not None:
                resolved[name] = ips

        shadows = []
        already_shadowed = set()

        for candidate_name, candidate_ips in resolved.items():
            if candidate_name in already_shadowed:
                continue

            shadowing_names = []
            shadow_type = None

            for other_name, other_ips in resolved.items():
                if other_name == candidate_name:
                    continue
                if other_name in already_shadowed:
                    continue

                if is_ip_subset(candidate_ips, other_ips):
                    if set(candidate_ips) == set(other_ips):
                        # Exact duplicate - only report the one that appears later in the list
                        if obj_names.index(candidate_name) > obj_names.index(other_name):
                            shadow_type = "duplicate"
                            shadowing_names.append(other_name)
                    else:
                        shadow_type = "included"
                        shadowing_names.append(other_name)

            if shadowing_names:
                shadows.append((candidate_name, shadowing_names, shadow_type))
                already_shadowed.add(candidate_name)

        return shadows

    def analyze_rules_at_location(self, location: str) -> List[ShadowObjectResult]:
        """Analyze all rules at a location for shadow objects in source/destination fields"""
        from PaloCleanerConf import repl_map

        results = []
        self._rule_removals.setdefault(location, {})

        for rulebase_name, rulebase in self._cleaner._rulebases.get(location, {}).items():
            if rulebase_name == "context":
                continue

            rule_type_name = rulebase_name.split('_')[1]

            for rule in rulebase:
                if rule.disabled:
                    continue

                rule_type = type(rule)
                if rule_type not in repl_map:
                    continue

                addr_fields = repl_map[rule_type].get("Address", [])

                for field_spec in addr_fields:
                    if isinstance(field_spec, list):
                        field_name = field_spec[0]
                    else:
                        field_name = field_spec

                    field_value = getattr(rule, field_name, None)
                    if not field_value:
                        continue

                    if isinstance(field_value, str):
                        continue

                    if not isinstance(field_value, list) or len(field_value) < 2:
                        continue

                    if field_value == ["any"]:
                        continue

                    shadows = self._find_shadows_in_object_list(field_value, location)

                    for shadowed_name, shadowing_names, shadow_type in shadows:
                        result = ShadowObjectResult(
                            location=location,
                            container_type="rule",
                            container_name=rule.name,
                            field_name=field_name,
                            shadowed_object=shadowed_name,
                            shadowing_objects=shadowing_names,
                            shadow_type=shadow_type,
                        )
                        results.append(result)

                        self._rule_removals[location].setdefault(rule.name, {})
                        self._rule_removals[location][rule.name].setdefault(field_name, [])
                        self._rule_removals[location][rule.name][field_name].append(shadowed_name)

        self._results.extend(results)
        return results

    def analyze_groups_at_location(self, location: str) -> List[ShadowObjectResult]:
        """Analyze all address groups at a location for shadow members"""
        results = []
        self._group_removals.setdefault(location, {})

        for obj in self._cleaner._objects.get(location, {}).get("Address", []):
            if not isinstance(obj, panos.objects.AddressGroup):
                continue
            if not obj.static_value:
                continue
            if len(obj.static_value) < 2:
                continue

            shadows = self._find_shadows_in_object_list(obj.static_value, location)

            for shadowed_name, shadowing_names, shadow_type in shadows:
                result = ShadowObjectResult(
                    location=location,
                    container_type="group",
                    container_name=obj.name,
                    field_name="static_value",
                    shadowed_object=shadowed_name,
                    shadowing_objects=shadowing_names,
                    shadow_type=shadow_type,
                )
                results.append(result)

                self._group_removals[location].setdefault(obj.name, {})
                self._group_removals[location][obj.name].setdefault("static_value", [])
                self._group_removals[location][obj.name]["static_value"].append(shadowed_name)

        self._results.extend(results)
        return results

    def apply_rule_cleaning(self, location: str):
        """Remove shadow objects from rules at the given location"""
        if location not in self._rule_removals:
            return

        for rulebase_name, rulebase in self._cleaner._rulebases.get(location, {}).items():
            if rulebase_name == "context":
                continue

            for rule in rulebase:
                if rule.name not in self._rule_removals[location]:
                    continue

                rule_changes = self._rule_removals[location][rule.name]
                changed = False

                for field_name, objects_to_remove in rule_changes.items():
                    field_value = getattr(rule, field_name, None)
                    if not field_value or not isinstance(field_value, list):
                        continue

                    for obj_name in objects_to_remove:
                        if obj_name in field_value and len(field_value) > 1:
                            field_value.remove(obj_name)
                            changed = True
                            self._cleaner._console.log(
                                f"[ {location} ] Removed shadow object {obj_name!r} from rule {rule.name!r} field {field_name!r}",
                                style="yellow"
                            )

                    setattr(rule, field_name, field_value)

                if changed and self._cleaner._apply_cleaning:
                    try:
                        rule.apply()
                        self._cleaner._console.log(
                            f"[ {location} ] Applied shadow object cleaning to rule {rule.name!r}"
                        )
                    except Exception as e:
                        self._cleaner._console.log(
                            f"[ {location} ] Error applying shadow object cleaning to rule {rule.name!r}: {e}",
                            style="red"
                        )

    def apply_group_cleaning(self, location: str):
        """Remove shadow members from groups at the given location"""
        if location not in self._group_removals:
            return

        for obj in self._cleaner._objects.get(location, {}).get("Address", []):
            if not isinstance(obj, panos.objects.AddressGroup):
                continue
            if obj.name not in self._group_removals[location]:
                continue

            group_changes = self._group_removals[location][obj.name]
            changed = False

            for field_name, objects_to_remove in group_changes.items():
                if field_name != "static_value" or not obj.static_value:
                    continue

                for obj_name in objects_to_remove:
                    if obj_name in obj.static_value and len(obj.static_value) > 1:
                        obj.static_value.remove(obj_name)
                        changed = True
                        self._cleaner._console.log(
                            f"[ {location} ] Removed shadow member {obj_name!r} from group {obj.name!r}",
                            style="yellow"
                        )

            if changed and self._cleaner._apply_cleaning:
                try:
                    obj.apply()
                    self._cleaner._console.log(
                        f"[ {location} ] Applied shadow member cleaning to group {obj.name!r}"
                    )
                except Exception as e:
                    self._cleaner._console.log(
                        f"[ {location} ] Error applying shadow member cleaning to group {obj.name!r}: {e}",
                        style="red"
                    )

    def get_tables_by_location(self) -> Dict[str, List[Any]]:
        """Generate Rich Table objects grouped by location"""
        from rich.table import Table

        if not self._results:
            return {}

        by_location: Dict[str, List[ShadowObjectResult]] = {}
        for result in self._results:
            by_location.setdefault(result.location, []).append(result)

        tables = {}
        for location, results in by_location.items():
            # Group by container
            by_container: Dict[str, List[ShadowObjectResult]] = {}
            for r in results:
                key = f"{r.container_type}:{r.container_name}"
                by_container.setdefault(key, []).append(r)

            location_tables = []
            for container_key, container_results in by_container.items():
                container_type, container_name = container_key.split(":", 1)
                count = len(container_results)

                table = Table(
                    title=f"[bold cyan]{container_type.upper()}[/] [bold]{container_name}[/] — {count} shadow object(s)",
                    show_header=True,
                    header_style="bold cyan",
                    title_style="yellow",
                    border_style="dim",
                    show_lines=True,
                    caption=f"Location: {location}"
                )
                table.add_column("Field", style="bold", width=20)
                table.add_column("Shadow Object (REMOVE)", width=30)
                table.add_column("Covered By", width=40)
                table.add_column("Type", width=10, justify="center")

                for r in container_results:
                    table.add_row(
                        r.field_name,
                        f"[red]- {r.shadowed_object}[/red]",
                        ", ".join(r.shadowing_objects),
                        r.shadow_type,
                    )

                location_tables.append(table)

            tables[location] = location_tables

        return tables

    def get_summary(self) -> str:
        """Get a text summary of findings"""
        if not self._results:
            return "No shadow objects detected."

        rule_count = sum(1 for r in self._results if r.container_type == "rule")
        group_count = sum(1 for r in self._results if r.container_type == "group")
        return f"Found {rule_count} shadow object(s) in rules, {group_count} shadow member(s) in groups."
