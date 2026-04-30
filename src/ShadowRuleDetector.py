"""
Shadow Rule Detection Module for PaloCleaner

Detects rules that are "shadowed" by other rules - i.e., rules whose traffic
would already be handled by a broader rule, making them redundant.

Rule A is shadowed by Rule B if:
- A's sources ⊆ B's sources
- A's destinations ⊆ B's destinations
- A's services ⊆ B's services
- A's applications ⊆ B's applications
- Same action (allow/deny)
- Same zone direction
"""

import ipaddress
from dataclasses import dataclass, field
from typing import List, Tuple, Set, Optional, Dict, Any, TYPE_CHECKING
from panos.policies import SecurityRule
import panos.objects

if TYPE_CHECKING:
    from rich.table import Table


@dataclass
class NormalizedRule:
    """A rule normalized to its actual IP ranges and services for comparison"""
    name: str
    location: str
    rule_ref: SecurityRule
    source_zones: Set[str] = field(default_factory=set)
    destination_zones: Set[str] = field(default_factory=set)
    source_ips: List[Tuple[int, int]] = field(default_factory=list)  # (min_ip, max_ip) tuples
    destination_ips: List[Tuple[int, int]] = field(default_factory=list)
    source_fqdns: Set[str] = field(default_factory=set)  # FQDN values (compared as strings)
    destination_fqdns: Set[str] = field(default_factory=set)  # FQDN values (compared as strings)
    services: Set[str] = field(default_factory=set)  # "tcp/None/443" format
    applications: Set[str] = field(default_factory=set)
    source_users: Set[str] = field(default_factory=set)  # User-ID filtering
    categories: Set[str] = field(default_factory=set)  # URL category filtering
    url_filtering: Optional[str] = None  # URL filtering profile name
    action: str = "allow"
    disabled: bool = False


@dataclass
class ShadowResult:
    """Result of shadow detection between two rules"""
    shadowed_rule: NormalizedRule
    shadowing_rule: NormalizedRule
    shadow_type: str  # "exact", "subset", "superset"


def ip_to_tuple(ip_str: str) -> Optional[Tuple[int, int]]:
    """Convert an IP address/network/range string to (min, max) integer tuple"""
    try:
        if '-' in ip_str:
            # IP range: 192.168.1.1-192.168.1.10
            start, end = ip_str.split('-')
            return (int(ipaddress.ip_address(start)), int(ipaddress.ip_address(end)))
        else:
            # Single IP or CIDR
            net = ipaddress.ip_network(ip_str, strict=False)
            return (int(net.network_address), int(net.broadcast_address))
    except ValueError:
        # FQDN or invalid - skip
        return None


def merge_ip_tuples(tuples: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping/adjacent IP ranges"""
    if not tuples:
        return []

    sorted_tuples = sorted(tuples)
    merged = [sorted_tuples[0]]

    for current in sorted_tuples[1:]:
        last = merged[-1]
        if current[0] <= last[1] + 1:  # Overlapping or adjacent
            merged[-1] = (last[0], max(last[1], current[1]))
        else:
            merged.append(current)

    return merged


def is_ip_subset(subset_tuples: List[Tuple[int, int]], superset_tuples: List[Tuple[int, int]]) -> bool:
    """Check if all IPs in subset_tuples are contained in superset_tuples"""
    if not subset_tuples:
        return True
    if not superset_tuples:
        return False

    # Handle "any" case (0.0.0.0/0)
    for t in superset_tuples:
        if t[0] == 0 and t[1] == 4294967295:  # 0.0.0.0 to 255.255.255.255
            return True

    subset_merged = merge_ip_tuples(subset_tuples)
    superset_merged = merge_ip_tuples(superset_tuples)

    for sub_range in subset_merged:
        covered = False
        for sup_range in superset_merged:
            if sub_range[0] >= sup_range[0] and sub_range[1] <= sup_range[1]:
                covered = True
                break
        if not covered:
            return False

    return True


def is_service_subset(subset: Set[str], superset: Set[str]) -> bool:
    """Check if services in subset are covered by superset"""
    if not subset:
        return True
    if "any" in superset:  # Only "any" covers everything, not application-default
        return True
    if "any" in subset:
        return "any" in superset
    return subset.issubset(superset)


def is_application_subset(subset: Set[str], superset: Set[str]) -> bool:
    """Check if applications in subset are covered by superset"""
    if not subset:
        return True
    if "any" in superset:
        return True
    if "any" in subset:
        return "any" in superset
    return subset.issubset(superset)


def is_user_subset(subset: Set[str], superset: Set[str]) -> bool:
    """Check if source users in subset are covered by superset"""
    if not subset:
        return True
    if "any" in superset:
        return True
    if "any" in subset:
        return "any" in superset
    return subset.issubset(superset)


def is_category_subset(subset: Set[str], superset: Set[str]) -> bool:
    """Check if URL categories in subset are covered by superset"""
    if not subset:
        return True
    if "any" in superset:
        return True
    if "any" in subset:
        return "any" in superset
    return subset.issubset(superset)


def is_url_filtering_match(profile_a: Optional[str], profile_b: Optional[str]) -> bool:
    """
    Check if URL filtering profiles match.
    Rules must have the same profile (or both have none) to be considered shadows.
    Different profiles mean different traffic handling.
    """
    # Both None or empty - match
    if not profile_a and not profile_b:
        return True
    # One has profile, other doesn't - no match
    if not profile_a or not profile_b:
        return False
    # Both have profiles - must be the same
    return profile_a == profile_b


def is_fqdn_subset(subset: Set[str], superset: Set[str]) -> bool:
    """
    Check if FQDNs in subset are covered by superset.
    FQDNs must match exactly (no wildcard/subnet logic).
    If subset has FQDNs but superset doesn't, it's NOT a subset.
    """
    if not subset:
        # No FQDNs in subset - OK
        return True
    if not superset:
        # Subset has FQDNs but superset doesn't - NOT a subset
        return False
    # Both have FQDNs - check exact match
    return subset.issubset(superset)


def is_zone_match(rule_a: NormalizedRule, rule_b: NormalizedRule) -> bool:
    """Check if zones match (both directions)"""
    # Handle "any" zones
    a_src = rule_a.source_zones or {"any"}
    a_dst = rule_a.destination_zones or {"any"}
    b_src = rule_b.source_zones or {"any"}
    b_dst = rule_b.destination_zones or {"any"}

    if "any" in b_src:
        src_match = True
    else:
        src_match = a_src.issubset(b_src) or "any" in a_src

    if "any" in b_dst:
        dst_match = True
    else:
        dst_match = a_dst.issubset(b_dst) or "any" in a_dst

    return src_match and dst_match


def is_shadowed_by(rule_a: NormalizedRule, rule_b: NormalizedRule) -> Optional[str]:
    """
    Check if rule_a is shadowed by rule_b.
    Returns shadow type if shadowed, None otherwise.
    """
    # Skip disabled rules
    if rule_a.disabled or rule_b.disabled:
        return None

    # Same rule check
    if rule_a.name == rule_b.name and rule_a.location == rule_b.location:
        return None

    # Action must match
    if rule_a.action != rule_b.action:
        return None

    # Zone check
    if not is_zone_match(rule_a, rule_b):
        return None

    # Source IP check
    if not is_ip_subset(rule_a.source_ips, rule_b.source_ips):
        return None

    # Source FQDN check (FQDNs must match exactly)
    if not is_fqdn_subset(rule_a.source_fqdns, rule_b.source_fqdns):
        return None

    # Destination IP check
    if not is_ip_subset(rule_a.destination_ips, rule_b.destination_ips):
        return None

    # Destination FQDN check (FQDNs must match exactly)
    if not is_fqdn_subset(rule_a.destination_fqdns, rule_b.destination_fqdns):
        return None

    # Service check
    if not is_service_subset(rule_a.services, rule_b.services):
        return None

    # Application check
    if not is_application_subset(rule_a.applications, rule_b.applications):
        return None

    # Source user check (User-ID)
    if not is_user_subset(rule_a.source_users, rule_b.source_users):
        return None

    # URL category check
    if not is_category_subset(rule_a.categories, rule_b.categories):
        return None

    # URL filtering profile check (must match exactly)
    if not is_url_filtering_match(rule_a.url_filtering, rule_b.url_filtering):
        return None

    # Determine shadow type
    src_ip_exact = set(rule_a.source_ips) == set(rule_b.source_ips)
    src_fqdn_exact = rule_a.source_fqdns == rule_b.source_fqdns
    dst_ip_exact = set(rule_a.destination_ips) == set(rule_b.destination_ips)
    dst_fqdn_exact = rule_a.destination_fqdns == rule_b.destination_fqdns
    svc_exact = rule_a.services == rule_b.services
    app_exact = rule_a.applications == rule_b.applications
    user_exact = rule_a.source_users == rule_b.source_users
    cat_exact = rule_a.categories == rule_b.categories
    url_filter_exact = rule_a.url_filtering == rule_b.url_filtering

    if (src_ip_exact and src_fqdn_exact and dst_ip_exact and dst_fqdn_exact and
            svc_exact and app_exact and user_exact and cat_exact and url_filter_exact):
        return "exact"
    return "subset"


class ShadowRuleDetector:
    """Detects shadow rules in a PaloCleaner instance"""

    def __init__(self, palo_cleaner):
        self._cleaner = palo_cleaner
        self._normalized_rules: Dict[str, List[NormalizedRule]] = {}
        self._shadow_results: List[ShadowResult] = []

    def _resolve_address(self, addr_name: str, location: str) -> Tuple[List[Tuple[int, int]], Set[str]]:
        """
        Resolve an address object/group name to list of IP tuples AND set of FQDNs.
        Uses PaloCleaner's flatten_object to handle deeply nested groups and DAGs.

        Returns: (ip_tuples, fqdns)
        """
        if addr_name == "any":
            return [(0, 4294967295)], set()  # 0.0.0.0/0, no FQDNs

        # Check if it's a direct IP/CIDR (used inline in rules)
        ip_tuple = ip_to_tuple(addr_name)
        if ip_tuple:
            return [ip_tuple], set()

        # Resolve the object and its location in the hierarchy
        obj, obj_loc = self._cleaner.get_relative_object_location(addr_name, location, "Address")
        if obj is None:
            return [], set()

        # Use flatten_object to recursively resolve all nested groups/DAGs
        flattened = self._cleaner.flatten_object(
            obj, obj_loc, location,
            referencer_type="ShadowDetector",
            referencer_name="shadow_analysis"
        )

        # Extract IP tuples and FQDNs from all flattened AddressObjects
        ip_result = []
        fqdn_result = set()
        for flat_obj, _ in flattened:
            if isinstance(flat_obj, panos.objects.AddressObject):
                value = flat_obj.value
                ip_tuple = ip_to_tuple(value)
                if ip_tuple:
                    ip_result.append(ip_tuple)
                else:
                    # Not an IP - treat as FQDN
                    fqdn_result.add(value.lower())  # Normalize to lowercase for comparison
            # Skip AddressGroups (they're containers) and Tags

        return ip_result, fqdn_result

    def _resolve_service_to_strings(self, svc_name: str, location: str) -> Set[str]:
        """
        Resolve a service object/group name to set of service strings.
        Uses PaloCleaner's flatten_object to handle nested ServiceGroups.
        """
        if svc_name in ("any", "application-default"):
            return {svc_name}

        obj, obj_loc = self._cleaner.get_relative_object_location(svc_name, location, "Service")
        if obj is None:
            return {svc_name}  # Might be predefined

        # Use flatten_object to recursively resolve all nested service groups
        flattened = self._cleaner.flatten_object(
            obj, obj_loc, location,
            referencer_type="ShadowDetector",
            referencer_name="shadow_analysis"
        )

        # Extract service strings from all flattened ServiceObjects
        from PaloCleanerTools import stringify_service
        result = set()
        for flat_obj, _ in flattened:
            if isinstance(flat_obj, panos.objects.ServiceObject):
                result.add(stringify_service(flat_obj))
            # Skip ServiceGroups (they're containers)

        return result if result else {svc_name}

    def normalize_rule(self, rule: SecurityRule, location: str) -> NormalizedRule:
        """Convert a SecurityRule to a NormalizedRule for comparison"""
        normalized = NormalizedRule(
            name=rule.name,
            location=location,
            rule_ref=rule,
            action=rule.action or "allow",
            disabled=rule.disabled or False
        )

        # Zones
        if rule.fromzone:
            normalized.source_zones = set(rule.fromzone)
        if rule.tozone:
            normalized.destination_zones = set(rule.tozone)

        # Source addresses (IPs and FQDNs)
        sources = rule.source or ["any"]
        for src in sources:
            ips, fqdns = self._resolve_address(src, location)
            normalized.source_ips.extend(ips)
            normalized.source_fqdns.update(fqdns)
        normalized.source_ips = merge_ip_tuples(normalized.source_ips)

        # Destination addresses (IPs and FQDNs)
        destinations = rule.destination or ["any"]
        for dst in destinations:
            ips, fqdns = self._resolve_address(dst, location)
            normalized.destination_ips.extend(ips)
            normalized.destination_fqdns.update(fqdns)
        normalized.destination_ips = merge_ip_tuples(normalized.destination_ips)

        # Services
        services = rule.service or ["any"]
        for svc in services:
            normalized.services.update(self._resolve_service_to_strings(svc, location))

        # Applications
        if rule.application:
            normalized.applications = set(rule.application)
        else:
            normalized.applications = {"any"}

        # Source users (User-ID)
        if hasattr(rule, 'source_user') and rule.source_user:
            normalized.source_users = set(rule.source_user)
        else:
            normalized.source_users = {"any"}

        # URL categories
        if hasattr(rule, 'category') and rule.category:
            normalized.categories = set(rule.category)
        else:
            normalized.categories = {"any"}

        # URL filtering profile
        if hasattr(rule, 'url_filtering') and rule.url_filtering:
            normalized.url_filtering = rule.url_filtering

        return normalized

    def analyze_location(self, location: str) -> List[ShadowResult]:
        """Analyze rules at a specific location for shadows"""
        results = []
        normalized_rules = []

        # Collect all security rules at this location
        for key, rules in self._cleaner._rulebases.get(location, {}).items():
            if key == "context":
                continue
            if "SecurityRule" not in key:
                continue

            for rule in rules:
                normalized_rules.append(self.normalize_rule(rule, location))

        self._normalized_rules[location] = normalized_rules

        # Track which rules are already reported as shadowed by their exact-duplicate group leader
        reported_as_exact_duplicate: Set[int] = set()

        # First pass: identify exact duplicate groups and report them
        # For each rule, find the earliest rule that is an exact duplicate (mutual shadow)
        for i, rule_a in enumerate(normalized_rules):
            if i in reported_as_exact_duplicate:
                continue

            # Find all exact duplicates of rule_a (rules that shadow each other mutually)
            duplicates = []
            for j, rule_b in enumerate(normalized_rules):
                if i >= j:
                    continue
                if j in reported_as_exact_duplicate:
                    continue

                shadow_type_ab = is_shadowed_by(rule_a, rule_b)
                shadow_type_ba = is_shadowed_by(rule_b, rule_a)

                if shadow_type_ab == "exact" and shadow_type_ba == "exact":
                    duplicates.append(j)

            # Report all duplicates as shadowed by rule_a (the first/canonical one)
            for j in duplicates:
                results.append(ShadowResult(
                    shadowed_rule=normalized_rules[j],
                    shadowing_rule=rule_a,
                    shadow_type="exact"
                ))
                reported_as_exact_duplicate.add(j)

        # Second pass: find subset shadows (non-mutual)
        for i, rule_a in enumerate(normalized_rules):
            for j, rule_b in enumerate(normalized_rules):
                if i >= j:
                    continue

                # Skip pairs already handled as exact duplicates
                if i in reported_as_exact_duplicate or j in reported_as_exact_duplicate:
                    # But still check if the non-duplicate rule shadows/is shadowed by others
                    pass

                shadow_type_ab = is_shadowed_by(rule_a, rule_b)
                shadow_type_ba = is_shadowed_by(rule_b, rule_a)

                # Skip exact duplicates (already handled)
                if shadow_type_ab == "exact" and shadow_type_ba == "exact":
                    continue

                # Report subset shadows (only one direction is true)
                if shadow_type_ab:
                    results.append(ShadowResult(
                        shadowed_rule=rule_a,
                        shadowing_rule=rule_b,
                        shadow_type=shadow_type_ab
                    ))
                if shadow_type_ba:
                    results.append(ShadowResult(
                        shadowed_rule=rule_b,
                        shadowing_rule=rule_a,
                        shadow_type=shadow_type_ba
                    ))

        self._shadow_results.extend(results)
        return results

    def analyze_all(self) -> List[ShadowResult]:
        """Analyze all locations for shadow rules"""
        all_results = []

        for location in self._cleaner._rulebases:
            results = self.analyze_location(location)
            all_results.extend(results)

        return all_results

    @staticmethod
    def _format_field(values, max_items: int = 3) -> str:
        """Format a list/set of values, showing max_items with '...' if truncated"""
        if not values:
            return "any"
        items = list(values)[:max_items]
        result = "\n".join(str(v) for v in items)
        if len(values) > max_items:
            result += "\n..."
        return result

    def get_tables_by_location(self) -> Dict[str, List[Any]]:
        """
        Generate Rich Table objects grouped by location, then by shadowing (master) rule.
        Returns a dict: {location: [Table, Table, ...]}
        Each table shows an "ultimate master" rule at the top and all redundant rules below.
        Only rules that are NOT themselves shadowed by another rule are shown as masters.
        """
        from rich.table import Table

        if not self._shadow_results:
            return {}

        # First, identify all rules that are shadowed by something (per location)
        # These cannot be "ultimate masters"
        shadowed_rules_by_location: Dict[str, Set[str]] = {}
        for result in self._shadow_results:
            loc = result.shadowed_rule.location
            if loc not in shadowed_rules_by_location:
                shadowed_rules_by_location[loc] = set()
            shadowed_rules_by_location[loc].add(result.shadowed_rule.name)

        # Group by location, then by shadowing rule (the master rule)
        by_location: Dict[str, Dict[str, List[ShadowResult]]] = {}
        for result in self._shadow_results:
            loc = result.shadowed_rule.location
            if loc not in by_location:
                by_location[loc] = {}

            # Group by the SHADOWING rule (the master that covers others)
            shadowing_key = result.shadowing_rule.name
            if shadowing_key not in by_location[loc]:
                by_location[loc][shadowing_key] = []
            by_location[loc][shadowing_key].append(result)

        tables = {}
        for location, by_shadowing in by_location.items():
            location_tables = []
            shadowed_rules = shadowed_rules_by_location.get(location, set())

            for shadowing_name, shadow_results in by_shadowing.items():
                # Skip this "master" if it is itself shadowed by another rule
                # (it's not an "ultimate master")
                if shadowing_name in shadowed_rules:
                    continue

                # Get the shadowing (master) rule
                shadowing_rule = shadow_results[0].shadowing_rule
                master_rule = shadowing_rule.rule_ref

                # Create a table for each master rule
                table = Table(
                    title=f"[bold green]{shadowing_name}[/] covers {len(shadow_results)} rule(s) that can be deleted",
                    show_header=True,
                    header_style="bold cyan",
                    title_style="yellow",
                    border_style="dim",
                    show_lines=True,
                    caption=f"Location: {location}"
                )
                table.add_column("Rule", style="bold", width=40)
                table.add_column("Src Zones", width=15)
                table.add_column("Source", width=18)
                table.add_column("Dst Zones", width=15)
                table.add_column("Destination", width=18)
                table.add_column("Services", width=15)
                table.add_column("Apps", width=15)
                table.add_column("Users", width=15)
                table.add_column("Categories", width=15)
                table.add_column("Action", width=8, justify="center")

                # Add master rule row at the top (green - KEEP this rule)
                table.add_row(
                    f"{shadowing_name} (KEEP)",
                    self._format_field(master_rule.fromzone),
                    self._format_field(master_rule.source),
                    self._format_field(master_rule.tozone),
                    self._format_field(master_rule.destination),
                    self._format_field(master_rule.service),
                    self._format_field(master_rule.application),
                    self._format_field(master_rule.source_user),
                    self._format_field(master_rule.category),
                    shadowing_rule.action,
                    style="green"
                )

                # Add shadowed rules below (dim - these are redundant and can be DELETED)
                for result in shadow_results:
                    shadowed = result.shadowed_rule
                    srule = shadowed.rule_ref
                    table.add_row(
                        f"  {shadowed.name} ({result.shadow_type})",
                        self._format_field(srule.fromzone),
                        self._format_field(srule.source),
                        self._format_field(srule.tozone),
                        self._format_field(srule.destination),
                        self._format_field(srule.service),
                        self._format_field(srule.application),
                        self._format_field(srule.source_user),
                        self._format_field(srule.category),
                        shadowed.action,
                        style="dim"
                    )

                location_tables.append(table)

            tables[location] = location_tables

        return tables

    def get_report(self) -> str:
        """Generate a text report of shadow rule findings (fallback for non-Rich output)"""
        if not self._shadow_results:
            return "No shadow rules detected."

        lines = []

        # Group by shadowing rule for compact display
        by_location = {}
        for result in self._shadow_results:
            loc = result.shadowed_rule.location
            if loc not in by_location:
                by_location[loc] = {}
            shadowing_name = result.shadowing_rule.name
            if shadowing_name not in by_location[loc]:
                by_location[loc][shadowing_name] = []
            by_location[loc][shadowing_name].append(result)

        for location, by_shadowing in by_location.items():
            lines.append(f"\n[ {location} ]")
            for shadowing_name, results in by_shadowing.items():
                shadowed_list = ", ".join([r.shadowed_rule.name for r in results])
                lines.append(f"  {shadowed_list} <- shadowed by '{shadowing_name}'")

        lines.append(f"\nTotal: {len(self._shadow_results)} shadow rule(s)")
        return "\n".join(lines)
