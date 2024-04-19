from panos.objects import AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, NatRule, AuthenticationRule, PolicyBasedForwarding, DecryptionRule, ApplicationOverride

# The structure below identifies the attributes and their format used on each type of rules
# it permits to identify which "referenced object type" can be found on each rule attribute,
# and with which format (string or list)

# For PolicyBasedForwarding rules, type can vary. The ones which can be either string or list are referenced as list
# and mismatching situations are handled directly on the PaloCleaner code

repl_map = {
    SecurityRule: {
        "Address": [["source"], ["destination"]],
        "Service": [["service"]],
        "Tag": [["tag"]],
    },
    NatRule: {
        "Address": [
            ["source"],
            ["destination"],
            "source_translation_ip_address",
            ["source_translation_translated_addresses"],
            "source_translation_static_translated_address",
            "destination_translated_address",
            ["source_translation_fallback_translated_addresses"],
            "source_translation_fallback_ip_address", 
            "destination_dynamic_translated_address"
        ],
        "Service": ["service"],
        "Tag": [["tag"]],
    },
    AuthenticationRule: {
        "Address": [["source_addresses"], ["destination_addresses"]],
        "Service": [["service"]],
        "Tag": [["tag"]],
    },
    PolicyBasedForwarding: {
        "Address": [
            ["source_addresses"],
            ["destination_addresses"],
            "forward_next_hop_value"
        ],
        "Service": [["services"]],
        "Tag": [["tags"]]
    }, 
    DecryptionRule: {
        "Address": [["source_addresses"], ["destination_addresses"]], 
        "Service": [["services"]], 
        "Tag": [["tags"]]
    }, 
    ApplicationOverride: {
        "Address": [["source"], ["destination"]], 
        "Service": [], 
        "Tag": [["tag"]]
    }
}

# Keep your big fingers away than this unless you really know what you are doing
cleaning_order = {
    1: {"Address": AddressGroup},
    2: {"Service": ServiceGroup},
    3: {"Address": AddressObject},
    4: {"Service": ServiceObject},
    5: {"Tag": Tag}
}