from panos.objects import AddressObject, AddressGroup, Tag, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, NatRule, AuthenticationRule

repl_map = {
    SecurityRule: {
        "Address": [["source"], ["destination"]],
        "Service": [["service"]],
        "Tag": [["tag"]],
    },
    NatRule: {
        "Address": [["source"], ["destination"], "source_translation_ip_address", ["source_translation_translated_addresses"], "source_translation_static_translated_address", "destination_translated_address"],
        "Service": ["service"],
        "Tag": [["tag"]],
    },
    AuthenticationRule: {
        "Address": [["source_addresses"], ["destination_addresses"]],
        "Service": [["service"]],
        "Tag": [["tag"]],
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