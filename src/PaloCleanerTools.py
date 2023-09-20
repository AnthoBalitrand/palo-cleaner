import panos.objects

def hostify_address(address: str) -> str:
    """
    Used to remove /32 at the end of an IP address

    Commenting : OK (15062023)

    :param address: (string) IP address to be modified
    :return: (string) Host IP address (instead of network /32)
    """

    # removing /32 mask for hosts
    if address[-3:] == '/32':
        return address[:-3:]
    return address


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