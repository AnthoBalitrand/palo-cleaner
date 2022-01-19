import argparse
from PaloCleaner import PaloCleaner

def parse_cli_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--panorama-url",
        action = "store",
        help = "Address of the Panorama server to which to connect",
        required = True
    )

    parser.add_argument(
        "--device-groups",
        nargs = "+",
        action = "extend",
        type = str,
        help = "List of device-groups to be included in the cleaning process"
    )

    parser.add_argument(
        "--api-user",
        action = "store",
        help = "Username to use for API connection to Panorama",
        required = True
    )

    parser.add_argument(
        "--api-password",
        action = "store",
        help = "Password to use for API connection to Panorama"
    )

    parser.add_argument(
        "--apply-cleaning",
        action = "store_true",
        help = "Apply cleaning operation"
    )

    parser.add_argument(
        "--delete-upward-objects",
        action = "store_true",
        help = "Deletes upward unused objects (shared + intermediates) if all childs are analyzed"
    )

    return parser.parse_args()


def main():
    # Get script start parameters list and values
    start_cli_args = parse_cli_args()

    # If password has not been provided in the command arguments, ask for it with getpass.getpass
    if not start_cli_args.api_password:
        pano_api_password = ""

    # Instantiate the PaloCleaner object (connection to Panorama)
    cleaner = PaloCleaner(start_cli_args.panorama_url,
                start_cli_args.api_user,
                pano_api_password,
                start_cli_args.device_groups,
                start_cli_args.apply_cleaning)
    cleaner.start()
    """

    # Get used address objects set for Panorama (shared context)
    print(f"Parsing used address objects set for shared... ", end="")
    cleaner.fetch_address_obj_set('shared', )

    # Get used address objects set for all device groups
    for dg in cleaner.get_devicegroups():
        if dg.about()['name'] in analysis_perimeter['direct'] + analysis_perimeter['indirect']:
            print(f"Parsing used address objects set for {dg}... ", end="")
            cleaner.fetch_address_obj_set(dg.about()['name'])

    # Start objects optimization for all DeviceGroup not having child
    for dg in [k for k, v in cleaner.reverse_dg_hierarchy(cleaner.get_pano_dg_hierarchy()).items() if not v]:
        if dg in analysis_perimeter['direct'] + analysis_perimeter['indirect']:
            print(f"Starting objects optimization processing for {dg}")
            cleaner.optimize_address_objects(dg)

    cleaner.remove_objects(analysis_perimeter, start_cli_args.delete_upward_objects)
    """
# entry point
if __name__ == "__main__":
    main()