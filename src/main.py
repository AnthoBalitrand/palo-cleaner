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
        help = "Password to use for API connection to Panorama",
        default = ""
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

    parser.add_argument(
        "--superverbose",
        action = "store_true",
        help = "Enables super-verbose logs. WARNING --> lots of outputs to STDOUT !"
    )

    parser.add_argument(
        "--max-days-since-change",
        action = "store",
        help = "Don't apply any change to rules not having be modified since more than X days",
        default = 0
    )

    parser.add_argument(
        "--max-days-since-hit",
        action = "store",
        help = "Don't apply any change to rules not being hit since more than X days",
        default = 0
    )

    return parser.parse_args()


def main():
    # Get script start parameters list and values
    start_cli_args = parse_cli_args()

    # Instantiate the PaloCleaner object (connection to Panorama)
    cleaner = PaloCleaner(**start_cli_args.__dict__)
    cleaner.start()

    """

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