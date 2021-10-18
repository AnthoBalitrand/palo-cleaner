import getpass
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
        "--inline-mode",
        action = "store_true",
        help = "Displays logs per line instead of interactive mode"
    )

    parser.add_argument(
        "--apply-cleaning",
        action = "store_true",
        help = "Apply cleaning operation"
    )

    return parser.parse_args()


def main():
    start_cli_args = parse_cli_args()
    if not start_cli_args.api_password:
        pano_api_password = getpass.getpass(f"Password for API user {start_cli_args.api_user} : ")
    else:
        pano_api_password = start_cli_args.api_password

    cleaner = PaloCleaner(start_cli_args.panorama_url,
                start_cli_args.api_user,
                pano_api_password,
                start_cli_args.device_groups,
                start_cli_args.inline_mode)

    cleaner.reverse_dg_hierarchy(cleaner.get_pano_dg_hierarchy(), print_result=True)

    print("\n\nDownloading Panorama objects...")
    cleaner.fetch_objects(cleaner._panorama, 'shared')
    cleaner.fetch_objects(cleaner._panorama, 'predefined')
    print("Downloading Panorama rulebases...")
    cleaner.fetch_rulebase(cleaner._panorama, 'shared')
    #print(cleaner._rulebases)
    for dg in cleaner.get_devicegroups():
        context_name = dg.about()['name']
        print(f"Downloading {context_name} objects... ")
        cleaner.fetch_objects(dg, context_name)
        print(f"Downloading {context_name} rulebases... ")
        cleaner.fetch_rulebase(dg, context_name)
    print(f"Parsing used address objects set for shared... ")
    cleaner.fetch_address_obj_set('shared')
    for dg in cleaner.get_devicegroups():
        print(f"Parsing used address objects set for {dg}... ")
        cleaner.fetch_address_obj_set(dg.about()['name'])

    for dg in [k for k, v in cleaner.reverse_dg_hierarchy(cleaner.get_pano_dg_hierarchy()).items() if not v]:
        print(f"Starting cleaning process for {dg}")
        cleaner.optimize_address_objects(dg)

    #cleaner.remove_objects()

# entry point
if __name__ == "__main__":
    main()