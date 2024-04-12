import argparse
import os
import time
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
        help = "Apply cleaning operation",
        default = False,
    )

    parser.add_argument(
        "--verbosity", "-v",
        action = "count",
        default = 1,
        help = "Verbosity level (from 1 to 3)"
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
        default = 0,
    )

    parser.add_argument(
        "--tiebreak-tag",
        nargs="+",
        action="extend",
        type=str,
        help = "Tag(s) used to choose preferred replacement object in case of multiple ones (overrides default choice)",
        default = None,
    )

    parser.add_argument(
        "--apply-tiebreak-tag",
        action = "store_true",
        help = "Applies the first tag defined on the --tiebreak-tag argument to objects choosen by the choice algorithm",
        default = False,
    )

    parser.add_argument(
        "--no-report" ,
        action = "store_true",
        help = "Does not generates job reports",
        default = False,
    )

    parser.add_argument(
        "--split-report",
        action = "store_true",
        help = "Split the report file (1 per device-group)",
        default = False,
    )

    parser.add_argument(
        "--favorise-tagged-objects",
        action = "store_true",
        help = "Favorise objects referenced on DAG or having DAGs when eliminating duplicates (works only for shared objects)",
        default = False,
    )

    parser.add_argument(
        "--multithread", "-m",
        dest = 'number_of_threads',
        type = int,
        action = "store",
        help = "Perform multithreading for objects replacement in rulebases and groups with X threads (no value or 0: number of system's CPU)",
        nargs = '?',
        const = 0,
    )

    parser.add_argument(
        "--ignore-appliances-opstate",
        nargs = "+",
        action = "extend",
        type = str,
        help = "List of appliances IP address for which opstate needs to be ignored (will not connect to get hitcounts)"
    )

    parser.add_argument(
        "--unused-only",
        nargs="*",
        action = "extend",
        type=str,
        help = "Only deletes unused objects. No replacements are realized. List of device-groups can be provided. Will work only if the provided device-groups are fully included in the analysis",
        default = None
    )

    parser.add_argument(
        "--protect-potential-replacements",
        action = "store_true",
        help = "Only when using --unused-only. Permits to not delete objects that could be used as replacements, even if they are not used for now",
        default = False
    )

    parser.add_argument(
        "--protect-tags",
        nargs="+",
        action="extend",
        type=str,
        help = "List of tags which will protect objects from deletion"
    )

    parser.add_argument(
        "--bulk-operations",
        action = "store_true",
        help = "API calls using bulk operations",
        default = False
    )

    parser.add_argument(
        "--same-name-only",
        action = "store_true",
        help = "Only replaces objects by ones existing at upward levels, and having same values",
        default = False
    )

    return parser.parse_args()


def main():
    # Get script start parameters list and values
    start_cli_args = parse_cli_args()

    # if the --apply-tiebreak-tag has been used without the --tiebreak-tag argument value, raise en error and exit
    if start_cli_args.apply_tiebreak_tag and not start_cli_args.tiebreak_tag:
        print("\n ERROR - --apply-tiebreak-tag has been called without --tiebreak-tag \n")
        exit(0)

    if start_cli_args.protect_potential_replacements and start_cli_args.unused_only is None:
        print("\n ERROR - --protect-potential-replacements has been called without --unused-only \n")
        exit(0)

    if start_cli_args.bulk_operations and start_cli_args.number_of_threads is not None:
        print("\n Error - --bulk-operations cannot be used in conjunction with --multithread \n")
        exit(0)

    # create the report directory if requested
    report_folder = None
    if not start_cli_args.no_report:
        report_folder = os.path.dirname(os.path.abspath(__file__)).replace('/src', '')
        report_folder += '/reports/'
        report_folder += str(int(time.time()))
        print(f"Report folder will be {report_folder}")
        os.mkdir(report_folder)

    # Instantiate the PaloCleaner object (connection to Panorama)
    cleaner = PaloCleaner(report_folder, **start_cli_args.__dict__)
    cleaner.start()

# entry point
if __name__ == "__main__":
    start = time.time()
    main()
    end = time.time()
    print(end - start)