import argparse
import sys
from argparse import RawTextHelpFormatter

from prowler.config.config import (
    available_compliance_frameworks,
    default_config_file_path,
    default_output_directory,
)
from prowler.providers.common.arguments import (
    init_providers_parser,
    validate_provider_arguments,
)


class ProwlerArgumentParser:
    # Set the default parser
    def __init__(self):
        # CLI Arguments
        self.parser = argparse.ArgumentParser(
            prog="prowler",
            formatter_class=RawTextHelpFormatter,
            epilog="""
To see the different available options on a specific provider, run:
    prowler {provider} -h|--help
Detailed documentation at https://docs.prowler.cloud
""",
        )

        # Common arguments parser
        self.common_providers_parser = argparse.ArgumentParser(add_help=False)

        # Providers Parser
        self.subparsers = self.parser.add_subparsers(
            title="Prowler Available Cloud Providers",
            dest="provider",
        )

        self.__init_outputs_parser__()
        self.__init_logging_parser__()
        self.__init_checks_parser__()
        self.__init_config_parser__()

        # Init Providers Arguments
        init_providers_parser(self)

    def parse(self, args=None) -> argparse.Namespace:
        """
        parse is a wrapper to call parse_args() and do some validation
        """
        # We can override sys.argv
        if args:
            sys.argv = args


        # Set AWS as the default provider if no provider is supplied
        if len(sys.argv) == 1:
            sys.argv = self.__set_default_provider__(sys.argv)


        # Parse arguments
        args = self.parser.parse_args()

        # A provider is always required
        if not args.provider:
            self.parser.error(
                "A provider is required to see its specific help options."
            )


        # Extra validation for provider arguments
        valid, message = validate_provider_arguments(args)
        if not valid:
            self.parser.error(f"{args.provider}: {message}")

        return args

    def __set_default_provider__(self, args: list) -> list:
        default_args = [args[0]]
        provider = "aws"
        default_args.append(provider)
        default_args.extend(args[1:])
        # Save the arguments with the default provider included
        return default_args

    def __init_outputs_parser__(self):
        # Outputs
        common_outputs_parser = self.common_providers_parser.add_argument_group(
            "Outputs"
        )
        common_outputs_parser.add_argument(
            # "-q",
            "--quiet",
            # action="store_true",
            # help="Store or send only Prowler failed findings",
        )
        common_outputs_parser.add_argument(
            # "-M",
            "--output-modes",
            # nargs="+",
            # help="Output modes, by default csv, html and json",
            default=["csv", "json", "html", "json-ocsf"],
            # choices=["csv", "json", "json-asff", "html", "json-ocsf"],
        )
        common_outputs_parser.add_argument(
            # "-F",
            "--output-filename",
            # nargs="?",
            # help="Custom output report name without the file extension, if not specified will use default output/prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format",
        )
        common_outputs_parser.add_argument(
            # "-o",
            "--output-directory",
            # nargs="?",
            # help="Custom output directory, by default the folder where Prowler is stored",
            default=default_output_directory,
        )
        common_outputs_parser.add_argument(
            "--verbose",
            # action="store_true",
            # help="Display detailed information about findings",
        )
        common_outputs_parser.add_argument(
        #     "-z",
            "--ignore-exit-code-3",
        #     action="store_true",
        #     help="Failed checks do not trigger exit code 3",
        )

        common_outputs_parser.add_argument(
            "--unix-timestamp",
            # action="store_true",
            default=False,
            # help="Set the output timestamp format as unix timestamps instead of iso format timestamps (default mode).",
        )

    def __init_logging_parser__(self):
        # Logging Options
        # Both options can be combined to only report to file some log level
        common_logging_parser = self.common_providers_parser.add_argument_group(
            "Logging"
        )
        common_logging_parser.add_argument(
            "--log-level",
            # choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="CRITICAL",
            # help="Select Log Level",
        )
        common_logging_parser.add_argument(
            "--log-file",
            # nargs="?",
            # help="Set log file name",
        )
        common_logging_parser.add_argument(
            "--only-logs",
            # action="store_true",
            # help="Print only Prowler logs by the stdout. This option sets --no-banner.",
        )


    def __init_checks_parser__(self):
        # Set checks to execute
        common_checks_parser = self.common_providers_parser.add_argument_group(
            "Specify checks/services to run"
        )
        # The following arguments needs to be set exclusivelly
        group = common_checks_parser.add_mutually_exclusive_group()
        group.add_argument(
            "--compliance",
            # nargs="+",
            # help="Compliance Framework to check against for. The format should be the following: framework_version_provider (e.g.: ens_rd2022_aws)",
            choices=available_compliance_frameworks,
        )

    def __init_config_parser__(self):
        config_parser = self.common_providers_parser.add_argument_group("Configuration")
        config_parser.add_argument(
            "--config-file",
            # nargs="?",
            default=default_config_file_path,
            # help="Set configuration file path",
        )


