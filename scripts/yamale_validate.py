#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

from yamale import validate
from yamale import make_data
from yamale import make_schema
from yamale import YamaleError
import argparse


def yamale_invalid(yaml_file, schema="", silent=True):
    if not schema:
        schema = yaml_file.split(".")
        schema = schema[0] + "_schema." + schema[1]
    data = make_data(yaml_file)
    schema = make_schema(schema)
    try:
        validate(schema, data, strict=True)
        if not silent:
            print("Validation success!")
        return False
    except YamaleError as e:
        if not silent:
            print("Validation failed!")
            for result in e.results:
                print("Error validating data "
                      "'{}' with '{}'\n\t".format(result.data,
                                                  result.schema))
                for error in result.errors:
                    print("\t{}".format(error))
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script for yaml file validation using yamale")
    parser.add_argument("file", help="Name of yaml file for validation")
    parser.add_argument("schema_file",
                        help="Name of validation file"
                             "(<file>_schema.yaml by default)", nargs="?")
    args = parser.parse_args()
    yamale_invalid(args.file, args.schema_file, silent=False)
