#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

import yaml

def load_yaml(file_object):
    # The PyYAML 5.1+ deprecates of the plain yaml.load(input) function,
    # but the FullLoader class is only available in PyYAML 5.1 and later.
    if hasattr(yaml, 'FullLoader'):
        return yaml.load(file_object, Loader=yaml.FullLoader)
    else:
        return yaml.load(file_object)
