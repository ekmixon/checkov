import logging
import operator
import re
from functools import reduce

# COMMENT_REGEX = re.compile(r'(checkov:skip=) *([A-Z_\d]+)(:[^\n]+)?')
from checkov.common.bridgecrew.platform_integration import bc_integration
from checkov.common.util.type_forcers import force_list

COMMENT_REGEX = re.compile(r'([A-Z_\d]+)(:[^\n]+)?')


class ContextParser(object):
    """
    ARM template context parser
    """

    def __init__(self, arm_file, arm_template, arm_template_lines):
        self.arm_file = arm_file
        self.arm_template = arm_template
        self.arm_template_lines = arm_template_lines

    def evaluate_default_parameters(self):
        # Get parameter defaults and variable values
        parameter_defaults = {}
        if 'parameters' in self.arm_template.keys():
            for parameter in self.arm_template['parameters']:
                if parameter in ['__startline__', '__endline__']:
                    continue
                if 'defaultValue' in self.arm_template['parameters'][parameter].keys():
                    parameter_defaults[parameter] = self.arm_template['parameters'][parameter]["defaultValue"]

        variable_values = {}
        if 'variables' in self.arm_template.keys():
            for var in self.arm_template['variables']:
                if var in ['__startline__', '__endline__']:
                    continue
                variable_values[var] = self.arm_template['variables'][var]

        # Find paths to substitute parameters and variables
        keys_w_params = []
        keys_w_params.extend(self.search_deep_values('[parameters(', self.arm_template, []))

        keys_w_vars = []
        keys_w_vars.extend(self.search_deep_values('[variables(', self.arm_template, []))

        # Substitute Parameters and Variables
        for key_entry in keys_w_params:
            try:
                param = re.sub("\[parameters\('|'\)]", "", self._get_from_dict(dict(self.arm_template),
                                                                               key_entry[:-1])[key_entry[-1]])
                if param in parameter_defaults:
                    logging.debug(f"Replacing parameter {param} in file {self.arm_file} with default value: {parameter_defaults[param]}")
                    self._set_in_dict(dict(self.arm_template), key_entry, parameter_defaults[param])
            except TypeError as e:
                logging.debug(f'Failed to evaluate param in {self.arm_file}, error:')
                logging.debug(e, stack_info=True)

        for key_entry in keys_w_vars:
            try:
                param = re.sub("\[variables\('|'\)]", "", self._get_from_dict(dict(self.arm_template),
                                                                              key_entry[:-1])[key_entry[-1]])
                if param in variable_values:
                    self._set_in_dict(dict(self.arm_template), key_entry, variable_values[param])
                    logging.debug(
                        f"Replacing variable {param} in file {self.arm_file} with default value: {variable_values[param]}"
                    )

                else:
                    logging.debug(
                        f"Variable {param} not found in evaluated variables in file {self.arm_file}"
                    )

            except TypeError as e:
                logging.debug(f'Failed to evaluate param in {self.arm_file}, error:')
                logging.debug(e, stack_info=True)

    @staticmethod
    def extract_arm_resource_id(arm_resource):
        # if arm_resource_name == '__startline__' or arm_resource_name == '__endline__':
        #    return
        if 'type' not in arm_resource:
            # This is not an ARM resource, skip
            return
        if 'name' not in arm_resource:
            # This is not an ARM resource, skip
            return
        return f"{arm_resource['type']}.{arm_resource['name']}"

    @staticmethod
    def extract_arm_resource_name(arm_resource):
        # if arm_resource_name == '__startline__' or arm_resource_name == '__endline__':
        #    return
        if 'name' not in arm_resource:
            # This is not an ARM resource, skip
            return
        return f"{arm_resource['name']}"

    def extract_arm_resource_code_lines(self, arm_resource):
        if find_lines_result_list := list(
            self.find_lines(arm_resource, '__startline__')
        ):
            start_line = min(find_lines_result_list)
            end_line = max(list(self.find_lines(arm_resource, '__endline__')))

            entity_lines_range = [start_line, end_line]

            entity_code_lines = self.arm_template_lines[start_line - 1: end_line]
            return entity_lines_range, entity_code_lines
        return None, None

    @staticmethod
    def find_lines(node, kv):
        if isinstance(node, list):
            for i in node:
                yield from ContextParser.find_lines(i, kv)
        elif isinstance(node, dict):
            if kv in node:
                yield node[kv]
            for j in node.values():
                yield from ContextParser.find_lines(j, kv)

    @staticmethod
    def collect_skip_comments(resource):
        skipped_checks = []
        bc_id_mapping = bc_integration.get_id_mapping()
        ckv_to_bc_id_mapping = bc_integration.get_ckv_to_bc_id_mapping()
        if "metadata" in resource and "checkov" in resource["metadata"]:
            for item in force_list(resource["metadata"]["checkov"]):
                if skip_search := re.search(COMMENT_REGEX, str(item)):
                    skipped_check = {
                        'id': skip_search[1],
                        'suppress_comment': skip_search[2][1:]
                        if skip_search[2]
                        else "No comment provided",
                    }

                    if bc_id_mapping and skipped_check["id"] in bc_id_mapping:
                        skipped_check["bc_id"] = skipped_check["id"]
                        skipped_check["id"] = bc_id_mapping[skipped_check["id"]]
                    elif ckv_to_bc_id_mapping:
                        skipped_check["bc_id"] = ckv_to_bc_id_mapping.get(skipped_check["id"])

                    skipped_checks.append(skipped_check)

        return skipped_checks

    @staticmethod
    def search_deep_keys(search_text, arm_dict, path):
        """Search deep for keys and get their values"""
        keys = []
        if isinstance(arm_dict, dict):
            for key in arm_dict:
                pathprop = path[:]
                pathprop.append(key)
                if key == search_text:
                    pathprop.append(arm_dict[key])
                    keys.append(pathprop)
                    # pop the last element off for nesting of found elements for
                    # dict and list checks
                    pathprop = pathprop[:-1]
                if isinstance(arm_dict[key], dict):
                    keys.extend(ContextParser.search_deep_keys(search_text, arm_dict[key], pathprop))
                elif isinstance(arm_dict[key], list):
                    for index, item in enumerate(arm_dict[key]):
                        pathproparr = pathprop[:]
                        pathproparr.append(index)
                        keys.extend(ContextParser.search_deep_keys(search_text, item, pathproparr))
        elif isinstance(arm_dict, list):
            for index, item in enumerate(arm_dict):
                pathprop = path[:]
                pathprop.append(index)
                keys.extend(ContextParser.search_deep_keys(search_text, item, pathprop))

        return keys

    @staticmethod
    def search_deep_values(search_text, arm_dict, path):
        """Search deep for keys with values matching search text"""
        keys = []
        if isinstance(arm_dict, dict):
            for key in arm_dict:
                pathprop = path[:]
                pathprop.append(key)

                if search_text in str(arm_dict[key]):
                    pathprop.append(arm_dict[key])
                    keys.append(pathprop)
                    # pop the last element off for nesting of found elements for
                    # dict and list checks
                    pathprop = pathprop[:-1]
                if isinstance(arm_dict[key], dict):
                    keys.extend(ContextParser.search_deep_values(search_text, arm_dict[key], pathprop))
                elif isinstance(arm_dict[key], list):
                    for index, item in enumerate(arm_dict[key]):
                        pathproparr = pathprop[:]
                        pathproparr.append(index)
                        keys.extend(ContextParser.search_deep_values(search_text, item, pathproparr))
        elif isinstance(arm_dict, list):
            for index, item in enumerate(arm_dict):
                pathprop = path[:]
                pathprop.append(index)
                keys.extend(ContextParser.search_deep_values(search_text, item, pathprop))

        for key in keys:
            for i in key:
                if isinstance(i, (list, dict)):
                    keys.remove(key)

            # Remove parameter
            if search_text in key[-1]:
                key.pop()

        return keys

    def _set_in_dict(self, data_dict, map_list, value):
        self._get_from_dict(data_dict, map_list[:-1])[map_list[-1]] = value

    @staticmethod
    def _get_from_dict(data_dict, map_list):
        return reduce(operator.getitem, map_list, data_dict)
