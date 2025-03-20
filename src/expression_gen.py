import re

def gen_condition_expression(condition_string: str, search_location: str):
	condition = condition_string.replace('and', '&').replace('or', '^')
	condition = condition.replace('AND', '&').replace('OR', '^')
	condition = condition.replace('\'', '')
	condition = condition.replace('\"', '')
	condition = condition.replace('\\', '\\\\') 

	def t1(match):
		tag_name = match.group(1)
		print(f"tag_name : {tag_name}")
		return f"get('tag_name')"

	condition = re.sub(r"([\w\-+:./\\()]+)", t1, condition)
	#condition = re.sub(r"([\w\-+:./\\]+)", rf"get('\1')", condition)
	#condition = re.sub(r"((\w|-|:|\+|\.|/|\\\\)+)", rf"self._tag_objsearch['{search_location}'].get('\1', set())", condition)
	condition = "cond_expr_result = " + condition
	return condition

def gen_condition_expression_2(condition_string: str, search_location: str):
    """
    Creates dynamically an executable Python statement used to find objects matching a DAG condition
    on the self._tag_objsearch structure.

    Example:
    condition_string = "'tag1' and ('tag2' or 'tag3')"
    search_location = "fwtest"

    Output:
    cond_expr_result = "self._tag_objsearch['fwtest'].get('tag1', set()) & (self._tag_objsearch['fwtest'].get('tag2', set()) ^ self._tag_objsearch['fwtest'].get('tag3', set()))"

    :param condition_string: The DAG (AddressGroup) dynamic statement
    :param search_location: The location where to find the matching objects
    :return: The transformed Python condition expression
    """

    # Replace logical operators
    condition = condition_string.replace('and', '&').replace('or', '^')
    condition = condition.replace('AND', '&').replace('OR', '^')

    # Remove unnecessary quotes
    condition = condition.replace("'", "").replace('"', "")

    # Function to safely replace each tag
    def tag_replacement(match):
        tag_name = match.group(1)
        #return f"get('{tag_name}')"
        return f"get('{tag_name}')"

    # Match full tag names, allowing special characters including parentheses
    #tag_pattern = r"([A-Za-z0-9\-+:./\\]+(?:\([A-Za-z0-9\-+:./\\ ]+\))?)"
    tag_pattern = r"([^\s()]+(?:\([^\s()]+\))?)"
    condition = re.sub(tag_pattern, tag_replacement, condition)

    condition = "cond_expr_result = " + condition
    return condition

def gen_condition_expression_3(condition_string: str, search_location: str):
    """
    Creates dynamically an executable Python statement used to find objects matching a DAG condition
    on the self._tag_objsearch structure.

    Example:
    condition_string = "'tag1' and ('tag2' or 'tag3')"
    search_location = "fwtest"

    Output:
    cond_expr_result = "self._tag_objsearch['fwtest'].get('tag1', set()) & (self._tag_objsearch['fwtest'].get('tag2', set()) ^ self._tag_objsearch['fwtest'].get('tag3', set()))"

    :param condition_string: The DAG (AddressGroup) dynamic statement
    :param search_location: The location where to find the matching objects
    :return: The transformed Python condition expression
    """

    # Replace logical operators
    condition = condition_string.replace(' and ', ' & ').replace(' or ', ' ^ ').replace(' AND ', ' & ').replace(' OR ', ' ^ ')
    condition = condition.replace(' AND ', ' & ').replace(' OR ', ' ^ ')

    # Remove unnecessary quotes
    #condition = condition.replace("'", "").replace('"', "")

    # Function to safely replace each tag
    def tag_replacement(match):
        print(match)
        tag_name = match.group(2) if match.group(2) else match.group(3)
        return f"get('{tag_name}')"
        #return f"self._tag_objsearch['{search_location}'].get('{tag_name}', set())"

    # Match full tag names, allowing special characters including parentheses
    #tag_pattern = r"([A-Za-z0-9\-+:./\\]+(?:\([A-Za-z0-9\-+:./\\ ]+\))?)"
    #tag_pattern = r"(['\"]([^'\"]+)['\"]|([^\s()^&]+(?:\([^\s()^&]+\))?))"
    #tag_pattern = r"(['\"]([^'\"]+)['\"]|([^\s()^&]+(?:\([^()]*\))?))"
    #tag_pattern = r"(['\"]([^'\"]*)['\"]|([^\s()^&]+(?:\([^()]*\))?))"
    #tag_pattern = r"(['\"]([^'\"]+)['\"]|([^\s()^&]+(?:\([^()]*\))?))"
    print(condition)
    tag_pattern = r"(['\"])([^'\^&\"]+)\1|([^\s()^&]+)"
    condition = re.sub(tag_pattern, tag_replacement, condition)

    condition = "cond_expr_result = " + condition
    return condition


def gen_condition_expression_4_final(condition_string: str, search_location: str):
    """
    Creates dynamically an executable Python statement used to find objects matching a DAG condition
    on the self._tag_objsearch structure
    Example :
    condition_string = "'tag1' and ('tag2' or 'tag3')"
    search_location = "fwtest"
    Output :
    cond_expr_result = "self._tag_objsearch[fwtest].get('tag1', set()) & (self._tag_objsearch[fwtest].get('tag2', set()) ^ self._tag_objsearch[fwtest].get('tag3', set()))"

    :param condition_string: The DAG (AddressGroup) dynamic statement
    :param search_location: The location where to find the matching objects
    :return:
    """

    condition = condition_string.replace(' and ', ' & ').replace(' or ', ' ^ ')
    condition = condition.replace(' AND ', ' & ').replace(' OR ', ' ^ ')

    #condition = condition.replace('\'', '')
    #condition = condition.replace('\"', '')
    condition = condition.replace('\\', '\\\\')
    tags_in_condition = set()
    
    def tag_replacement(match):
        # replace any tag name with the dict where to search for it 
        # ie : "tag1" is replaced by "self._tag_objsearch[fwtest].get('tag1', set())"
        tag_name = match.group(2) if match.group(2) else match.group(3)
        tags_in_condition.add(tag_name)
        return f"{search_location}:'{tag_name}'"

    # This new tag_pattern regex permits to match tags containing parenthesis
    # all caracters are allowed in a tag
    # tags can contain spaces if they are between quotes 
    tag_pattern = r"(['\"])([^'\^&\"]+)\1|([^\s()^&]+)"
    condition = re.sub(tag_pattern, tag_replacement, condition)

    condition = "cond_expr_result = " + condition
    print(tags_in_condition)
    return condition







'guestos.Microsoft Windows Server 2003 Standard 32-bit' or 'guestos.Microsoft Windows 7 64-bit' or 'guestos.Microsoft Windows Server 2008 32-bit'  or 'guestos.Microsoft Windows Server 2008 64-bit'  or 'guestos.Microsoft Windows Server 2008 R2 64-bit' or 'guestos.Microsoft Windows Server 2012 64-bit' or 'vcenter.NGP_AH_MAR_A8_R5_NGP_MAR_WINDOWS_guestos.Microsoft/Windows/Server/2016/or/later/(64-bit)' or 'guestos.Microsoft Windows Server 2016 64-bit'  or 'WINDOWS'  or 'vcenter.NGP_AH_MAR_A8_R5_NGP_MAR_MGMT_guestos.Microsoft/Windows/Server/2019/(64-bit)'  or 'vcenter.NGP_AH_MAR_A8_R5_NGP_MAR_WINDOWS_guestos.Microsoft/Windows/Server/2022/(64-bit)'