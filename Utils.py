import re

def get_regex_matches(string, regex):
	matches = re.findall(regex, string)
	return len(matches) > 0