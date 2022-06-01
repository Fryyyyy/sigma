# Output backends for sigmac
# Copyright 2016-2017 Thomas Patzke
# Modified 2022 by fryy@, Google Inc

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
from .base import BaseBackend
from .mixins import QuoteCharMixin
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier

class FindGrepBackend(BaseBackend, QuoteCharMixin):
    """Generates Perl compatible regular expressions and puts 'find -exec grep -P' around it"""
    identifier = "findgrep"
    active = True
    config_required = False

    reEscape = re.compile("([\\|()\[\]{}.^$+])")

    def __init__(self, *args, **kwargs):
        """Initialize field mappings."""
        super().__init__(*args, **kwargs)
        self.category = None

    def generate(self, sigmaparser):
        self.category = sigmaparser.parsedyaml['logsource'].setdefault('category', None)
        return super().generate(sigmaparser)

    def generateBefore(self, parsed):
        if self.category == "file_event":
            filesregexp = parsed.sigmaParser.parsedyaml["detection"].get("files", "")
            if not filesregexp:
                return ""
            if len(filesregexp) > 1:
                raise NotImplementedError("Multiple file regexps not implemented for this backend")
            return "find . -type f -regextype egrep -regex \"%s\" -exec " % list(filesregexp.values())[0]
        return ""

    def generateAfter(self, parsed):
        if self.category == "file_event":
            filesregexp = parsed.sigmaParser.parsedyaml["detection"].get("files", "")
            if not filesregexp:
                return ""
            return " {} \;"
        return ""

    def generateQuery(self, parsed):
        return "grep -P '%s'" % self.generateNode(parsed.parsedSearch)

    def cleanValue(self, val):
        val = super().cleanValue(val)
        val = val.replace("'","'\"'\"'")
        return re.sub("\\*", ".*", val)

    def generateORNode(self, node):
        return "(?:%s)" % "|".join([".*" + self.generateNode(val) for val in node])

    def generateANDNode(self, node):
        return "".join(["(?=.*%s)" % self.generateNode(val) for val in node])

    def generateNOTNode(self, node):
        return "(?!.*%s)" % self.generateNode(node.item)

    def generateSubexpressionNode(self, node):
        return "(?:.*%s)" % self.generateNode(node.items)

    def generateTypedValueNode(self, node):
        if type(node) == SigmaRegularExpressionModifier:
            return node
        raise NotImplementedError("Node type not implemented for this backend")

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.generateORNode(node)

    def generateMapItemNode(self, node):
        key, value = node
        if value is None:
            return self.generateNULLValueNode(node)
        else:
            return self.generateNode(value)

    def generateValueNode(self, node):
        return self.cleanValue(str(node))

    def generateNULLValueNode(self, node):
        key, value = node
        return "(?!%s)" % key
