# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

from django.core import serializers
from django.db.models import Q

from scanpipe.pipelines import Pipeline
from scanpipe.pipes import analyze


# TODO: Discuss if we want to persist the detection issues on the database
# or simply return the data in an output file.
# Also, why not attaching the detection issues in the entries of the `licenses` list
# instead of having a global list at the resource level?
class AnalyzeScan(Pipeline):
    """
    A pipeline to analyze scan results.
    """

    def find_detection_issues(self):
        """
        Find detection issues in a project scan results.
        """
        analyze.find_detection_issue(self.project)

    def json_output(self):
        """
        Generate a JSON output including the detection issues.
        """
        project = self.project
        qs = project.codebaseresources.files().filter(~Q(license_detection_issues=[]))
        serialized_data = serializers.serialize("json", qs, indent=2)

        output_file = project.get_output_file_path("detection_issues", "json")
        with output_file.open("w") as file:
            file.write(serialized_data)

        self.log(f"Detection issues results at {output_file.resolve()}")

    steps = (
        find_detection_issues,
        json_output,
    )
