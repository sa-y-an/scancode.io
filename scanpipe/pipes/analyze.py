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

from scancode_analyzer.analyzer_plugin import LicenseMatch
from scancode_analyzer.analyzer_plugin import is_analyzable
from scancode_analyzer.license_analyzer import LicenseDetectionIssue
from summarycode.classify import set_classification_flags


def find_detection_issue(project):
    """
    Iterate through project codebase resources with detected licenses value to
    find detection issues.
    """
    qs = project.codebaseresources.files().has_licenses()

    for resource in qs:
        set_license_detection_issues(resource)


def get_license_detection_issues(resource):
    """
    Return a list of license detection issues for the provided `resource`.
    """
    license_matches = LicenseMatch.from_files_licenses(resource.licenses)
    license_detection_issues = LicenseDetectionIssue.from_license_matches(
        license_matches=license_matches,
        is_license_text=getattr(resource, "is_license_text", False),
        is_legal=getattr(resource, "is_legal", False),
        path=getattr(resource, "path"),
    )
    return list(license_detection_issues)


def set_license_detection_issues(resource):
    """
    Find and save license detection issues for the provided `resource`.
    A resource needs to be "analyzable" (having all the data required for analysis)
    to generate any license detection issues data.
    """
    # TODO: The `is_license_text` value is required for the analyzer but not available
    # in the CodebaseResource context.
    # It is generated using the --license-text IsLicenseText post scan plugging.
    # We could:
    # - always generate that value and store it in the database
    # - refactor the IsLicenseText code to make the logic re-usable as a function
    # to be called when needed
    resource.is_license_text = True

    # TODO: This value is required by the set_classification_flags function to generate
    # the is_key_file value, but is not used or needed by the analyzer
    # Adding a is_top_level property on the CodebaseResource may be useful though.
    resource.is_top_level = False
    resource = set_classification_flags(resource)

    if is_analyzable(resource):
        license_detection_issues = get_license_detection_issues(resource)
        resource.license_detection_issues = [
            issue.to_dict(is_summary=False) for issue in license_detection_issues
        ]
        resource.save()
