"""Yes, this could be done in bash. But it has been inconsistent.

- First argument should be the override value.
- Second should be the actual value.
"""

# =========================================================================== #
import re
import sys

semver = re.compile(
    "^(?P<major>0|[1-9]\\d*)\\.(?P<minor>0|[1-9]\\d*)\\.(?P<patch>0|[1-9]\\d*)"
    "(?:-(?P<prerelease>(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    "(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    "(?:\\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
)


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print("Not enough arguments.")

    _, tag_override, tag = sys.argv
    matched = semver.match(github_ref_name := tag_override or tag)

    if matched is None:
        sys.exit(1)
    else:
        # NOTE: Should only print this since it is used to determine the release
        #       name.
        print(github_ref_name)
