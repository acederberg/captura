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

    matched = semver.match(github_ref_name := sys.argv[1])
    if matched is None:
        print(f"Illegal git ref name `{ github_ref_name }`. Exitting.")
        sys.exit(1)
    else:
        print(f"Valid git ref name `{ github_ref_name }`.")
